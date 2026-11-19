// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/gvart/hearth/internal/policy"
	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
	"github.com/gvart/hearth/internal/store"
)

const (
	// stallTimeout is the send deadline injected in the stalled-agent tests.
	stallTimeout = 200 * time.Millisecond
	// stallWindow is how many unread bytes the stalled agent takes.
	stallWindow = 64 << 10
	// stallBytes is a request several windows large, so sending it waits
	// on the agent.
	stallBytes = 8 * stallWindow
)

// noise is n bytes of hex that does not compress: the stream may be
// compressed, and a payload that shrinks would never fill the window.
func noise(n int) string {
	b := make([]byte, n/2)
	_, _ = rand.Read(b) // never fails
	return hex.EncodeToString(b)
}

// stallCeiling allows everything the stalled-agent tests send.
var stallCeiling = &agentv1.Ceiling{Exec: []string{"/bin/true"}, Probe: true, Shell: true}

// bigCmd is a command larger than the stalled agent's window: sending it
// fills the window and then waits on the agent.
func bigCmd() *agentv1.ExecRequest {
	return &agentv1.ExecRequest{Action: &agentv1.ExecRequest_Command{Command: &agentv1.Command{
		Argv: []string{"/bin/true", noise(stallBytes)},
	}}}
}

// bigProbe is a probe larger than the stalled agent's window.
func bigProbe() *agentv1.ProbeRequest {
	return &agentv1.ProbeRequest{Probe: &agentv1.ProbeRequest_Http{Http: &agentv1.HTTPProbe{
		Url: "http://example.invalid/" + noise(stallBytes),
	}}}
}

// answerAgent answers every exec and probe request, as a healthy agent does.
func answerAgent(stream *connect.BidiStreamForClient[agentv1.AgentMessage, agentv1.HubMessage]) {
	go func() {
		for {
			msg, err := stream.Receive()
			if err != nil {
				return
			}
			var reply *agentv1.AgentMessage
			switch {
			case msg.GetExecRequest() != nil:
				reply = &agentv1.AgentMessage{Payload: &agentv1.AgentMessage_ExecResult{
					ExecResult: &agentv1.ExecResult{Id: msg.GetExecRequest().GetId()},
				}}
			case msg.GetProbeRequest() != nil:
				reply = &agentv1.AgentMessage{Payload: &agentv1.AgentMessage_ProbeResult{
					ProbeResult: &agentv1.ProbeResult{Id: msg.GetProbeRequest().GetId()},
				}}
			default:
				continue
			}
			_ = stream.Send(reply)
		}
	}()
}

// waitAttached waits until the hub attached the stream of dev-1.
func waitAttached(ctx context.Context, t *testing.T, agents *Agents) {
	t.Helper()
	for range 500 {
		if !errors.Is(agents.CheckProbe(ctx, "dev-1"), ErrAgentNotConnected) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("the agent's stream was not attached")
}

// TestSendToStalledAgent sends exec, probe and shell requests to an agent
// that stopped reading its stream: each fails within the send deadline
// saying so, the stream is torn down, and a reconnecting agent works again.
func TestSendToStalledAgent(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		// stalled sends to an agent that does not read (which answered
		// only a shell's open), and fails.
		stalled func(ctx context.Context, t *testing.T, st *store.Store, agents *Agents) error
		// works runs against a healthy agent that answers on stream.
		works func(ctx context.Context, t *testing.T, st *store.Store, agents *Agents,
			stream *connect.BidiStreamForClient[agentv1.AgentMessage, agentv1.HubMessage]) error
	}{
		"exec": {
			stalled: func(ctx context.Context, _ *testing.T, _ *store.Store, agents *Agents) error {
				_, err := agents.Exec(ctx, "dev-1", bigCmd())
				return err
			},
			works: func(ctx context.Context, _ *testing.T, _ *store.Store, agents *Agents,
				stream *connect.BidiStreamForClient[agentv1.AgentMessage, agentv1.HubMessage],
			) error {
				answerAgent(stream)
				_, err := agents.Exec(ctx, "dev-1", trueCmd())
				return err
			},
		},
		"probe": {
			stalled: func(ctx context.Context, _ *testing.T, _ *store.Store, agents *Agents) error {
				_, err := agents.Probe(ctx, "dev-1", bigProbe())
				return err
			},
			works: func(ctx context.Context, _ *testing.T, _ *store.Store, agents *Agents,
				stream *connect.BidiStreamForClient[agentv1.AgentMessage, agentv1.HubMessage],
			) error {
				answerAgent(stream)
				res, err := agents.Probe(ctx, "dev-1", &agentv1.ProbeRequest{})
				if err == nil && res.GetError() != "" {
					err = errors.New("probe not ok")
				}
				return err
			},
		},
		"shell": {
			stalled: func(ctx context.Context, t *testing.T, st *store.Store, agents *Agents) error {
				sh, err := agents.OpenShell(grantShell(ctx, t, st), "dev-1", 24, 80)
				if err != nil {
					t.Fatalf("OpenShell: %v", err)
				}
				return sh.Write([]byte(noise(stallBytes)))
			},
			works: func(ctx context.Context, t *testing.T, st *store.Store, agents *Agents,
				stream *connect.BidiStreamForClient[agentv1.AgentMessage, agentv1.HubMessage],
			) error {
				fakeShellAgent(stream, false)
				sh, err := agents.OpenShell(grantShell(ctx, t, st), "dev-1", 24, 80)
				if err != nil {
					return err
				}
				defer sh.Close()
				if err := sh.Write([]byte("ls\n")); err != nil {
					return err
				}
				_, err = sh.Read(ctx)
				return err
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()
			st := newTestStore(t)
			enrollDevice(t, st, "dev-1")
			client, agents := newExecClientWindow(t, st, stallWindow, func(a *Agents) { a.sendTimeout = stallTimeout })
			stream := connectAgent(ctx, t, client, minShellMinor, stallCeiling)
			if name == "shell" {
				stalledAgent(stream)
			}
			waitAttached(ctx, t, agents)

			start := time.Now()
			err := tc.stalled(ctx, t, st, agents)
			if d := time.Since(start); d > stallTimeout+time.Second {
				t.Errorf("the send returned after %s, want within %s", d, stallTimeout)
			}
			if err == nil || !strings.Contains(err.Error(), "agent dev-1 is not reading") {
				t.Errorf("err = %v, want the agent is not reading", err)
			}
			// The hub dropped the stream, and the agent sees it end.
			if !errors.Is(agents.CheckProbe(ctx, "dev-1"), ErrAgentNotConnected) {
				t.Error("the stalled stream is still attached")
			}
			for {
				if _, err := stream.Receive(); err != nil {
					break
				}
			}

			again := connectAgent(ctx, t, client, minShellMinor, stallCeiling)
			waitAttached(ctx, t, agents)
			if err := tc.works(ctx, t, st, agents, again); err != nil {
				t.Errorf("after reconnecting: %v", err)
			}
		})
	}
}

// TestSendQueuedBehindStalledSend: a small request waiting for its turn
// behind a send the agent does not take fails within the deadline too.
func TestSendQueuedBehindStalledSend(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	st := newTestStore(t)
	enrollDevice(t, st, "dev-1")
	client, agents := newExecClientWindow(t, st, stallWindow, func(a *Agents) { a.sendTimeout = stallTimeout })
	connectAgent(ctx, t, client, minShellMinor, stallCeiling)
	waitAttached(ctx, t, agents)

	first := make(chan error, 1)
	go func() {
		_, err := agents.Exec(ctx, "dev-1", bigCmd())
		first <- err
	}()
	time.Sleep(stallTimeout / 4) // the first send holds the stream
	start := time.Now()
	_, err := agents.Exec(ctx, "dev-1", trueCmd())
	if d := time.Since(start); d > stallTimeout+time.Second {
		t.Errorf("the queued send returned after %s, want within %s", d, stallTimeout)
	}
	if err == nil || !strings.Contains(err.Error(), "is not reading") {
		t.Errorf("queued exec err = %v, want the agent is not reading", err)
	}
	if err := <-first; err == nil || !strings.Contains(err.Error(), "is not reading") {
		t.Errorf("first exec err = %v, want the agent is not reading", err)
	}
}

// TestStalledExecIsAudited: an exec to an agent that stopped reading is
// audited as a failed action, as any other exec failure is.
func TestStalledExecIsAudited(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	st := newTestStore(t)
	enrollDevice(t, st, "dev-1")
	client, agents := newExecClientWindow(t, st, stallWindow, func(a *Agents) { a.sendTimeout = stallTimeout })
	connectAgent(ctx, t, client, minShellMinor, stallCeiling)
	waitAttached(ctx, t, agents)

	engine := policy.NewWithConfig(st.Audit(), nil, policy.Config{
		Actors: map[string]map[policy.Class]policy.Mode{policy.ActorMCP: {policy.Dangerous: policy.ModeAllow}},
	})
	err := engine.Do(ctx, policy.Request{
		ActorKind: policy.ActorMCP, ActorID: "test", Action: policy.DeviceExec, Target: "dev-1",
	}, func(ctx context.Context) error {
		_, err := agents.Exec(ctx, "dev-1", bigCmd())
		return err
	})
	if err == nil || !strings.Contains(err.Error(), "is not reading") {
		t.Fatalf("Do = %v, want the agent is not reading", err)
	}
	entries, err := st.Audit().List(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	var results []string
	for _, e := range entries {
		if e.Action == string(policy.DeviceExec) {
			results = append(results, e.Decision+" "+e.Result)
		}
	}
	// One entry per action: its start, carrying its outcome, as for any
	// exec that failed.
	if len(results) != 1 || !strings.HasPrefix(results[0], policy.Allow+" error: ") ||
		!strings.Contains(results[0], "agent dev-1 is not reading") {
		t.Errorf("audit = %q, want one exec allowed with an error outcome saying the agent is not reading", results)
	}
}
