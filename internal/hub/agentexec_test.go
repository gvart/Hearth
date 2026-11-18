// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/gvart/hearth/internal/policy"
	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
	"github.com/gvart/hearth/internal/proto/hearth/agent/v1/agentv1connect"
	"github.com/gvart/hearth/internal/store"
)

// newExecClient serves an AgentStream for dev-1 and returns a client and the
// stream's Agents.
func newExecClient(t *testing.T, st *store.Store) (agentv1connect.AgentServiceClient, *Agents) {
	t.Helper()
	as := NewAgentStream(slog.New(slog.DiscardHandler), 5*time.Second, NewRegistry(RegistryConfig{Store: st}))
	path, h := agentv1connect.NewAgentServiceHandler(as)
	mux := http.NewServeMux()
	mux.Handle(path, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r.WithContext(withDeviceID(r.Context(), "dev-1")))
	}))
	srv := httptest.NewUnstartedServer(mux)
	srv.Config.Protocols = new(http.Protocols)
	srv.Config.Protocols.SetUnencryptedHTTP2(true)
	srv.Start()
	t.Cleanup(srv.Close)
	transport := &http.Transport{Protocols: new(http.Protocols)}
	transport.Protocols.SetUnencryptedHTTP2(true)
	t.Cleanup(transport.CloseIdleConnections)
	return agentv1connect.NewAgentServiceClient(&http.Client{Transport: transport}, srv.URL), as.agents
}

// connectAgent opens a stream for dev-1 speaking protocol minor, reporting
// ceiling, and reads the Welcome.
func connectAgent(ctx context.Context, t *testing.T, c agentv1connect.AgentServiceClient, minor uint32,
	ceiling *agentv1.Ceiling,
) *connect.BidiStreamForClient[agentv1.AgentMessage, agentv1.HubMessage] {
	t.Helper()
	stream := c.Connect(ctx)
	t.Cleanup(func() {
		_ = stream.CloseRequest()
		_ = stream.CloseResponse()
	})
	h := hello(ProtocolMajor)
	h.GetHello().ProtocolVersion.Minor = minor
	h.GetHello().Ceiling = ceiling
	if err := stream.Send(h); err != nil {
		t.Fatal(err)
	}
	if msg, err := stream.Receive(); err != nil || msg.GetWelcome() == nil {
		t.Fatalf("receive welcome: %v %v", msg, err)
	}
	return stream
}

func TestAgentsExec(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	st := newTestStore(t)
	enrollDevice(t, st, "dev-1")
	client, agents := newExecClient(t, st)

	if _, err := agents.Exec(ctx, "dev-1", &agentv1.ExecRequest{}); !errors.Is(err, ErrAgentNotConnected) {
		t.Fatalf("Exec before connect = %v, want ErrAgentNotConnected", err)
	}

	stream := connectAgent(ctx, t, client, 2, &agentv1.Ceiling{Exec: []string{"/bin/true"}})
	// The agent answers each request with its id.
	go func() {
		for {
			msg, err := stream.Receive()
			if err != nil {
				return
			}
			req := msg.GetExecRequest()
			_ = stream.Send(&agentv1.AgentMessage{Payload: &agentv1.AgentMessage_ExecResult{
				ExecResult: &agentv1.ExecResult{Id: req.GetId(), Denied: true},
			}})
		}
	}()
	// By id, name and hostname.
	for _, ref := range []string{"dev-1", "dev-1-name"} {
		var res *agentv1.ExecResult
		var err error
		for range 100 { // the session attaches just after Welcome
			if res, err = agents.Exec(ctx, ref, trueCmd()); !errors.Is(err, ErrAgentNotConnected) {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		if err != nil || !res.GetDenied() {
			t.Errorf("Exec(%s) = %v, %v; want the agent's denial", ref, res, err)
		}
	}
	if _, err := agents.Exec(ctx, "nope", &agentv1.ExecRequest{}); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("Exec on unknown device = %v, want ErrNotFound", err)
	}

	_ = stream.CloseRequest()
	_ = stream.CloseResponse()
	for range 100 {
		if _, err := agents.Exec(ctx, "dev-1", &agentv1.ExecRequest{}); errors.Is(err, ErrAgentNotConnected) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Error("agent still connected after its stream ended")
}

func TestAgentsExecOldAgent(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	st := newTestStore(t)
	enrollDevice(t, st, "dev-1")
	client, agents := newExecClient(t, st)
	connectAgent(ctx, t, client, 0, nil)
	var err error
	for range 100 {
		if _, err = agents.Exec(ctx, "dev-1", &agentv1.ExecRequest{}); !errors.Is(err, ErrAgentNotConnected) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err == nil || !strings.Contains(err.Error(), "too old") {
		t.Errorf("Exec on a minor 0 agent = %v, want too old", err)
	}
}

func TestAgentsExecAmbiguousName(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	enrollDevice(t, st, "dev-1")
	enrollDevice(t, st, "dev-2")
	if err := st.Devices().Upsert(t.Context(), store.Device{ID: "dev-2", Name: "dev-1-name", Status: store.StatusUnknown}); err != nil {
		t.Fatal(err)
	}
	_, err := NewAgents(st.Devices()).Exec(t.Context(), "dev-1-name", &agentv1.ExecRequest{})
	if err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Errorf("Exec by a shared name = %v, want ambiguous", err)
	}
}

func trueCmd() *agentv1.ExecRequest {
	return &agentv1.ExecRequest{Action: &agentv1.ExecRequest_Command{Command: &agentv1.Command{Argv: []string{"/bin/true"}}}}
}

// The hub never grants more than the device's ceiling: a request beyond the
// ceiling the agent reported, or to an agent that reports none, is refused
// with ErrBeyondCeiling and never reaches the agent.
func TestAgentsExecNeverBeyondCeiling(t *testing.T) {
	t.Parallel()
	restart := func(m, n string) *agentv1.ExecRequest {
		return &agentv1.ExecRequest{Action: &agentv1.ExecRequest_Restart{Restart: &agentv1.RestartService{Manager: m, Name: n}}}
	}
	exec := func(argv ...string) *agentv1.ExecRequest {
		return &agentv1.ExecRequest{Action: &agentv1.ExecRequest_Command{Command: &agentv1.Command{Argv: argv}}}
	}
	full := &agentv1.Ceiling{Exec: []string{"/usr/bin/df"}, Restart: []string{"docker:jellyfin"}}
	tests := []struct {
		name    string
		minor   uint32
		ceiling *agentv1.Ceiling
		req     *agentv1.ExecRequest
		allowed bool
	}{
		{"exec in ceiling", 2, full, exec("/usr/bin/df", "-h"), true},
		{"restart in ceiling", 2, full, restart("docker", "jellyfin"), true},
		{"exec not in ceiling", 2, full, exec("/bin/rm", "-rf", "/"), false},
		{"exec by another path", 2, full, exec("df"), false},
		{"restart of another service", 2, full, restart("docker", "pihole"), false},
		{"restart with another manager", 2, full, restart("systemd", "jellyfin"), false},
		{"empty ceiling", 2, &agentv1.Ceiling{}, exec("/usr/bin/df"), false},
		{"no ceiling reported", 2, nil, exec("/usr/bin/df"), false},
		{"agent too old to report a ceiling", 1, full, exec("/usr/bin/df"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			st := newTestStore(t)
			enrollDevice(t, st, "dev-1")
			client, agents := newExecClient(t, st)
			stream := connectAgent(ctx, t, client, tt.minor, tt.ceiling)
			received := make(chan *agentv1.ExecRequest, 10)
			go func() {
				for {
					msg, err := stream.Receive()
					if err != nil {
						return
					}
					if req := msg.GetExecRequest(); req != nil {
						received <- req
						_ = stream.Send(&agentv1.AgentMessage{Payload: &agentv1.AgentMessage_ExecResult{
							ExecResult: &agentv1.ExecResult{Id: req.GetId()},
						}})
					}
				}
			}()
			var err error
			for range 100 { // the session attaches just after Welcome
				if _, err = agents.Exec(ctx, "dev-1", tt.req); !errors.Is(err, ErrAgentNotConnected) {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			checkErr := agents.Check(ctx, "dev-1", tt.req)
			if tt.allowed {
				if err != nil || checkErr != nil {
					t.Fatalf("Exec = %v, Check = %v; want both allowed", err, checkErr)
				}
				if len(received) != 1 {
					t.Fatalf("agent received %d requests, want 1", len(received))
				}
				return
			}
			if !errors.Is(err, policy.ErrBeyondCeiling) || !errors.Is(checkErr, policy.ErrBeyondCeiling) {
				t.Fatalf("Exec = %v, Check = %v; want ErrBeyondCeiling", err, checkErr)
			}
			if len(received) != 0 {
				t.Fatal("the agent received a request beyond its ceiling")
			}
		})
	}
}

// A ceiling the agent lowers in its facts applies at once.
func TestAgentsExecCeilingLoweredByFacts(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	st := newTestStore(t)
	enrollDevice(t, st, "dev-1")
	client, agents := newExecClient(t, st)
	stream := connectAgent(ctx, t, client, 2, &agentv1.Ceiling{Exec: []string{"/bin/true"}})
	var err error
	for range 100 {
		if err = agents.Check(ctx, "dev-1", trueCmd()); !errors.Is(err, ErrAgentNotConnected) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("Check before facts = %v", err)
	}
	facts := hello(ProtocolMajor).GetHello()
	facts.Ceiling = &agentv1.Ceiling{}
	if err := stream.Send(&agentv1.AgentMessage{Payload: &agentv1.AgentMessage_Facts{Facts: facts}}); err != nil {
		t.Fatal(err)
	}
	for range 100 {
		if err = agents.Check(ctx, "dev-1", trueCmd()); err != nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !errors.Is(err, policy.ErrBeyondCeiling) {
		t.Fatalf("Check after the ceiling was lowered = %v, want ErrBeyondCeiling", err)
	}
}
