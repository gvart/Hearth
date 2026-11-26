// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/policy"
	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
)

// probeUntilAttached retries Probe while the session is not attached yet.
func probeUntilAttached(ctx context.Context, t *testing.T, agents *Agents) (*agentv1.ProbeResult, error) {
	t.Helper()
	var res *agentv1.ProbeResult
	var err error
	for range 100 {
		req := &agentv1.ProbeRequest{Probe: &agentv1.ProbeRequest_Tcp{Tcp: &agentv1.TCPProbe{Address: "127.0.0.1:1"}}}
		if res, err = agents.Probe(ctx, "dev-1", req); !errors.Is(err, ErrAgentNotConnected) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	return res, err
}

func TestAgentsProbe(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	st := newTestStore(t)
	enrollDevice(t, st, "dev-1")
	client, agents := newExecClient(t, st)

	if err := agents.CheckProbe(ctx, "dev-1"); !errors.Is(err, ErrAgentNotConnected) {
		t.Fatalf("CheckProbe before connect = %v, want ErrAgentNotConnected", err)
	}
	stream := connectAgent(ctx, t, client, 3, &agentv1.Ceiling{Probe: true})
	got := make(chan *agentv1.ProbeRequest, 1)
	go func() {
		for {
			msg, err := stream.Receive()
			if err != nil {
				return
			}
			req := msg.GetProbeRequest()
			got <- req
			_ = stream.Send(&agentv1.AgentMessage{Payload: &agentv1.AgentMessage_ProbeResult{
				ProbeResult: &agentv1.ProbeResult{Id: req.GetId(), Error: "connection refused"},
			}})
		}
	}()
	res, err := probeUntilAttached(ctx, t, agents)
	if err != nil || res.GetError() != "connection refused" {
		t.Fatalf("Probe = %v, %v; want the agent's failure", res, err)
	}
	if req := <-got; req.GetTcp().GetAddress() != "127.0.0.1:1" || req.GetId() != res.GetId() {
		t.Errorf("agent got %v, want the tcp probe with the result's id", req)
	}
	if err := agents.CheckProbe(ctx, "dev-1"); err != nil {
		t.Errorf("CheckProbe = %v, want nil", err)
	}

	_ = stream.CloseRequest()
	_ = stream.CloseResponse()
	for range 100 {
		if err := agents.CheckProbe(ctx, "dev-1"); errors.Is(err, ErrAgentNotConnected) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Error("agent still connected after its stream ended")
}

func TestAgentsProbeNeverBeyondCeiling(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		minor   uint32
		ceiling *agentv1.Ceiling
		want    string
	}{
		"old agent":         {minor: 2, ceiling: &agentv1.Ceiling{Probe: true}, want: "too old"},
		"probe not allowed": {minor: 3, ceiling: &agentv1.Ceiling{Exec: []string{"/bin/true"}}, want: "turn Checks on"},
		"no ceiling":        {minor: 3, want: "turn Checks on"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			st := newTestStore(t)
			enrollDevice(t, st, "dev-1")
			client, agents := newExecClient(t, st)
			stream := connectAgent(ctx, t, client, tc.minor, tc.ceiling)
			sent := make(chan struct{}, 1)
			go func() {
				if msg, err := stream.Receive(); err == nil && msg.GetProbeRequest() != nil {
					sent <- struct{}{}
				}
			}()
			_, err := probeUntilAttached(ctx, t, agents)
			if !errors.Is(err, policy.ErrBeyondCeiling) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Probe = %v, want beyond the ceiling (%s)", err, tc.want)
			}
			if err := agents.CheckProbe(ctx, "dev-1"); !errors.Is(err, policy.ErrBeyondCeiling) {
				t.Errorf("CheckProbe = %v, want beyond the ceiling", err)
			}
			select {
			case <-sent:
				t.Error("a probe beyond the ceiling reached the agent")
			case <-time.After(50 * time.Millisecond):
			}
		})
	}
}
