// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/automation"
	"github.com/gvart/hearth/internal/integrations/kubernetes"
	"github.com/gvart/hearth/internal/policy"
	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
	"github.com/gvart/hearth/internal/store"
)

// TestRunbookCheckFromDeviceThroughItsAgent runs a runbook's check step from
// dev-1 through the real agent registry: the agent's reported ceiling is the
// limit, and a check beyond it never reaches the agent.
func TestRunbookCheckFromDeviceThroughItsAgent(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		ceiling      *agentv1.Ceiling
		status, step string
		sent         bool
	}{
		"allowed by the ceiling": {ceiling: &agentv1.Ceiling{Probe: true}, status: automation.RunbookSucceeded, step: "ok", sent: true},
		"beyond the ceiling":     {ceiling: &agentv1.Ceiling{Exec: []string{"/bin/true"}}, status: automation.RunbookFailed, step: "denied"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			st := newTestStore(t)
			enrollDevice(t, st, "dev-1")
			client, agents := newExecClient(t, st)
			stream := connectAgent(ctx, t, client, 3, tc.ceiling)
			sent := make(chan *agentv1.ProbeRequest, 1)
			go func() {
				for {
					msg, err := stream.Receive()
					if err != nil {
						return
					}
					if req := msg.GetProbeRequest(); req != nil {
						sent <- req
						_ = stream.Send(&agentv1.AgentMessage{Payload: &agentv1.AgentMessage_ProbeResult{
							ProbeResult: &agentv1.ProbeResult{Id: req.GetId()},
						}})
					}
				}
			}()
			for errors.Is(agents.CheckProbe(ctx, "dev-1"), ErrAgentNotConnected) && ctx.Err() == nil {
				time.Sleep(10 * time.Millisecond)
			}

			dir := t.TempDir()
			rb := "id: rb\nsteps:\n  - {id: reach, type: check, check: {type: tcp, address: '10.0.0.5:5432', from: dev-1-name}}\n"
			if err := os.WriteFile(filepath.Join(dir, "rb.yaml"), []byte(rb), 0o600); err != nil {
				t.Fatal(err)
			}
			sealer, err := kubernetes.NewSealer([]byte("test secret"))
			if err != nil {
				t.Fatal(err)
			}
			engine := automation.NewRunbooks(automation.RunbooksConfig{
				Dir: dir, Kinds: automation.Builtin(slog.New(slog.DiscardHandler)), Policy: policy.New(st.Audit()),
				Runs: st.RunbookRuns(), Sealer: sealer, Probers: agents, Poll: 5 * time.Millisecond,
			})
			runCtx, stop := context.WithCancel(ctx)
			done := make(chan struct{})
			go func() {
				defer close(done)
				_ = engine.Run(runCtx)
			}()
			t.Cleanup(func() {
				stop()
				<-done
			})

			run, err := engine.Start(ctx, policy.ActorWeb, "10.0.0.9", "rb")
			if err != nil {
				t.Fatal(err)
			}
			for run.Status != tc.status {
				if ctx.Err() != nil {
					t.Fatalf("run is %s, want %s: %+v", run.Status, tc.status, run.Steps)
				}
				time.Sleep(5 * time.Millisecond)
				if run, err = engine.GetRun(ctx, run.ID); err != nil {
					t.Fatal(err)
				}
			}
			if s := run.Steps[0]; s.Status != tc.step {
				t.Errorf("step = %+v, want %s", s, tc.step)
			}
			select {
			case req := <-sent:
				if !tc.sent {
					t.Error("a probe beyond the ceiling reached the agent")
				} else if req.GetTcp().GetAddress() != "10.0.0.5:5432" {
					t.Errorf("agent got %v", req)
				}
			case <-time.After(50 * time.Millisecond):
				if tc.sent {
					t.Error("the probe never reached the agent")
				}
			}

			entries, err := st.Audit().Query(ctx, store.AuditFilter{Actions: []string{string(policy.AutomationProbe)}}, 10)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 1 || entries[0].Target != "dev-1-name" || entries[0].ActorID != automation.RunbookActor("rb") {
				t.Fatalf("audit = %+v, want one automation.probe entry for the runbook on dev-1-name", entries)
			}
			if !tc.sent && (entries[0].Decision != policy.Deny || !strings.Contains(entries[0].Result, "turn Checks on")) {
				t.Errorf("audit = %+v, want denied beyond the ceiling", entries[0])
			}
		})
	}
}
