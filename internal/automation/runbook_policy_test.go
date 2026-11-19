// SPDX-License-Identifier: AGPL-3.0-only

package automation

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

// TestRunbookGrantFromThePolicyFile checks the grant the docs name, as the hub
// reads it from its policy file, through the decision a plan shows.
func TestRunbookGrantFromThePolicyFile(t *testing.T) {
	yaml := `id: rb
steps:
  - id: risky
    type: action
    action: {type: script, name: risky, policy: automation.exec}
`
	for _, tc := range []struct {
		name, file string
		want       string
	}{
		{"granted to the runbook", "dangerous_automations: [runbook/rb]\n", policy.Allow},
		{"granted to another runbook", "dangerous_automations: [runbook/other]\n", policy.Deny},
		{"granted to the automation of the same id", "dangerous_automations: [rb]\n", policy.Deny},
		{"no grant", "", policy.Deny},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "policy.yaml")
			if err := os.WriteFile(path, []byte(tc.file), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg, err := policy.LoadConfig(path)
			if err != nil {
				t.Fatal(err)
			}
			h := newRBHarness(t, yaml, cfg)
			plan, err := h.rb.Plan(t.Context(), "rb")
			if err != nil {
				t.Fatal(err)
			}
			if got := plan.Steps[0].Decision; got != tc.want {
				t.Errorf("plan decision = %q, want %q", got, tc.want)
			}
			if n := len(h.script.calls()); n != 0 {
				t.Errorf("the plan ran %d actions", n)
			}
		})
	}
}

// TestRunbookHeldActionKeepsTheSecretOutOfTheApproval holds a webhook that
// sends a secret answer for approval. The approval is replicated and shown to
// whoever decides it, so it must not carry the answer.
func TestRunbookHeldActionKeepsTheSecretOutOfTheApproval(t *testing.T) {
	const secret = "held-secret-value"
	bodies := make(chan string, 1)
	hook := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		bodies <- string(b)
	}))
	defer hook.Close()

	// Only the steps are held: starting and answering are the operator's.
	cfg := policy.Config{Actors: map[string]map[policy.Class]policy.Mode{
		policy.ActorAutomation: {policy.Safe: policy.ModeConfirm},
	}}
	h := newRBHarness(t, `id: rb
steps:
  - id: token
    type: prompt
    message: The token?
    secret: true
  - id: send
    type: action
    action: {type: webhook, url: `+hook.URL+`/hook, body: "t={{ .Input.token }}"}
`, cfg)
	pol := policy.NewWithConfig(h.audit, h.st.Approvals(), cfg)
	h.rb = NewRunbooks(RunbooksConfig{
		Dir: h.dir, Kinds: h.kinds, Policy: pol, Runs: h.st.RunbookRuns(), Sealer: xorSealer{}, Poll: 5 * time.Millisecond,
	})
	defer h.run(h.rb)()

	id := h.start("rb")
	h.await(id, RunbookWaiting)
	h.answer(id, "token", secret)

	ctx := t.Context()
	var held store.Approval
	deadline := time.Now().Add(10 * time.Second)
	for {
		pending, err := h.st.Approvals().List(ctx, store.ApprovalPending, 10)
		if err != nil {
			t.Fatal(err)
		}
		if len(pending) == 1 {
			held = pending[0]
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the webhook was never held for approval")
		}
		time.Sleep(5 * time.Millisecond)
	}
	for what, s := range map[string]string{"target": held.Target, "detail": string(held.Detail)} {
		if strings.Contains(s, secret) {
			t.Errorf("the approval's %s holds the secret: %s", what, s)
		}
	}
	select {
	case b := <-bodies:
		t.Fatalf("the webhook ran before it was approved: %q", b)
	default:
	}

	if err := pol.Decide(context.Background(), policy.ActorWeb, "10.0.0.1", held.ID, true, func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	h.await(id, RunbookSucceeded)
	if got := <-bodies; got != "t="+secret {
		t.Errorf("webhook body = %q", got)
	}
	stored, err := h.st.RunbookRuns().Get(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(stored.State), secret) {
		t.Error("the run's state holds the secret")
	}
}
