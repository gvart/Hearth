// SPDX-License-Identifier: AGPL-3.0-only

package policy

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/store"
)

func TestHolding(t *testing.T) {
	webDangerous := Request{ActorKind: ActorWeb, ActorID: "10.0.0.1", Action: AutomationApply, Target: "nightly"}
	for _, tc := range []struct {
		name string
		cfg  Config
		want string
	}{
		{name: "allowed becomes held", cfg: Config{}, want: Confirm},
		{
			name: "held stays held",
			cfg:  Config{Classes: map[Class]Mode{Dangerous: ModeConfirm}},
			want: Confirm,
		},
		{
			name: "denied stays denied",
			cfg:  Config{Actors: map[string]map[Class]Mode{ActorWeb: {Dangerous: ModeDeny}}},
			want: Deny,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := NewWithConfig(nil, nil, tc.cfg)
			before, _ := e.Check(webDangerous)
			if got, _ := e.Holding(ActorWeb, Dangerous).Check(webDangerous); got != tc.want {
				t.Errorf("decision %s, want %s", got, tc.want)
			}
			if after, _ := e.Check(webDangerous); after != before {
				t.Errorf("the original engine changed from %s to %s", before, after)
			}
		})
	}
}

func TestHoldingLeavesOtherActorsAndClasses(t *testing.T) {
	cfg := Config{Actors: map[string]map[Class]Mode{ActorMCP: {Dangerous: ModeAllow}}}
	e := NewWithConfig(nil, nil, cfg).Holding(ActorWeb, Dangerous)
	mcp := Request{ActorKind: ActorMCP, ActorID: "client", Action: AutomationApply, Target: "nightly"}
	if got, _ := e.Check(mcp); got != Allow {
		t.Errorf("another actor kind decided %s, want allow", got)
	}
}

// TestApprovalDetailIsNeverAudited: what only an approver should read goes in
// the approval, and in no entry of the audit log.
func TestApprovalDetailIsNeverAudited(t *testing.T) {
	s := openStore(t)
	e := NewWithConfig(s.Audit(), s.Approvals(), Config{Classes: map[Class]Mode{Dangerous: ModeConfirm}})
	e.poll = 5 * time.Millisecond
	req := Request{
		ActorKind: ActorWeb, ActorID: "10.0.0.1", Action: AutomationApply, Target: "nightly",
		Detail: map[string]any{"file": "nightly.yaml"}, ApprovalDetail: map[string]any{DetailPlan: "run approver-only"},
	}
	held := make(chan string, 1)
	req.OnHold = func(id string, _ time.Time) { held <- id }
	done := make(chan error, 1)
	go func() { done <- e.Do(t.Context(), req, func(context.Context) error { return nil }) }()
	id := <-held
	ap, err := s.Approvals().Get(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(ap.Detail), "approver-only") || !strings.Contains(string(ap.Detail), "nightly.yaml") {
		t.Errorf("approval detail = %s, want the file and the plan", ap.Detail)
	}
	if err := e.Decide(t.Context(), ActorAdmin, "op", id, true, reauthed); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	entries, err := s.Audit().Query(t.Context(), store.AuditFilter{}, 50)
	if err != nil {
		t.Fatal(err)
	}
	for _, en := range entries {
		if strings.Contains(string(en.Detail), "approver-only") {
			t.Errorf("audit entry %s %s holds the approval detail: %s", en.Action, en.Result, en.Detail)
		}
	}
}
