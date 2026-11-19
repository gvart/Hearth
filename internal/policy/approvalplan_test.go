// SPDX-License-Identifier: AGPL-3.0-only

package policy

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/store"
)

// TestDecidedApprovalKeepsNoPlan: the plan of a held request is stored while
// the approval is pending, and gone once it is approved, denied or expired.
func TestDecidedApprovalKeepsNoPlan(t *testing.T) {
	plan := map[string]any{DetailPlan: map[string]any{"argv": []string{"curl", "-H", "Authorization: s3cret"}}}
	for _, outcome := range []string{store.ApprovalApproved, store.ApprovalDenied, store.ApprovalExpired} {
		t.Run(outcome, func(t *testing.T) {
			s := openStore(t)
			timeout := time.Minute
			if outcome == store.ApprovalExpired {
				timeout = 50 * time.Millisecond
			}
			e := NewWithConfig(s.Audit(), s.Approvals(), confirmAll(timeout))
			e.poll = 5 * time.Millisecond
			held := make(chan string, 1)
			done := make(chan error, 1)
			go func() {
				done <- e.Do(t.Context(), Request{
					ActorKind: ActorAutomation, ActorID: "a", Action: AutomationExec, Target: "pi",
					ApprovalDetail: plan,
					OnHold:         func(id string, _ time.Time) { held <- id },
				}, func(context.Context) error { return nil })
			}()
			id := <-held
			if outcome != store.ApprovalExpired {
				ap, err := s.Approvals().Get(t.Context(), id)
				if err != nil || !strings.Contains(string(ap.Detail), "s3cret") {
					t.Fatalf("pending detail = %s, %v; want the plan", ap.Detail, err)
				}
				if err := e.Decide(t.Context(), ActorWeb, "w", id, outcome == store.ApprovalApproved); err != nil {
					t.Fatal(err)
				}
			}
			<-done
			ap, err := s.Approvals().Get(t.Context(), id)
			if err != nil || ap.Status != outcome {
				t.Fatalf("approval = %+v, %v; want %s", ap, err, outcome)
			}
			if strings.Contains(string(ap.Detail), "s3cret") || strings.Contains(string(ap.Detail), DetailPlan) {
				t.Errorf("decided detail = %s, want no plan", ap.Detail)
			}
		})
	}
}
