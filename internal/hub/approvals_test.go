// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

// withPolicy makes the fixture's API decide with cfg, holding in its store.
func withPolicy(cfg policy.Config) func(*Config) {
	return func(c *Config) { c.Policy = policy.NewWithConfig(c.Store.Audit(), c.Store.Approvals(), cfg) }
}

func TestAPIApprovals(t *testing.T) {
	f := newAPIFixture(t, true, withPolicy(policy.Config{}))
	c := sessionCookie(t, f.login(t, testPassword))

	// The CLI holds a revocation; the web UI approves it.
	cli := policy.NewWithConfig(f.st.Audit(), f.st.Approvals(), policy.Config{
		Classes: map[policy.Class]policy.Mode{policy.Dangerous: policy.ModeConfirm},
	})
	held := make(chan string, 1)
	done := make(chan error, 1)
	ran := false
	go func() {
		done <- cli.Do(t.Context(), policy.Request{
			ActorKind: policy.ActorAdmin, ActorID: "root", Action: policy.DeviceRevoke, Target: "pi",
			OnHold: func(id string, _ time.Time) { held <- id },
		}, func(context.Context) error { ran = true; return nil })
	}()
	id := <-held

	if resp := f.do(t, http.MethodGet, "/api/v1/approvals", "", nil); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("unauthenticated list = %d", resp.StatusCode)
	}
	if resp := f.do(t, http.MethodPost, "/api/v1/approvals/"+id+"/approve", "", nil); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("unauthenticated approve = %d", resp.StatusCode)
	}
	resp := f.do(t, http.MethodGet, "/api/v1/approvals", "", c)
	list := decode[[]ApprovalJSON](t, resp)
	if resp.StatusCode != http.StatusOK || len(list) != 1 || list[0].ID != id || list[0].Action != "device.revoke" ||
		list[0].Class != "dangerous" || list[0].Status != store.ApprovalPending || list[0].ActorID != "root" {
		t.Fatalf("list = %d %+v", resp.StatusCode, list)
	}
	if resp := f.do(t, http.MethodGet, "/api/v1/approvals?status=bogus", "", c); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("bad status filter = %d", resp.StatusCode)
	}
	if resp := f.do(t, http.MethodPost, "/api/v1/approvals/nope/approve", "", c); resp.StatusCode != http.StatusNotFound {
		t.Errorf("approve unknown = %d", resp.StatusCode)
	}
	if resp := f.do(t, http.MethodPost, "/api/v1/approvals/"+id+"/approve", "", c); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("approve = %d %s", resp.StatusCode, resp.body)
	}
	if err := <-done; err != nil || !ran {
		t.Fatalf("held action = %v, ran %v; want run after approval", err, ran)
	}
	if resp := f.do(t, http.MethodPost, "/api/v1/approvals/"+id+"/deny", "", c); resp.StatusCode != http.StatusConflict {
		t.Errorf("deny after approve = %d, want 409", resp.StatusCode)
	}
	if list := decode[[]ApprovalJSON](t, f.do(t, http.MethodGet, "/api/v1/approvals", "", c)); len(list) != 0 {
		t.Errorf("pending after approval = %+v", list)
	}
	all := decode[[]ApprovalJSON](t, f.do(t, http.MethodGet, "/api/v1/approvals?status=all", "", c))
	if len(all) != 1 || all[0].Status != store.ApprovalApproved || all[0].DecidedBy != "web/127.0.0.1" || all[0].DecidedAt == nil {
		t.Errorf("all = %+v", all)
	}
}

// A pending approval shows its plan to a signed-in approver; once it is
// approved, denied or expired, the API returns none and the store holds none.
func TestAPIDecidedApprovalReturnsNoPlan(t *testing.T) {
	f := newAPIFixture(t, true, withPolicy(policy.Config{}))
	c := sessionCookie(t, f.login(t, testPassword))
	plan := map[string]any{policy.DetailPlan: map[string]any{"argv": []string{"curl", "-H", "Authorization: s3cret"}}}

	for _, outcome := range []string{store.ApprovalPending, store.ApprovalApproved, store.ApprovalDenied, store.ApprovalExpired} {
		t.Run(outcome, func(t *testing.T) {
			timeout := time.Minute
			if outcome == store.ApprovalExpired {
				timeout = 300 * time.Millisecond
			}
			cli := policy.NewWithConfig(f.st.Audit(), f.st.Approvals(), policy.Config{
				Classes:         map[policy.Class]policy.Mode{policy.Dangerous: policy.ModeConfirm},
				ApprovalTimeout: timeout,
			})
			held := make(chan string, 1)
			ctx, cancel := context.WithCancel(t.Context())
			done := make(chan error, 1)
			go func() {
				done <- cli.Do(ctx, policy.Request{
					ActorKind: policy.ActorAdmin, ActorID: "root", Action: policy.DeviceRevoke, Target: outcome,
					ApprovalDetail: plan,
					OnHold:         func(id string, _ time.Time) { held <- id },
				}, func(context.Context) error { return nil })
			}()
			id := <-held
			if outcome == store.ApprovalPending {
				list := decode[[]ApprovalJSON](t, f.do(t, http.MethodGet, "/api/v1/approvals", "", c))
				if len(list) == 0 || list[0].ID != id || !strings.Contains(string(list[0].Detail), "s3cret") {
					t.Errorf("pending list = %+v, want the plan", list)
				}
				cancel()
				<-done
				return
			}
			defer cancel()
			if outcome != store.ApprovalExpired {
				verb := map[string]string{store.ApprovalApproved: "approve", store.ApprovalDenied: "deny"}[outcome]
				if resp := f.do(t, http.MethodPost, "/api/v1/approvals/"+id+"/"+verb, "", c); resp.StatusCode != http.StatusNoContent {
					t.Fatalf("%s = %d %s", verb, resp.StatusCode, resp.body)
				}
			}
			<-done

			var got *ApprovalJSON
			list := decode[[]ApprovalJSON](t, f.do(t, http.MethodGet, "/api/v1/approvals?status=all", "", c))
			for i := range list {
				if list[i].ID == id {
					got = &list[i]
				}
			}
			if got == nil {
				t.Fatalf("approval %s not listed in %+v", id, list)
			}
			if got.Status != outcome {
				t.Fatalf("status = %s, want %s", got.Status, outcome)
			}
			if strings.Contains(string(got.Detail), "s3cret") || strings.Contains(string(got.Detail), policy.DetailPlan) {
				t.Errorf("API detail = %s, want no plan", got.Detail)
			}
			ap, err := f.st.Approvals().Get(t.Context(), id)
			if err != nil || strings.Contains(string(ap.Detail), "s3cret") {
				t.Errorf("stored detail = %s, %v; want no plan", ap.Detail, err)
			}
		})
	}
}

func TestAPICreateTokenDryRun(t *testing.T) {
	tests := []struct {
		name     string
		cfg      policy.Config
		status   int
		decision string
	}{
		{"allowed", policy.Config{}, http.StatusOK, policy.Allow},
		{"would be held", policy.Config{Actors: map[string]map[policy.Class]policy.Mode{
			policy.ActorWeb: {policy.Safe: policy.ModeConfirm},
		}}, http.StatusOK, policy.Confirm},
		{"denied", policy.Config{Classes: map[policy.Class]policy.Mode{policy.Safe: policy.ModeDeny}}, http.StatusForbidden, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newAPIFixture(t, true, withPolicy(tt.cfg))
			c := sessionCookie(t, f.login(t, testPassword))
			resp := f.do(t, http.MethodPost, "/api/v1/tokens", `{"dry_run":true}`, c)
			if resp.StatusCode != tt.status {
				t.Fatalf("status = %d, body %s", resp.StatusCode, resp.body)
			}
			if tt.decision != "" {
				if got := decode[DryRunJSON](t, resp); !got.DryRun || got.Decision != tt.decision {
					t.Errorf("body = %+v, want decision %s", got, tt.decision)
				}
			}
			entries, err := f.st.Audit().List(t.Context(), 10)
			if err != nil || entries[0].Action != string(policy.TokenCreate) || !strings.HasPrefix(entries[0].Result, policy.DryRun) {
				t.Fatalf("audit = %+v, %v", entries, err)
			}
			if len(entries) != 3 { // set-password, login, then the dry run alone
				t.Errorf("audit has %d entries, want 3", len(entries))
			}
			if aps, _ := f.st.Approvals().List(t.Context(), "", 10); len(aps) != 0 {
				t.Error("a dry run held an approval")
			}
		})
	}
}
