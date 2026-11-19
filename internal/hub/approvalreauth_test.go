// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

// reauthed is a re-authentication that passed.
func reauthed(context.Context) error { return nil }

// passwordBody is the body of an approve request.
func passwordBody(password string) string {
	b, _ := json.Marshal(map[string]string{"password": password})
	return string(b)
}

// holdRevocation holds a dangerous revocation for approval in f's store, as
// the CLI would, and returns its approval id, whether it ran, and its outcome.
func holdRevocation(t *testing.T, f *apiFixture) (id string, ran func() bool, done <-chan error) {
	t.Helper()
	cli := policy.NewWithConfig(f.st.Audit(), f.st.Approvals(), policy.Config{
		Classes: map[policy.Class]policy.Mode{policy.Dangerous: policy.ModeConfirm},
	})
	held := make(chan string, 1)
	out := make(chan error, 1)
	didRun := make(chan struct{}, 1)
	go func() {
		out <- cli.Do(context.WithoutCancel(t.Context()), policy.Request{
			ActorKind: policy.ActorAdmin, ActorID: "root", Action: policy.DeviceRevoke, Target: "pi",
			OnHold: func(id string, _ time.Time) { held <- id },
		}, func(context.Context) error { didRun <- struct{}{}; return nil })
	}()
	return <-held, func() bool { return len(didRun) > 0 }, out
}

// Approving needs the admin password again, in the request: a session alone,
// such as a stolen cookie, cannot approve. Every refusal leaves the approval
// pending and is audited, without the password.
func TestApproveNeedsPassword(t *testing.T) {
	const (
		wrong = "wrong-guess-7f3a9c"
		other = "another-hubs-admin-pw-55e1" // a real password, of another account
	)
	f := newAPIFixture(t, true, withPolicy(policy.Config{}))
	// The victim's session, and the same cookie in a thief's hands.
	stolen := sessionCookie(t, f.login(t, testPassword))
	id, ran, done := holdRevocation(t, f)
	path := "/api/v1/approvals/" + id + "/approve"

	tests := []struct {
		name, contentType, body string
	}{
		{"no body", "", ""},
		{"no password", "application/json", `{}`},
		{"empty password", "application/json", passwordBody("")},
		{"wrong password", "application/json", passwordBody(wrong)},
		{"another account's password", "application/json", passwordBody(other)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := f.send(t, http.MethodPost, path, tt.contentType, tt.body, stolen)
			if resp.StatusCode != http.StatusForbidden {
				t.Fatalf("approve = %d %s, want 403", resp.StatusCode, resp.body)
			}
			var e ErrorJSON
			if err := json.Unmarshal(resp.body, &e); err != nil || e.Code != "reauth_failed" {
				t.Errorf("error = %s, want code reauth_failed", resp.body)
			}
			ap, err := f.st.Approvals().Get(t.Context(), id)
			if err != nil || ap.Status != store.ApprovalPending {
				t.Fatalf("approval = %+v, %v; want still pending", ap, err)
			}
			if ran() {
				t.Fatal("the held action ran")
			}
		})
	}
	// A deny needs no password.
	entries, err := f.st.Audit().List(t.Context(), 50)
	if err != nil {
		t.Fatal(err)
	}
	refusals := 0
	for _, e := range entries {
		if e.Action == string(policy.ApprovalApprove) && e.Target == id {
			if e.Decision != policy.Deny || !strings.Contains(e.Result, "re-authenticat") {
				t.Errorf("approve audit entry = %+v, want a re-authentication denial", e)
			}
			refusals++
		}
	}
	if refusals != len(tests) {
		t.Errorf("audited %d refused approvals, want %d", refusals, len(tests))
	}

	// The right password approves.
	if resp := f.do(t, http.MethodPost, path, passwordBody(testPassword), stolen); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("approve with the password = %d %s", resp.StatusCode, resp.body)
	}
	if err := <-done; err != nil || !ran() {
		t.Fatalf("held action = %v, ran %v; want run after approval", err, ran())
	}

	// No password, right or wrong, is in the audit log, the logs or the approval.
	entries, err = f.st.Audit().List(t.Context(), 100)
	if err != nil {
		t.Fatal(err)
	}
	ap, err := f.st.Approvals().Get(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	for _, pw := range []string{testPassword, wrong, other} {
		for _, e := range entries {
			if strings.Contains(e.Result+e.Target+e.ActorID+string(e.Detail), pw) {
				t.Errorf("audit entry holds a password: %+v", e)
			}
		}
		if strings.Contains(f.logs.String(), pw) {
			t.Errorf("the logs hold a password")
		}
		if strings.Contains(ap.DecidedBy+string(ap.Detail), pw) {
			t.Errorf("the approval holds a password: %+v", ap)
		}
	}
}

// A refused approve answers without echoing the password.
func TestApproveRefusalHidesPassword(t *testing.T) {
	const wrong = "do-not-echo-me-31c8"
	f := newAPIFixture(t, true, withPolicy(policy.Config{}))
	c := sessionCookie(t, f.login(t, testPassword))
	id, _, _ := holdRevocation(t, f)
	resp := f.do(t, http.MethodPost, "/api/v1/approvals/"+id+"/approve", passwordBody(wrong), c)
	if resp.StatusCode != http.StatusForbidden || strings.Contains(string(resp.body), wrong) {
		t.Errorf("approve = %d %s; want 403 without the password", resp.StatusCode, resp.body)
	}
	for k, v := range resp.Header {
		if strings.Contains(strings.Join(v, " "), wrong) {
			t.Errorf("header %s holds the password", k)
		}
	}
}

// Approving shares login's rate limit: guessing the password through
// approvals is no faster than through login.
func TestApproveRateLimited(t *testing.T) {
	f := newAPIFixture(t, true, withPolicy(policy.Config{}))
	c := sessionCookie(t, f.login(t, testPassword))
	id, ran, _ := holdRevocation(t, f)
	path := "/api/v1/approvals/" + id + "/approve"
	limited := false
	for range loginBurst + 1 {
		resp := f.do(t, http.MethodPost, path, passwordBody("wrong-guess-a1b2c3"), c)
		if resp.StatusCode == http.StatusTooManyRequests {
			limited = true
			break
		}
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("approve = %d %s", resp.StatusCode, resp.body)
		}
	}
	if !limited {
		t.Fatal("wrong passwords were never rate limited")
	}
	// Even the right password waits.
	if resp := f.do(t, http.MethodPost, path, passwordBody(testPassword), c); resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("approve while limited = %d, want 429", resp.StatusCode)
	}
	if ap, err := f.st.Approvals().Get(t.Context(), id); err != nil || ap.Status != store.ApprovalPending || ran() {
		t.Errorf("approval = %+v, %v, ran %v; want pending", ap, err, ran())
	}
}

// Denying needs no password: it can only stop an action.
func TestDenyNeedsNoPassword(t *testing.T) {
	f := newAPIFixture(t, true, withPolicy(policy.Config{}))
	c := sessionCookie(t, f.login(t, testPassword))
	id, ran, done := holdRevocation(t, f)
	if resp := f.do(t, http.MethodPost, "/api/v1/approvals/"+id+"/deny", "", c); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("deny = %d %s", resp.StatusCode, resp.body)
	}
	if err := <-done; !errors.Is(err, policy.ErrDenied) || ran() {
		t.Errorf("held action = %v, ran %v; want denied", err, ran())
	}
}

// An approval link cannot approve, with or without a password: it only
// denies. Its approve is refused and audited, and leaves both the approval
// pending and the link unspent.
func TestApprovalLinkCannotApprove(t *testing.T) {
	f, pol, ntfy := linkFixture(t, time.Minute)
	secret, runs, done := holdExec(t, pol, ntfy)
	withPassword, _ := json.Marshal(map[string]string{"token": secret, "password": testPassword})
	for _, body := range []string{tokenBody(secret), string(withPassword)} {
		resp := f.do(t, http.MethodPost, "/api/v1/approval-link/approve", body, nil)
		var e ErrorJSON
		if resp.StatusCode != http.StatusForbidden || json.Unmarshal(resp.body, &e) != nil || e.Code != "signin_required" {
			t.Fatalf("approve by link = %d %s, want 403 signin_required", resp.StatusCode, resp.body)
		}
	}
	if runs() != 0 {
		t.Fatal("ran without approval")
	}
	// The link still works, for a deny.
	resp := f.do(t, http.MethodPost, "/api/v1/approval-link", tokenBody(secret), nil)
	if ap := decode[ApprovalJSON](t, resp); resp.StatusCode != http.StatusOK || ap.Status != store.ApprovalPending {
		t.Fatalf("peek after refused approve = %d %+v", resp.StatusCode, ap)
	}
	if resp := f.do(t, http.MethodPost, "/api/v1/approval-link/deny", tokenBody(secret), nil); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("deny by link = %d %s", resp.StatusCode, resp.body)
	}
	if err := <-done; !errors.Is(err, policy.ErrDenied) || runs() != 0 {
		t.Fatalf("held action = %v, runs %d; want denied", err, runs())
	}
	entries, err := f.st.Audit().List(t.Context(), 50)
	if err != nil {
		t.Fatal(err)
	}
	refused := 0
	for _, e := range entries {
		if e.ActorKind == policy.ActorApprovalLink && e.Action == string(policy.ApprovalApprove) {
			if e.Decision != policy.Deny {
				t.Errorf("approve by link audited as %+v", e)
			}
			refused++
		}
		if strings.Contains(e.Result+e.Target+string(e.Detail), testPassword) || strings.Contains(e.Result+string(e.Detail), secret) {
			t.Errorf("audit entry holds a secret: %+v", e)
		}
	}
	if refused != 2 {
		t.Errorf("audited %d refused link approvals, want 2", refused)
	}
	if strings.Contains(f.logs.String(), testPassword) {
		t.Error("the logs hold the password")
	}
}
