// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/notify"
	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

// fakeNtfy records the messages an ntfy server gets.
type fakeNtfy struct {
	mu   sync.Mutex
	msgs []map[string]any
	got  chan struct{}
}

func newFakeNtfy(t *testing.T) (*fakeNtfy, *notify.Notifier) {
	t.Helper()
	f := &fakeNtfy{got: make(chan struct{}, 10)}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		f.mu.Lock()
		f.msgs = append(f.msgs, m)
		f.mu.Unlock()
		f.got <- struct{}{}
		_, _ = io.WriteString(w, `{"id":"x"}`)
	}))
	t.Cleanup(srv.Close)
	n, err := notify.Parse([]byte("channels:\n  phone:\n    type: ntfy\n    url: " + srv.URL + "\n    topic: lab\n"))
	if err != nil {
		t.Fatal(err)
	}
	return f, n
}

func (f *fakeNtfy) last(t *testing.T) map[string]any {
	t.Helper()
	select {
	case <-f.got:
	case <-time.After(5 * time.Second):
		t.Fatal("no notification")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.msgs[len(f.msgs)-1]
}

// linkFixture is an API whose policy holds dangerous automation actions
// and sends each hold to a fake ntfy with an approval link.
func linkFixture(t *testing.T, timeout time.Duration) (*apiFixture, *policy.Engine, *fakeNtfy) {
	t.Helper()
	ntfy, notifier := newFakeNtfy(t)
	var pol *policy.Engine
	f := newAPIFixture(t, true, func(c *Config) {
		pol = policy.NewWithConfig(c.Store.Audit(), c.Store.Approvals(), policy.Config{
			Actors:          map[string]map[policy.Class]policy.Mode{policy.ActorAutomation: {policy.Dangerous: policy.ModeConfirm}},
			ApprovalTimeout: timeout,
		})
		pol.OnHeld(NewApprovalNotifier(ApprovalNotifierConfig{
			Links: c.Store.ApprovalLinks(), Notifier: notifier, Channel: "phone",
			BaseURL: "https://hub.lan:8443/", Log: c.Log,
		}))
		c.Policy = pol
	})
	return f, pol, ntfy
}

// holdExec starts a held automation exec and returns the approval link's
// secret, how many times it ran, and its outcome.
func holdExec(t *testing.T, pol *policy.Engine, ntfy *fakeNtfy) (secret string, runs func() int, done <-chan error) {
	t.Helper()
	var (
		mu sync.Mutex
		n  int
	)
	out := make(chan error, 1)
	go func() {
		out <- pol.Do(context.WithoutCancel(t.Context()), policy.Request{
			ActorKind: policy.ActorAutomation, ActorID: "disk-report", Action: policy.AutomationExec, Target: "pi",
			Detail: map[string]any{"command": "df -h"},
		}, func(context.Context) error { mu.Lock(); n++; mu.Unlock(); return nil })
	}()
	msg := ntfy.last(t)
	link, _ := msg["click"].(string)
	const prefix = "https://hub.lan:8443/#/approve/"
	if !strings.HasPrefix(link, prefix) || len(link) < len(prefix)+40 {
		t.Fatalf("notification link = %q; message %v", link, msg)
	}
	if body, _ := msg["message"].(string); !strings.Contains(body, "automation/disk-report") || !strings.Contains(body, "automation.exec on pi") ||
		!strings.Contains(body, "df -h") {
		t.Errorf("notification body = %q", body)
	}
	return strings.TrimPrefix(link, prefix), func() int { mu.Lock(); defer mu.Unlock(); return n }, out
}

func tokenBody(secret string) string {
	b, _ := json.Marshal(map[string]string{"token": secret})
	return string(b)
}

func TestApprovalLinkDeniesOnce(t *testing.T) {
	f, pol, ntfy := linkFixture(t, time.Minute)
	secret, runs, done := holdExec(t, pol, ntfy)

	// Bad requests and wrong links decide nothing.
	if resp := f.send(t, http.MethodPost, "/api/v1/approval-link/deny", "text/plain", tokenBody(secret), nil); resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Errorf("deny as text/plain = %d", resp.StatusCode)
	}
	if resp := f.do(t, http.MethodPost, "/api/v1/approval-link/deny", `{}`, nil); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("deny without a token = %d", resp.StatusCode)
	}
	for _, path := range []string{"/api/v1/approval-link", "/api/v1/approval-link/deny"} {
		if resp := f.do(t, http.MethodPost, path, tokenBody(secret+"x"), nil); resp.StatusCode != http.StatusGone {
			t.Errorf("%s with a wrong token = %d, want 410", path, resp.StatusCode)
		}
	}

	// The page shows the action, without a session and without using the link.
	for range 2 {
		resp := f.do(t, http.MethodPost, "/api/v1/approval-link", tokenBody(secret), nil)
		ap := decode[ApprovalJSON](t, resp)
		if resp.StatusCode != http.StatusOK || ap.Action != "automation.exec" || ap.Target != "pi" || ap.Status != store.ApprovalPending {
			t.Fatalf("peek = %d %+v", resp.StatusCode, ap)
		}
	}
	if runs() != 0 {
		t.Fatal("ran before approval")
	}

	if resp := f.do(t, http.MethodPost, "/api/v1/approval-link/deny", tokenBody(secret), nil); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("deny = %d %s", resp.StatusCode, resp.body)
	}
	if err := <-done; !errors.Is(err, policy.ErrDenied) || runs() != 0 {
		t.Fatalf("held action = %v, runs %d; want denied", err, runs())
	}
	// The link is spent: no second deny, no peek.
	for _, path := range []string{"/api/v1/approval-link/deny", "/api/v1/approval-link"} {
		if resp := f.do(t, http.MethodPost, path, tokenBody(secret), nil); resp.StatusCode != http.StatusGone {
			t.Errorf("%s after use = %d, want 410", path, resp.StatusCode)
		}
	}
	if runs() != 0 {
		t.Errorf("runs = %d, want 0", runs())
	}

	entries, err := f.st.Audit().List(t.Context(), 20)
	if err != nil {
		t.Fatal(err)
	}
	var deniedByLink bool
	for _, e := range entries {
		if e.ActorKind == policy.ActorApprovalLink && e.Action == string(policy.ApprovalDeny) && e.Decision == policy.Allow {
			deniedByLink = e.ActorID == "127.0.0.1"
		}
		if strings.Contains(e.Result+e.Target+string(e.Detail), secret) {
			t.Errorf("audit entry holds the link secret: %+v", e)
		}
	}
	if !deniedByLink {
		t.Error("no audit entry for the denial by link")
	}
	if strings.Contains(f.logs.String(), secret) {
		t.Error("the link secret is in the logs")
	}
}

func TestApprovalLinkDenies(t *testing.T) {
	f, pol, ntfy := linkFixture(t, time.Minute)
	secret, runs, done := holdExec(t, pol, ntfy)
	if resp := f.do(t, http.MethodPost, "/api/v1/approval-link/deny", tokenBody(secret), nil); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("deny = %d %s", resp.StatusCode, resp.body)
	}
	if err := <-done; !errors.Is(err, policy.ErrDenied) || runs() != 0 {
		t.Fatalf("held action = %v, runs %d; want denied", err, runs())
	}
	if resp := f.do(t, http.MethodPost, "/api/v1/approval-link/deny", tokenBody(secret), nil); resp.StatusCode != http.StatusGone {
		t.Errorf("deny after deny = %d, want 410", resp.StatusCode)
	}
}

// An approval decided elsewhere first leaves its link unable to decide.
func TestApprovalLinkAfterUIDecision(t *testing.T) {
	f, pol, ntfy := linkFixture(t, time.Minute)
	secret, _, done := holdExec(t, pol, ntfy)
	c := sessionCookie(t, f.login(t, testPassword))
	list := decode[[]ApprovalJSON](t, f.do(t, http.MethodGet, "/api/v1/approvals", "", c))
	if len(list) != 1 {
		t.Fatalf("pending = %+v", list)
	}
	if resp := f.do(t, http.MethodPost, "/api/v1/approvals/"+list[0].ID+"/deny", "", c); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("UI deny = %d", resp.StatusCode)
	}
	if err := <-done; !errors.Is(err, policy.ErrDenied) {
		t.Fatalf("held action = %v, want denied", err)
	}
	resp := f.do(t, http.MethodPost, "/api/v1/approval-link", tokenBody(secret), nil)
	if ap := decode[ApprovalJSON](t, resp); resp.StatusCode != http.StatusOK || ap.Status != store.ApprovalDenied {
		t.Errorf("peek after UI deny = %d %+v", resp.StatusCode, ap)
	}
	if resp := f.do(t, http.MethodPost, "/api/v1/approval-link/deny", tokenBody(secret), nil); resp.StatusCode != http.StatusConflict {
		t.Errorf("deny after UI deny = %d, want 409", resp.StatusCode)
	}
}

func TestApprovalLinkExpires(t *testing.T) {
	f, pol, ntfy := linkFixture(t, 300*time.Millisecond)
	secret, runs, done := holdExec(t, pol, ntfy)
	if err := <-done; !errors.Is(err, policy.ErrDenied) || runs() != 0 {
		t.Fatalf("unapproved action = %v, runs %d; want denied on expiry", err, runs())
	}
	for _, path := range []string{"/api/v1/approval-link", "/api/v1/approval-link/deny"} {
		if resp := f.do(t, http.MethodPost, path, tokenBody(secret), nil); resp.StatusCode != http.StatusGone {
			t.Errorf("%s after expiry = %d, want 410", path, resp.StatusCode)
		}
	}
	if runs() != 0 {
		t.Error("ran after expiry")
	}
}

// Without a link (the store cannot hold one) the hold is still notified.
func TestApprovalNotifierWithoutLink(t *testing.T) {
	ntfy, notifier := newFakeNtfy(t)
	st := newTestStore(t)
	_ = st.Close() // every write now fails
	hook := NewApprovalNotifier(ApprovalNotifierConfig{
		Links: st.ApprovalLinks(), Notifier: notifier, Channel: "phone", BaseURL: "https://hub.lan:8443",
		Log: slog.New(slog.DiscardHandler),
	})
	hook(t.Context(), store.Approval{
		ID: "a", ActorKind: "automation", ActorID: "x", Action: "automation.exec", Class: "dangerous",
		ExpiresAt: time.Now().Add(time.Minute),
	})
	msg := ntfy.last(t)
	if _, ok := msg["click"]; ok {
		t.Errorf("message has a link: %v", msg)
	}
	if body, _ := msg["message"].(string); !strings.Contains(body, "in Hearth") {
		t.Errorf("body = %q", body)
	}
}
