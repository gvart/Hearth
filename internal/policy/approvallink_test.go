// SPDX-License-Identifier: AGPL-3.0-only

package policy

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/store"
)

// TestOnHeldSeesEveryHold checks the hook gets the stored approval.
func TestOnHeldSeesEveryHold(t *testing.T) {
	s := openStore(t)
	e := NewWithConfig(s.Audit(), s.Approvals(), confirmAll(50*time.Millisecond))
	e.poll = 5 * time.Millisecond
	var got []store.Approval
	e.OnHeld(func(ctx context.Context, ap store.Approval) {
		// The approval is stored by now.
		if _, err := s.Approvals().Get(ctx, ap.ID); err != nil {
			t.Errorf("held approval not stored: %v", err)
		}
		got = append(got, ap)
	})
	err := e.Do(t.Context(), Request{ActorKind: ActorAutomation, ActorID: "a", Action: AutomationExec, Target: "pi"},
		func(context.Context) error { return nil })
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("Do = %v, want denied on expiry", err)
	}
	if len(got) != 1 || got[0].Action != string(AutomationExec) || got[0].Target != "pi" || got[0].ActorID != "a" {
		t.Errorf("OnHeld got %+v", got)
	}
	// Allowed and denied requests are never held.
	_ = e.Do(t.Context(), Request{ActorKind: ActorToken, ActorID: "t", Action: DeviceEnroll}, func(context.Context) error { return nil })
	_ = e.Do(t.Context(), Request{ActorKind: ActorWeb, ActorID: "w", Action: DeviceRevoke}, func(context.Context) error { return nil })
	if len(got) != 1 {
		t.Errorf("OnHeld called %d times, want 1", len(got))
	}
}

// TestDecideLink approves a held action through its link once; every
// other use of a link is denied and audited.
func TestDecideLink(t *testing.T) {
	s := openStore(t)
	e := NewWithConfig(s.Audit(), s.Approvals(), confirmAll(time.Minute))
	e.poll = 5 * time.Millisecond
	links := s.ApprovalLinks()
	// The link exists once OnHeld has created it; OnHold fires before that.
	held := make(chan string, 1)
	e.OnHeld(func(ctx context.Context, ap store.Approval) {
		if err := links.Create(ctx, "secret-"+ap.ID, ap.ID, ap.ExpiresAt); err != nil {
			t.Error(err)
		}
		held <- ap.ID
	})
	use := func(secret string) func(context.Context) (string, error) {
		return func(ctx context.Context) (string, error) { return links.Use(ctx, secret, time.Now()) }
	}
	runs := 0
	done := make(chan error, 1)
	stopped := make(chan struct{})
	t.Cleanup(func() { <-stopped }) // a failed test must not leave Do running
	go func() {
		defer close(stopped)
		done <- e.Do(t.Context(), Request{
			ActorKind: ActorAutomation, ActorID: "a", Action: AutomationExec, Target: "pi",
		}, func(context.Context) error { runs++; return nil })
	}()
	id := <-held

	// A wrong link is refused before anything is decided.
	if err := e.DecideLink(t.Context(), "198.51.100.7", true, use("guess")); !errors.Is(err, store.ErrNotFound) || !errors.Is(err, ErrDenied) {
		t.Fatalf("wrong link = %v, want ErrNotFound and ErrDenied", err)
	}
	if err := e.DecideLink(t.Context(), "198.51.100.7", true, use("secret-"+id)); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil || runs != 1 {
		t.Fatalf("Do = %v, runs %d; want approved and run once", err, runs)
	}
	// Reusing the link, to approve or deny, is refused.
	for _, approve := range []bool{true, false} {
		if err := e.DecideLink(t.Context(), "198.51.100.7", approve, use("secret-"+id)); !errors.Is(err, store.ErrTokenUsed) || !errors.Is(err, ErrDenied) {
			t.Errorf("reused link (approve %v) = %v, want ErrTokenUsed", approve, err)
		}
	}
	if runs != 1 {
		t.Errorf("runs = %d after reuse, want 1", runs)
	}

	ap, err := s.Approvals().Get(t.Context(), id)
	if err != nil || ap.Status != store.ApprovalApproved || ap.DecidedBy != "approval_link/198.51.100.7" {
		t.Errorf("approval = %+v, %v", ap, err)
	}
	entries, _ := s.Audit().List(t.Context(), 10)
	var trail []string
	for _, en := range slices.Backward(entries) {
		trail = append(trail, en.ActorKind+":"+en.Action+":"+en.Decision)
	}
	want := []string{
		"automation:automation.exec:confirm",
		"approval_link:approval.approve:deny", // the wrong link
		"approval_link:approval.approve:allow",
		"automation:automation.exec:allow",
		"approval_link:approval.approve:deny", // reused
		"approval_link:approval.deny:deny",    // reused
	}
	if !slices.Equal(trail, want) {
		t.Errorf("audit trail = %v\nwant %v", trail, want)
	}
	for _, en := range entries {
		if strings.Contains(string(en.Detail)+en.Result+en.Target, "secret-") {
			t.Errorf("audit entry %+v holds the link secret", en)
		}
	}
	if !strings.Contains(entries[0].Result, "already used") {
		t.Errorf("reused link result = %q", entries[0].Result)
	}
}

// TestDecideLinkExpired: a link cannot outlive its approval, and an
// approval nobody decides is denied.
func TestDecideLinkExpired(t *testing.T) {
	s := openStore(t)
	e := NewWithConfig(s.Audit(), s.Approvals(), confirmAll(50*time.Millisecond))
	e.poll = 5 * time.Millisecond
	var id string
	e.OnHeld(func(ctx context.Context, ap store.Approval) {
		id = ap.ID
		if err := s.ApprovalLinks().Create(ctx, "secret", ap.ID, ap.ExpiresAt); err != nil {
			t.Error(err)
		}
	})
	ran := false
	err := e.Do(t.Context(), Request{ActorKind: ActorAutomation, ActorID: "a", Action: AutomationExec, Target: "pi"},
		func(context.Context) error { ran = true; return nil })
	if !errors.Is(err, ErrDenied) || ran {
		t.Fatalf("Do = %v, ran %v; want denied on expiry", err, ran)
	}
	err = e.DecideLink(t.Context(), "198.51.100.7", true, func(ctx context.Context) (string, error) {
		return s.ApprovalLinks().Use(ctx, "secret", time.Now())
	})
	if !errors.Is(err, store.ErrTokenExpired) || !errors.Is(err, ErrDenied) {
		t.Errorf("expired link = %v, want ErrTokenExpired", err)
	}
	if ap, _ := s.Approvals().Get(t.Context(), id); ap.Status != store.ApprovalExpired {
		t.Errorf("approval status = %s, want expired", ap.Status)
	}
}
