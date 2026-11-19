// SPDX-License-Identifier: AGPL-3.0-only

package policy

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/store"
)

// reauthed is a re-authentication that passed.
func reauthed(context.Context) error { return nil }

// Approving needs the approver to re-authenticate. No check, or a failing
// one for any reason, denies the approval, audited, and leaves it pending;
// a passing one approves. Denying needs none.
func TestApproveNeedsReauth(t *testing.T) {
	s := openStore(t)
	e := NewWithConfig(s.Audit(), s.Approvals(), confirmAll(time.Minute))
	e.poll = 5 * time.Millisecond
	held := make(chan string, 1)
	ran := make(chan struct{}, 1)
	done := make(chan error, 1)
	go func() {
		done <- e.Do(t.Context(), Request{
			ActorKind: ActorAdmin, ActorID: "root", Action: DeviceRevoke, Target: "pi",
			OnHold: func(id string, _ time.Time) { held <- id },
		}, func(context.Context) error { ran <- struct{}{}; return nil })
	}()
	id := <-held

	errBusy := errors.New("verifier busy")
	tests := []struct {
		name   string
		reauth func(context.Context) error
		cause  error
	}{
		{"no check", nil, nil},
		{"wrong password", func(context.Context) error { return errors.New("wrong password") }, nil},
		// An error that is not a denial still denies: re-authentication fails closed.
		{"check failed", func(context.Context) error { return errBusy }, errBusy},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := e.Decide(t.Context(), ActorWeb, "192.0.2.1", id, true, tt.reauth)
			if !errors.Is(err, ErrReauth) || !errors.Is(err, ErrDenied) {
				t.Fatalf("Decide = %v, want ErrReauth and ErrDenied", err)
			}
			if tt.cause != nil && !errors.Is(err, tt.cause) {
				t.Errorf("Decide = %v, want it to wrap %v", err, tt.cause)
			}
			if ap, err := s.Approvals().Get(t.Context(), id); err != nil || ap.Status != store.ApprovalPending {
				t.Fatalf("approval = %+v, %v; want pending", ap, err)
			}
			entries, _ := s.Audit().List(t.Context(), 1)
			if len(entries) != 1 || entries[0].Action != string(ApprovalApprove) || entries[0].Decision != Deny ||
				!strings.Contains(entries[0].Result, "re-authenticat") {
				t.Errorf("audit = %+v, want the refused approval", entries)
			}
		})
	}
	if len(ran) != 0 {
		t.Fatal("ran without approval")
	}
	if err := e.Decide(t.Context(), ActorWeb, "192.0.2.1", id, true, reauthed); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil || len(ran) != 1 {
		t.Fatalf("Do = %v, ran %d; want approved and run", err, len(ran))
	}
}

func TestDenyNeedsNoReauth(t *testing.T) {
	s := openStore(t)
	e := NewWithConfig(s.Audit(), s.Approvals(), confirmAll(time.Minute))
	e.poll = 5 * time.Millisecond
	held := make(chan string, 1)
	done := make(chan error, 1)
	go func() {
		done <- e.Do(t.Context(), Request{
			ActorKind: ActorAdmin, ActorID: "root", Action: DeviceRevoke, Target: "pi",
			OnHold: func(id string, _ time.Time) { held <- id },
		}, func(context.Context) error { return nil })
	}()
	if err := e.Decide(t.Context(), ActorWeb, "192.0.2.1", <-held, false, nil); err != nil {
		t.Fatal(err)
	}
	if err := <-done; !errors.Is(err, ErrDenied) {
		t.Fatalf("Do = %v, want denied", err)
	}
}
