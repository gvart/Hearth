// SPDX-License-Identifier: AGPL-3.0-only

package policy

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/store"
)

const sweepPlan = `{"device":"pi","plan":{"argv":["curl","-H","Authorization: s3cret"]}}`

// orphan stores a pending approval whose requester is gone, as a hub restart
// leaves one.
func orphan(t *testing.T, s *store.Store, id string, created time.Time, ttl time.Duration) {
	t.Helper()
	if err := s.Approvals().Create(t.Context(), store.Approval{
		ID: id, CreatedAt: created, ExpiresAt: created.Add(ttl), ActorKind: ActorAutomation, ActorID: "a",
		Action: string(AutomationExec), Class: string(Dangerous), Target: "pi", Detail: []byte(sweepPlan),
	}); err != nil {
		t.Fatal(err)
	}
}

func TestSweepApprovals(t *testing.T) {
	s := openStore(t)
	ctx := t.Context()
	base := time.UnixMilli(1_700_000_000_000).UTC()
	orphan(t, s, "due", base, time.Minute)
	orphan(t, s, "notdue", base, time.Hour)
	orphan(t, s, "denied", base, time.Minute)
	orphan(t, s, "approved", base, time.Hour)
	if err := s.Approvals().Decide(ctx, "denied", store.ApprovalDenied, "web/w", base.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := s.Approvals().Decide(ctx, "approved", store.ApprovalApproved, "web/w", base.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	e := NewWithConfig(s.Audit(), s.Approvals(), confirmAll(time.Minute))
	e.now = func() time.Time { return base.Add(2 * time.Minute) }

	n, err := e.SweepApprovals(ctx)
	if err != nil || n != 1 {
		t.Fatalf("SweepApprovals = %d, %v; want 1, nil", n, err)
	}

	due, err := s.Approvals().Get(ctx, "due")
	if err != nil || due.Status != store.ApprovalExpired || due.DecidedBy != "timeout" {
		t.Fatalf("due = %+v, %v; want expired by timeout", due, err)
	}
	if strings.Contains(string(due.Detail), "s3cret") || strings.Contains(string(due.Detail), DetailPlan) {
		t.Errorf("expired detail = %s, want no plan", due.Detail)
	}
	notdue, _ := s.Approvals().Get(ctx, "notdue")
	if notdue.Status != store.ApprovalPending || !strings.Contains(string(notdue.Detail), "s3cret") {
		t.Errorf("not-yet-due = %s %s, want pending with its plan", notdue.Status, notdue.Detail)
	}
	denied, _ := s.Approvals().Get(ctx, "denied")
	if denied.Status != store.ApprovalDenied || denied.DecidedBy != "web/w" {
		t.Errorf("denied = %+v, want untouched", denied)
	}
	approved, _ := s.Approvals().Get(ctx, "approved")
	if approved.Status != store.ApprovalApproved || approved.DecidedBy != "web/w" {
		t.Errorf("approved = %+v, want untouched", approved)
	}

	entries, err := s.Audit().List(ctx, 10)
	if err != nil || len(entries) != 1 {
		t.Fatalf("audit = %+v, %v; want one entry", entries, err)
	}
	got := entries[0]
	if got.Decision != Deny || got.Action != string(AutomationExec) || got.Target != "pi" ||
		!strings.Contains(got.Result, "expired") || !strings.Contains(string(got.Detail), `"approval":"due"`) {
		t.Errorf("audit entry = %+v, want a denial naming approval due", got)
	}
	if strings.Contains(string(got.Detail), "s3cret") {
		t.Errorf("audit detail = %s, want no plan", got.Detail)
	}

	// A second sweep finds nothing and audits nothing more.
	if n, err := e.SweepApprovals(ctx); err != nil || n != 0 {
		t.Errorf("second SweepApprovals = %d, %v; want 0, nil", n, err)
	}
	if entries, _ := s.Audit().List(ctx, 10); len(entries) != 1 {
		t.Errorf("audit has %d entries after a second sweep, want 1", len(entries))
	}
}

// A hold whose requester is waiting is left to it: the sweep may race its
// expiry, and either way the approval is expired and audited once.
func TestSweepApprovalsAfterWaiterExpired(t *testing.T) {
	s := openStore(t)
	ctx := t.Context()
	base := time.UnixMilli(1_700_000_000_000).UTC()
	orphan(t, s, "x", base, time.Minute)
	e := NewWithConfig(s.Audit(), s.Approvals(), confirmAll(time.Minute))
	e.now = func() time.Time { return base.Add(2 * time.Minute) }
	e.expire(ctx, "x") // the waiter got there first
	if n, err := e.SweepApprovals(ctx); err != nil || n != 0 {
		t.Errorf("SweepApprovals = %d, %v; want 0, nil", n, err)
	}
	if entries, _ := s.Audit().List(ctx, 10); len(entries) != 0 {
		t.Errorf("audit = %+v, want none: the waiter audits its own expiry", entries)
	}
}

func TestSweepApprovalsHoldsNothing(t *testing.T) {
	n, err := New(nil).SweepApprovals(t.Context())
	if err != nil || n != 0 {
		t.Errorf("SweepApprovals without approvals = %d, %v; want 0, nil", n, err)
	}
}

// The sweep runs at startup, not only after one interval.
func TestRunSweepsAtStartup(t *testing.T) {
	s := openStore(t)
	base := time.Now().Add(-time.Hour)
	orphan(t, s, "due", base, time.Minute)
	e := NewWithConfig(s.Audit(), s.Approvals(), confirmAll(time.Minute))
	e.sweepEvery = time.Hour
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- e.RunApprovalSweep(ctx, slog.New(slog.NewTextHandler(io.Discard, nil))) }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		ap, err := s.Approvals().Get(t.Context(), "due")
		if err == nil && ap.Status == store.ApprovalExpired {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("approval still %+v, %v after startup", ap, err)
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Errorf("RunApprovalSweep = %v, want nil on cancel", err)
	}
}

// flakyApprovals fails the first Overdue calls, as a cluster without a quorum.
type flakyApprovals struct {
	Approvals
	failures atomic.Int32
	calls    atomic.Int32
}

func (f *flakyApprovals) Overdue(ctx context.Context, at time.Time, limit int) ([]store.Approval, error) {
	f.calls.Add(1)
	if f.failures.Add(-1) >= 0 {
		return nil, errors.New("no quorum")
	}
	return f.Approvals.Overdue(ctx, at, limit)
}

// A failed sweep is logged and retried; it neither stops the loop nor returns.
func TestRunRetriesFailedSweep(t *testing.T) {
	s := openStore(t)
	base := time.Now().Add(-time.Hour)
	orphan(t, s, "due", base, time.Minute)
	f := &flakyApprovals{Approvals: s.Approvals()}
	f.failures.Store(2)
	e := NewWithConfig(s.Audit(), f, confirmAll(time.Minute))
	e.sweepEvery = 5 * time.Millisecond
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- e.RunApprovalSweep(ctx, slog.New(slog.NewTextHandler(io.Discard, nil))) }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		ap, err := s.Approvals().Get(t.Context(), "due")
		if err == nil && ap.Status == store.ApprovalExpired {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("approval still %+v, %v after %d sweeps", ap, err, f.calls.Load())
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Errorf("RunApprovalSweep = %v, want nil on cancel", err)
	}
	if f.calls.Load() < 3 {
		t.Errorf("Overdue called %d times, want at least 3 (two failures, then a sweep)", f.calls.Load())
	}
}
