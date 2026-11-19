// SPDX-License-Identifier: AGPL-3.0-only

package policy

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/store"
)

// scriptedAudit is an Auditor that honours its context, as the store does,
// and fails every append from the failFrom-th on (never when zero).
type scriptedAudit struct {
	memAudit
	mu       sync.Mutex
	appends  int
	failFrom int
	err      error
}

func (a *scriptedAudit) Append(ctx context.Context, e store.AuditEntry) (int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	a.mu.Lock()
	a.appends++
	fail := a.failFrom > 0 && a.appends >= a.failFrom
	a.mu.Unlock()
	if fail {
		return 0, a.err
	}
	return a.memAudit.Append(ctx, e)
}

// cancellingApprovals approves what it holds and cancels the requester's
// context at the moment the requester reads that approval.
type cancellingApprovals struct {
	autoApprovals
	cancel context.CancelFunc
}

func (a *cancellingApprovals) Get(ctx context.Context, id string) (store.Approval, error) {
	a.cancel()
	return a.autoApprovals.Get(ctx, id)
}

// funcApprovals calls fn when an approval is decided: the decision is the
// action of Engine.Decide.
type funcApprovals struct {
	autoApprovals
	fn func() error
}

func (a *funcApprovals) Decide(ctx context.Context, id, status, by string, at time.Time) error {
	if err := a.fn(); err != nil {
		return err
	}
	return a.autoApprovals.Decide(ctx, id, status, by, at)
}

var errAuditDown = errors.New("audit log unavailable")

// paths are the ways an action comes to run. firstWrite is the number of the
// append that must succeed right before fn is called.
var paths = []struct {
	name       string
	firstWrite int
	do         func(ctx context.Context, t *testing.T, audit Auditor, fn func() error) error
}{
	{"allowed", 1, func(ctx context.Context, _ *testing.T, audit Auditor, fn func() error) error {
		return New(audit).Do(ctx, Request{ActorKind: ActorAdmin, ActorID: "root", Action: DeviceRevoke, Target: "pi"},
			func(context.Context) error { return fn() })
	}},
	{"confirmed", 2, func(ctx context.Context, _ *testing.T, audit Auditor, fn func() error) error {
		e := NewWithConfig(audit, &autoApprovals{decision: store.ApprovalApproved}, uniform(ModeConfirm))
		e.poll = time.Millisecond
		return e.Do(ctx, Request{ActorKind: ActorAdmin, ActorID: "root", Action: DeviceRevoke, Target: "pi"},
			func(context.Context) error { return fn() })
	}},
	{"approved", 1, func(ctx context.Context, t *testing.T, audit Auditor, fn func() error) error {
		approvals := &funcApprovals{fn: fn}
		ap := store.Approval{
			ID: "ap", ActorKind: ActorAutomation, ActorID: "a", Action: string(AutomationExec),
			ExpiresAt: time.Now().Add(time.Minute),
		}
		if err := approvals.Create(context.Background(), ap); err != nil {
			t.Fatal(err)
		}
		return NewWithConfig(audit, approvals, Config{}).Decide(ctx, ActorWeb, "192.0.2.1", ap.ID, true, reauthed)
	}},
}

// TestFailedAuditWriteRefusesTheAction: the action's function is never called
// when the entry that must precede it cannot be written.
func TestFailedAuditWriteRefusesTheAction(t *testing.T) {
	for _, p := range paths {
		t.Run(p.name, func(t *testing.T) {
			audit := &scriptedAudit{failFrom: p.firstWrite, err: errAuditDown}
			called := false
			err := p.do(t.Context(), t, audit, func() error { called = true; return nil })
			if called {
				t.Error("the action ran without an audit entry")
			}
			if !errors.Is(err, errAuditDown) {
				t.Errorf("err = %v, want it to match the audit failure", err)
			}
			if err == nil || !strings.Contains(err.Error(), "nothing was run") {
				t.Errorf("err = %v, want it to say nothing was run", err)
			}
		})
	}
}

// TestCancelledRequestDoesNotRun: a request cancelled before its entry is
// written does not run.
func TestCancelledRequestDoesNotRun(t *testing.T) {
	for _, p := range paths {
		t.Run(p.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			called := false
			err := p.do(ctx, t, &scriptedAudit{}, func() error { called = true; return nil })
			if called {
				t.Error("a cancelled request ran")
			}
			if err == nil {
				t.Error("a cancelled request reported success")
			}
		})
	}
}

// TestCancelledAtApprovalDoesNotRun: a requester that gives up as its approval
// arrives does not run, and the hold still ends in an outcome.
func TestCancelledAtApprovalDoesNotRun(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	audit := &scriptedAudit{}
	approvals := &cancellingApprovals{autoApprovals: autoApprovals{decision: store.ApprovalApproved}, cancel: cancel}
	e := NewWithConfig(audit, approvals, uniform(ModeConfirm))
	e.poll = time.Millisecond
	called := false
	err := e.Do(ctx, Request{ActorKind: ActorAdmin, ActorID: "root", Action: DeviceRevoke},
		func(context.Context) error { called = true; return nil })
	if called {
		t.Error("the action ran after its requester was cancelled")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
	got := audit.all()
	if len(got) != 2 || got[0].Decision != Confirm || got[1].Decision != Deny ||
		!strings.HasPrefix(got[1].Result, "approved, but not run") {
		t.Errorf("audit = %+v, want the hold and then why it did not run", got)
	}
}

// TestOutcomeSurvivesCancellation: a request cancelled while its action runs
// still gets the action's outcome into the audit log.
func TestOutcomeSurvivesCancellation(t *testing.T) {
	for _, p := range paths {
		t.Run(p.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			audit := &scriptedAudit{}
			boom := errors.New("boom")
			err := p.do(ctx, t, audit, func() error { cancel(); return boom })
			if !errors.Is(err, boom) {
				t.Fatalf("err = %v, want the action's error", err)
			}
			got := audit.all()
			if last := got[len(got)-1]; last.Decision != Allow || last.Result != "error: boom" {
				t.Errorf("audit = %+v, want the outcome recorded", got)
			}
		})
	}
}

// TestUnfinishedActionIsNotASuccess: an action that never reports, as when
// the hub crashes while it runs, stays visibly started.
func TestUnfinishedActionIsNotASuccess(t *testing.T) {
	audit := &scriptedAudit{failFrom: 2, err: errAuditDown}
	err := New(audit).Do(t.Context(), Request{ActorKind: ActorAdmin, ActorID: "root", Action: DeviceRevoke},
		func(context.Context) error { return nil })
	if !errors.Is(err, ErrOutcomeNotRecorded) {
		t.Errorf("err = %v, want ErrOutcomeNotRecorded", err)
	}
	if got := audit.all(); len(got) != 1 || got[0].Result != Started {
		t.Errorf("audit = %+v, want one entry still %q", got, Started)
	}
}

// TestOutcomeNotRecordedIsNotUnavailable: an action that ran must not read as
// the retryable "nothing happened" of a cluster without a leader.
func TestOutcomeNotRecordedIsNotUnavailable(t *testing.T) {
	audit := &scriptedAudit{failFrom: 2, err: store.ErrUnavailable}
	err := New(audit).Do(t.Context(), Request{ActorKind: ActorAdmin, ActorID: "root", Action: DeviceRevoke},
		func(context.Context) error { return nil })
	if !errors.Is(err, ErrOutcomeNotRecorded) {
		t.Errorf("err = %v, want ErrOutcomeNotRecorded", err)
	}
	if errors.Is(err, store.ErrUnavailable) {
		t.Errorf("err = %v matches store.ErrUnavailable, but the action ran", err)
	}
}

// TestDecisionThatTookEffectIsASuccess: an approval that committed is not
// reported as failed because its outcome entry could not be written. A retry
// could only be told the approval is closed.
func TestDecisionThatTookEffectIsASuccess(t *testing.T) {
	approvals := &decisionLog{audit: &memAudit{}}
	id := heldApproval(t, approvals)
	audit := &scriptedAudit{failFrom: 2, err: store.ErrUnavailable}
	if err := NewWithConfig(audit, approvals, Config{}).Decide(t.Context(), ActorWeb, "192.0.2.1", id, true, reauthed); err != nil {
		t.Errorf("Decide = %v, want success: the approval took effect", err)
	}
	ap, err := approvals.Get(t.Context(), id)
	if err != nil || ap.Status != store.ApprovalApproved {
		t.Errorf("approval = %+v, %v; want it approved", ap, err)
	}
	if got := audit.all(); len(got) != 1 || got[0].Result != Started {
		t.Errorf("audit = %+v, want the decision still shown as started", got)
	}
}

// TestDecisionThatFailedStaysAFailure: losing the outcome entry does not turn
// a decision that did not take effect into a success.
func TestDecisionThatFailedStaysAFailure(t *testing.T) {
	approvals := &decisionLog{audit: &memAudit{}, decideErr: store.ErrApprovalClosed}
	id := heldApproval(t, approvals)
	audit := &scriptedAudit{failFrom: 2, err: store.ErrUnavailable}
	err := NewWithConfig(audit, approvals, Config{}).Decide(t.Context(), ActorWeb, "192.0.2.1", id, true, reauthed)
	if !errors.Is(err, store.ErrApprovalClosed) || !errors.Is(err, ErrOutcomeNotRecorded) {
		t.Errorf("Decide = %v, want ErrApprovalClosed and ErrOutcomeNotRecorded", err)
	}
}

// TestReservedDetailKeysCannotHideAnEntry: the keys that tie an action's
// entries belong to the engine, whatever a request's Detail says.
func TestReservedDetailKeysCannotHideAnEntry(t *testing.T) {
	for _, key := range []string{store.AuditOpKey, store.AuditOutcomeOfKey} {
		t.Run(key, func(t *testing.T) {
			s, err := store.Open(t.Context(), filepath.Join(t.TempDir(), "hearth.db"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = s.Close() })
			req := Request{
				ActorKind: ActorMCP, ActorID: "claude", Action: DeviceRead, Target: "pi",
				Detail: map[string]any{key: "forged", "query": "pi"},
			}
			if err := New(s.Audit()).Do(t.Context(), req, func(context.Context) error { return nil }); err != nil {
				t.Fatal(err)
			}
			got, err := s.Audit().List(t.Context(), 10)
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != 1 || got[0].Result != ReadAllowed || string(got[0].Detail) != `{"query":"pi"}` {
				t.Fatalf("audit = %+v, want the entry visible without the forged key", got)
			}
		})
	}
}

// TestEntriesAreTiedByOperation: the two entries of an action share one id,
// and two actions do not.
func TestEntriesAreTiedByOperation(t *testing.T) {
	audit := &memAudit{}
	e := New(audit)
	for range 2 {
		if err := e.Do(t.Context(), Request{ActorKind: ActorAdmin, ActorID: "root", Action: DeviceRevoke},
			func(context.Context) error { return nil }); err != nil {
			t.Fatal(err)
		}
	}
	raw := audit.raw()
	if len(raw) != 4 {
		t.Fatalf("wrote %d entries, want 4", len(raw))
	}
	key := func(e store.AuditEntry, k string) string {
		var d map[string]string
		if err := json.Unmarshal(e.Detail, &d); err != nil {
			t.Fatal(err)
		}
		return d[k]
	}
	first, second := key(raw[0], store.AuditOpKey), key(raw[2], store.AuditOpKey)
	if first == "" || first == second {
		t.Errorf("operation ids = %q, %q; want two different ids", first, second)
	}
	if got := key(raw[1], store.AuditOutcomeOfKey); got != first {
		t.Errorf("outcome ties to %q, want %q", got, first)
	}
}

// TestReadWrites pins how many entries a read costs: the audit log's busiest
// actions must not write twice.
func TestReadWrites(t *testing.T) {
	boom := errors.New("boom")
	mcp := Request{ActorKind: ActorMCP, ActorID: "claude", Action: DeviceRead}
	scan := Request{ActorKind: ActorHub, ActorID: "hub", Action: NetworkScan, RecordOutcome: true}
	tests := []struct {
		name       string
		req        Request
		mode       Mode
		fnErr      error
		wantWrites int
		wantResult string
	}{
		{"read that succeeds", mcp, ModeAllow, nil, 1, ReadAllowed},
		{"read that fails", mcp, ModeAllow, boom, 2, "error: boom"},
		{"read that asks for its outcome", scan, ModeAllow, nil, 2, "ok"},
		{"read held for approval", mcp, ModeConfirm, nil, 3, "ok"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			audit := &memAudit{}
			e := NewWithConfig(audit, &autoApprovals{decision: store.ApprovalApproved}, uniform(tt.mode))
			e.poll = time.Millisecond
			called := false
			err := e.Do(t.Context(), tt.req, func(context.Context) error { called = true; return tt.fnErr })
			if !errors.Is(err, tt.fnErr) || !called {
				t.Fatalf("err = %v, called = %v", err, called)
			}
			if got := len(audit.raw()); got != tt.wantWrites {
				t.Errorf("wrote %d entries, want %d", got, tt.wantWrites)
			}
			got := audit.all()
			if last := got[len(got)-1]; last.Result != tt.wantResult {
				t.Errorf("result = %q, want %q", last.Result, tt.wantResult)
			}
		})
	}
}

// TestReadRefusedWithoutAuditEntry: reads follow the same rule as any action.
func TestReadRefusedWithoutAuditEntry(t *testing.T) {
	called := false
	err := New(failingAudit{errAuditDown}).Do(t.Context(), Request{ActorKind: ActorMCP, ActorID: "claude", Action: DeviceRead},
		func(context.Context) error { called = true; return nil })
	if called || !errors.Is(err, errAuditDown) {
		t.Errorf("called = %v, err = %v; want refused", called, err)
	}
}

// TestRefusalKeepsTheCause: the API answers 503 for a cluster without quorum
// by matching store.ErrUnavailable, and the message says what to look at.
func TestRefusalKeepsTheCause(t *testing.T) {
	err := New(failingAudit{store.ErrUnavailable}).Do(t.Context(), Request{ActorKind: ActorAdmin, ActorID: "root", Action: DeviceRevoke},
		func(context.Context) error { t.Error("the action ran"); return nil })
	if !errors.Is(err, store.ErrUnavailable) {
		t.Errorf("err = %v, want it to match store.ErrUnavailable", err)
	}
	if err == nil || !strings.Contains(err.Error(), "most of its hubs are unreachable") {
		t.Errorf("err = %v, want it to explain the cluster's state", err)
	}
}
