// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"context"
	"io"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

type fakeLeaderNode struct{ leader atomic.Bool }

func (n *fakeLeaderNode) IsLeader() bool                  { return n.leader.Load() }
func (n *fakeLeaderNode) WaitReady(context.Context) error { return nil }

func sweepFixture(t *testing.T) (*store.Store, *policy.Engine) {
	t.Helper()
	s := newTestStore(t)
	t.Cleanup(func() { _ = s.Close() })
	created := time.Now().Add(-time.Hour)
	if err := s.Approvals().Create(t.Context(), store.Approval{
		ID: "due", CreatedAt: created, ExpiresAt: created.Add(time.Minute), ActorKind: policy.ActorAutomation,
		ActorID: "a", Action: string(policy.AutomationExec), Class: string(policy.Dangerous), Target: "pi",
		Detail: []byte(`{"plan":{"argv":["x","s3cret"]}}`),
	}); err != nil {
		t.Fatal(err)
	}
	return s, policy.NewWithConfig(s.Audit(), s.Approvals(), policy.Config{})
}

func waitStatus(t *testing.T, s *store.Store, id, want string, d time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if ap, err := s.Approvals().Get(t.Context(), id); err == nil && ap.Status == want {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return false
}

// A follower never proposes the sweep; the hub that becomes leader does it
// at once.
func TestApprovalSweepFollowsLeadership(t *testing.T) {
	s, pol := sweepFixture(t)
	node := &fakeLeaderNode{}
	changed := make(chan struct{}, 1)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		done <- RunApprovalSweep(ctx, pol, node, changed, slog.New(slog.NewTextHandler(io.Discard, nil)))
	}()

	if waitStatus(t, s, "due", store.ApprovalExpired, 300*time.Millisecond) {
		t.Fatal("a follower expired an approval")
	}
	ap, err := s.Approvals().Get(t.Context(), "due")
	if err != nil || ap.Status != store.ApprovalPending {
		t.Fatalf("approval = %+v, %v; want pending", ap, err)
	}

	node.leader.Store(true)
	changed <- struct{}{}
	if !waitStatus(t, s, "due", store.ApprovalExpired, 5*time.Second) {
		t.Fatal("the new leader did not expire the overdue approval")
	}
	cancel()
	if err := <-done; err != nil {
		t.Errorf("RunApprovalSweep = %v, want nil", err)
	}
}

// A single node has no leadership to wait for.
func TestApprovalSweepSingleNode(t *testing.T) {
	s, pol := sweepFixture(t)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- RunApprovalSweep(ctx, pol, nil, nil, slog.New(slog.NewTextHandler(io.Discard, nil))) }()
	if !waitStatus(t, s, "due", store.ApprovalExpired, 5*time.Second) {
		t.Error("the single node did not expire the overdue approval")
	}
	cancel()
	if err := <-done; err != nil {
		t.Errorf("RunApprovalSweep = %v, want nil", err)
	}
}
