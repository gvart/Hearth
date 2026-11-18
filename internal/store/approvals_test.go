// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestApprovalsLifecycle(t *testing.T) {
	s := openTest(t)
	ctx := t.Context()
	ap := s.Approvals()
	base := time.UnixMilli(1_700_000_000_000).UTC()
	for _, id := range []string{"a", "b", "c", "d"} {
		if err := ap.Create(ctx, Approval{
			ID: id, CreatedAt: base, ExpiresAt: base.Add(time.Minute), ActorKind: "automation", ActorID: "x",
			Action: "automation.exec", Class: "dangerous", Target: "pi",
		}); err != nil {
			t.Fatal(err)
		}
	}
	got, err := ap.Get(ctx, "a")
	if err != nil || got.Status != ApprovalPending || string(got.Detail) != "{}" || !got.ExpiresAt.Equal(base.Add(time.Minute)) {
		t.Fatalf("Get(a) = %+v, %v", got, err)
	}

	tests := []struct {
		name    string
		id      string
		status  string
		at      time.Time
		wantErr error
	}{
		{"approve", "a", ApprovalApproved, base.Add(time.Second), nil},
		{"approve again", "a", ApprovalApproved, base.Add(time.Second), ErrApprovalClosed},
		{"deny after approve", "a", ApprovalDenied, base.Add(time.Second), ErrApprovalClosed},
		{"deny", "b", ApprovalDenied, base.Add(time.Second), nil},
		{"approve after expiry", "c", ApprovalApproved, base.Add(time.Minute), ErrApprovalClosed},
		{"expire", "c", ApprovalExpired, base.Add(time.Minute), nil},
		{"approve expired", "c", ApprovalApproved, base.Add(time.Second), ErrApprovalClosed},
		{"unknown", "zzz", ApprovalApproved, base, ErrNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ap.Decide(ctx, tt.id, tt.status, "admin/root", tt.at)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Decide = %v, want %v", err, tt.wantErr)
			}
			if err != nil && !IsDomainError(err) {
				t.Errorf("%v is not a domain error", err)
			}
		})
	}
	if err := ap.Decide(ctx, "d", "maybe", "admin/root", base); err == nil {
		t.Error("Decide with an invalid status succeeded")
	}
	if err := ap.Decide(ctx, "d", ApprovalApproved, "", base); err == nil {
		t.Error("Decide without a decider succeeded")
	}

	a, _ := ap.Get(ctx, "a")
	if a.Status != ApprovalApproved || a.DecidedBy != "admin/root" || !a.DecidedAt.Equal(base.Add(time.Second)) {
		t.Errorf("a = %+v", a)
	}
	pending, err := ap.List(ctx, ApprovalPending, 10)
	if err != nil || len(pending) != 1 || pending[0].ID != "d" {
		t.Errorf("List(pending) = %+v, %v", pending, err)
	}
	all, err := ap.List(ctx, "", 10)
	if err != nil || len(all) != 4 {
		t.Errorf("List(all) = %d, %v", len(all), err)
	}
	if err := ap.Create(ctx, Approval{ID: "e"}); err == nil {
		t.Error("Create without actor, action and class succeeded")
	}
}

// A newer binary on a cluster database before schema 9 holds nothing for
// approval: creating one is refused the same way on every node.
func TestApprovalsBeforeTheirSchema(t *testing.T) {
	ctx := t.Context()
	path := filepath.Join(t.TempDir(), "hearth.db")
	s, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	p, err := s.newMigrator()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.DownTo(ctx, approvalsSchema-1); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	s, err = Open(ctx, path, WithoutUpgrade())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })

	if got, err := s.Approvals().List(ctx, "", 10); err != nil || len(got) != 0 {
		t.Errorf("List before the schema = %v, %v; want none", got, err)
	}
	if _, err := s.Approvals().Get(ctx, "a"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Get before the schema = %v, want ErrNotFound", err)
	}
	now := time.Now()
	err = s.Approvals().Create(ctx, Approval{
		ID: "a", CreatedAt: now, ExpiresAt: now.Add(time.Minute), ActorKind: "admin", ActorID: "root",
		Action: "device.revoke", Class: "dangerous",
	})
	if !errors.Is(err, ErrSchemaTooOld) || !IsDomainError(err) {
		t.Errorf("Create before the schema = %v, want a domain ErrSchemaTooOld", err)
	}
}
