// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
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

// A decided approval keeps no plan: the plan can hold secrets from command
// arguments, and a decided approval no longer needs it. The rest of the
// detail stays; a pending approval keeps its plan.
func TestApprovalsDropPlanWhenDecided(t *testing.T) {
	const detail = `{"plan":{"argv":["curl","-H","Authorization: s3cret"]},"device":"pi"}`
	base := time.UnixMilli(1_700_000_000_000).UTC()
	tests := []struct {
		name   string
		status string
		at     time.Time
	}{
		{"approved", ApprovalApproved, base.Add(time.Second)},
		{"denied", ApprovalDenied, base.Add(time.Second)},
		{"expired", ApprovalExpired, base.Add(time.Minute)},
	}
	s := openTest(t)
	ctx := t.Context()
	ap := s.Approvals()
	for _, id := range []string{"pending", "approved", "denied", "expired"} {
		if err := ap.Create(ctx, Approval{
			ID: id, CreatedAt: base, ExpiresAt: base.Add(time.Minute), ActorKind: "automation", ActorID: "x",
			Action: "automation.exec", Class: "dangerous", Detail: []byte(detail),
		}); err != nil {
			t.Fatal(err)
		}
	}
	if got, _ := ap.Get(ctx, "pending"); string(got.Detail) != detail {
		t.Errorf("pending detail = %s, want the full plan", got.Detail)
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ap.Decide(ctx, tt.name, tt.status, "admin/root", tt.at); err != nil {
				t.Fatal(err)
			}
			got, err := ap.Get(ctx, tt.name)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(got.Detail), "s3cret") || strings.Contains(string(got.Detail), `"plan"`) {
				t.Errorf("decided detail = %s, want no plan", got.Detail)
			}
			if !strings.Contains(string(got.Detail), `"device"`) {
				t.Errorf("decided detail = %s, want the rest kept", got.Detail)
			}
			var raw string
			if err := s.db.QueryRowContext(ctx, `SELECT detail FROM approvals WHERE id = ?`, tt.name).Scan(&raw); err != nil ||
				strings.Contains(raw, "s3cret") {
				t.Errorf("stored detail = %q, %v; want no plan", raw, err)
			}
		})
	}
	// A refused decision leaves the plan of the approval it did not close.
	if err := ap.Decide(ctx, "pending", ApprovalApproved, "admin/root", base.Add(time.Hour)); !errors.Is(err, ErrApprovalClosed) {
		t.Fatalf("late approve = %v", err)
	}
	if got, _ := ap.Get(ctx, "pending"); string(got.Detail) != detail {
		t.Errorf("pending detail after a refused decision = %s, want the full plan", got.Detail)
	}
}

// Migration 00017 clears the plan of approvals decided before it, and leaves
// a pending one alone.
func TestApprovalsPlanMigration(t *testing.T) {
	ctx := t.Context()
	path := filepath.Join(t.TempDir(), "hearth.db")
	s, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	p, err := s.newMigrator()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.DownTo(ctx, approvalPlanSchema-1); err != nil {
		t.Fatal(err)
	}
	const detail = `{"plan":{"argv":["x","s3cret"]},"device":"pi"}`
	for id, status := range map[string]string{"p": "pending", "a": "approved", "d": "denied", "e": "expired"} {
		if _, err := s.db.ExecContext(ctx, `INSERT INTO approvals (id, created_at, expires_at, actor_kind, actor_id, action, class, detail, status)
			VALUES (?, 1, 2, 'a', 'b', 'c', 'dangerous', ?, ?)`, id, detail, status); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.migrateTo(ctx, approvalPlanSchema); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"a", "d", "e"} {
		got, err := s.Approvals().Get(ctx, id)
		if err != nil || strings.Contains(string(got.Detail), "s3cret") || !strings.Contains(string(got.Detail), `"device"`) {
			t.Errorf("%s detail = %s, %v; want the plan cleared and the rest kept", id, got.Detail, err)
		}
	}
	if got, _ := s.Approvals().Get(ctx, "p"); string(got.Detail) != detail {
		t.Errorf("pending detail = %s, want it untouched", got.Detail)
	}
}

// The plan of a decided approval does not stay in the -wal file: once a
// checkpoint has copied it and the next write restarts the log, the file is
// truncated (journal_size_limit), while the store is still open.
func TestDecidedPlanLeavesTheWAL(t *testing.T) {
	s := openTest(t)
	ctx := t.Context()
	base := time.Now()
	if err := s.Approvals().Create(ctx, Approval{
		ID: "x", CreatedAt: base, ExpiresAt: base.Add(time.Minute), ActorKind: "a", ActorID: "b",
		Action: "c", Class: "dangerous", Detail: []byte(`{"plan":"MARKERSECRET"}`),
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.Approvals().Decide(ctx, "x", ApprovalDenied, "w/w", base); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(ctx, "PRAGMA wal_checkpoint(PASSIVE)"); err != nil {
		t.Fatal(err)
	}
	if err := s.Approvals().Create(ctx, Approval{
		ID: "y", CreatedAt: base, ExpiresAt: base, ActorKind: "a", ActorID: "b", Action: "c", Class: "dangerous",
	}); err != nil {
		t.Fatal(err)
	}
	wal, err := os.ReadFile(s.path + "-wal")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(wal, []byte("MARKERSECRET")) {
		t.Errorf("the -wal file (%d bytes) still holds the plan of a decided approval", len(wal))
	}
}

func TestApprovalsOverdue(t *testing.T) {
	s := openTest(t)
	ctx := t.Context()
	ap := s.Approvals()
	base := time.UnixMilli(1_700_000_000_000).UTC()
	for id, exp := range map[string]time.Duration{"due": time.Minute, "later": time.Hour, "decided": time.Minute} {
		if err := ap.Create(ctx, Approval{
			ID: id, CreatedAt: base, ExpiresAt: base.Add(exp), ActorKind: "automation", ActorID: "x",
			Action: "automation.exec", Class: "dangerous", Target: "pi",
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := ap.Decide(ctx, "decided", ApprovalDenied, "admin/root", base.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name string
		at   time.Time
		want string
	}{
		{"before any expiry", base.Add(time.Minute - time.Millisecond), ""},
		{"at expiry", base.Add(time.Minute), "due"},
		{"later", base.Add(2 * time.Hour), "due,later"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ap.Overdue(ctx, tt.at, 10)
			if err != nil {
				t.Fatal(err)
			}
			ids := make([]string, 0, len(got))
			for _, a := range got {
				ids = append(ids, a.ID)
			}
			if strings.Join(ids, ",") != tt.want {
				t.Errorf("Overdue = %v, want %q", ids, tt.want)
			}
		})
	}
}
