// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func auditRows(ctx context.Context, t *testing.T, s *Store, action string) int {
	t.Helper()
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM audit_log WHERE action = ?`, action).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// TestAuditKeyLandsOnce: an entry appended again with the same key, as a
// retry does, adds nothing and keeps the first write's timestamp; entries
// without a key, or with another, are appended as before.
func TestAuditKeyLandsOnce(t *testing.T) {
	ctx := t.Context()
	s := openTest(t)
	ts := time.UnixMilli(1_700_000_000_000)
	e := AuditEntry{TS: ts, ActorKind: "admin", ActorID: "root", Action: "x", Decision: "allow", Result: "ok", Key: "k1"}
	first, err := s.Audit().Append(ctx, e)
	if err != nil {
		t.Fatal(err)
	}
	again := e
	again.TS = ts.Add(time.Hour)
	second, err := s.Audit().Append(ctx, again)
	if err != nil {
		t.Fatal(err)
	}
	if second != first {
		t.Errorf("second append = id %d, want the first's %d", second, first)
	}
	other := e
	other.Key = "k2"
	if _, err := s.Audit().Append(ctx, other); err != nil {
		t.Fatal(err)
	}
	unkeyed := e
	unkeyed.Key = ""
	for range 2 {
		if _, err := s.Audit().Append(ctx, unkeyed); err != nil {
			t.Fatal(err)
		}
	}
	if n := auditRows(ctx, t, s, "x"); n != 4 {
		t.Errorf("%d rows, want 4 (k1 once, k2, two without a key)", n)
	}
	var got int64
	if err := s.db.QueryRowContext(ctx, `SELECT ts FROM audit_log WHERE audit_key = 'k1'`).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != ts.UnixMilli() {
		t.Errorf("ts = %d, want the first write's %d", got, ts.UnixMilli())
	}
	triggers := auditTriggers(ctx, t, s)
	for _, name := range []string{"audit_log_no_update", "audit_log_no_delete", "audit_log_no_replace"} {
		if !triggers[name] {
			t.Errorf("trigger %s missing after the key migration (have %v)", name, triggers)
		}
	}
}

// TestAuditKeyBeforeTheSchema: a cluster still before the key's schema never
// sees the keyed command, which its older hubs could not apply; the entry is
// appended without its key.
func TestAuditKeyBeforeTheSchema(t *testing.T) {
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
	if _, err := p.DownTo(ctx, auditKeySchema-1); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()

	var proposed []string
	s, err = Open(ctx, path, WithoutUpgrade(), WithApplier(func(s *Store) Applier {
		return ApplierFunc(func(ctx context.Context, cmd Command) (Result, error) {
			proposed = append(proposed, cmd.Op())
			return s.ApplyLocal(ctx, cmd)
		})
	}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	e := AuditEntry{ActorKind: "admin", ActorID: "root", Action: "x", Decision: "allow", Key: "k1"}
	if _, err := s.Audit().Append(ctx, e); err != nil {
		t.Fatal(err)
	}
	if len(proposed) != 1 || proposed[0] != (AppendAudit{}).Op() {
		t.Errorf("proposed %v, want only %s", proposed, AppendAudit{}.Op())
	}
	once := AppendAuditOnce{
		AppendAudit: AppendAudit{ActorKind: "a", ActorID: "b", Action: "x", Decision: "allow", Detail: "{}"},
		Key:         "k",
	}
	if _, err := s.ApplyLocal(ctx, once); !errors.Is(err, ErrSchemaTooOld) || !IsDomainError(err) {
		t.Errorf("keyed command before the schema = %v, want a domain ErrSchemaTooOld", err)
	}
}
