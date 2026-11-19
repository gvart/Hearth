// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"testing"
)

// auditNoReplaceSchemaForTest is the schema version whose migration (00019)
// added the guard against a REPLACE of an audit row.
const auditNoReplaceSchemaForTest = 19

func auditTriggers(ctx context.Context, t *testing.T, s *Store) map[string]bool {
	t.Helper()
	rows, err := s.db.QueryContext(ctx, `SELECT name FROM sqlite_master WHERE type = 'trigger' AND tbl_name = 'audit_log'`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	got := map[string]bool{}
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatal(err)
		}
		got[n] = true
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return got
}

// TestAuditRefusesReplace: INSERT OR REPLACE and REPLACE INTO on an existing
// audit id are refused and leave the row alone; appends, updates and deletes
// behave as before.
func TestAuditRefusesReplace(t *testing.T) {
	ctx := t.Context()
	s := openTest(t)
	id, err := s.Audit().Append(ctx, AuditEntry{ActorKind: "admin", ActorID: "root", Action: "x", Decision: "allow"})
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`INSERT OR REPLACE INTO audit_log (id, ts, actor_kind, actor_id, action, decision) VALUES (?, 9, 'evil', 'evil', 'forged', 'allow')`,
		`REPLACE INTO audit_log (id, ts, actor_kind, actor_id, action, decision) VALUES (?, 9, 'evil', 'evil', 'forged', 'allow')`,
		`INSERT INTO audit_log (id, ts, actor_kind, actor_id, action, decision) VALUES (?, 9, 'evil', 'evil', 'forged', 'allow') ON CONFLICT (id) DO UPDATE SET action = 'forged'`,
	} {
		if _, err := s.db.ExecContext(ctx, q, id); err == nil {
			t.Errorf("%.30q on an existing id succeeded", q)
		}
	}
	var actor, action string
	if err := s.db.QueryRowContext(ctx, `SELECT actor_kind, action FROM audit_log WHERE id = ?`, id).Scan(&actor, &action); err != nil {
		t.Fatal(err)
	}
	if actor != "admin" || action != "x" {
		t.Errorf("row = %q, %q after a refused replace; want admin, x", actor, action)
	}

	// REPLACE with a fresh id is a plain insert and still works.
	if _, err := s.db.ExecContext(ctx, `INSERT OR REPLACE INTO audit_log (id, ts, actor_kind, actor_id, action, decision) VALUES (?, 1, 'a', 'b', 'c', 'allow')`, id+100); err != nil {
		t.Errorf("replace of a new id: %v", err)
	}
	if _, err := s.Audit().Append(ctx, AuditEntry{ActorKind: "admin", ActorID: "root", Action: "y", Decision: "allow"}); err != nil {
		t.Errorf("append after the guard: %v", err)
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE audit_log SET result = 'x'`); err == nil {
		t.Error("audit_log accepts an UPDATE")
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM audit_log`); err == nil {
		t.Error("audit_log accepts a DELETE")
	}
}

// TestAuditNoReplaceDown: the down migration removes only the replace guard
// and appends still work without it.
func TestAuditNoReplaceDown(t *testing.T) {
	ctx := t.Context()
	s := openTest(t)
	if !auditTriggers(ctx, t, s)["audit_log_no_replace"] {
		t.Fatal("audit_log_no_replace missing")
	}
	p, err := s.newMigrator()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.DownTo(ctx, auditNoReplaceSchemaForTest-1); err != nil {
		t.Fatal(err)
	}
	got := auditTriggers(ctx, t, s)
	if got["audit_log_no_replace"] || !got["audit_log_no_update"] || !got["audit_log_no_delete"] || len(got) != 2 {
		t.Errorf("triggers after down = %v; want only no_update and no_delete", got)
	}
	if _, err := s.Audit().Append(ctx, AuditEntry{ActorKind: "admin", ActorID: "root", Action: "x", Decision: "allow"}); err != nil {
		t.Errorf("append after down: %v", err)
	}
}
