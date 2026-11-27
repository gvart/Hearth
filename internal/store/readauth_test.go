// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"errors"
	"testing"
	"time"
)

// TestReadLocalUnproven: a read from a member that did not prove the hub CA
// key reads the replicated tables but the master tables, and nothing else:
// not a session however the query names the table, not the raw pages of the
// database (sqlite_dbpage, dbstat), not a pragma. Each refused query reads
// fine on the connection a master's read gets.
func TestReadLocalUnproven(t *testing.T) {
	ctx := t.Context()
	s := openTestWith(t, WithDigest())
	now := time.Now()
	if err := s.Admin().CreateSession(ctx, "secret", now, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := s.Devices().Upsert(ctx, Device{ID: "pi", Hostname: "pi", LastSeen: now}); err != nil {
		t.Fatal(err)
	}
	refused := []string{
		`SELECT hash FROM sessions`,
		`SeLeCt hash FROM "SESSIONS"`,
		`SELECT name FROM mcp_tokens`,
		`SELECT id FROM devices WHERE id IN (SELECT hash FROM sessions)`,
		`WITH x AS (SELECT * FROM panel_links) SELECT count(*) FROM x`,
		`SELECT count(*) FROM sqlite_dbpage`,
		`SELECT count(*) FROM dbstat`,
		`SELECT name FROM sqlite_schema`,
		`SELECT name FROM pragma_table_info('sessions')`,
		`PRAGMA table_info(sessions)`,
	}
	for _, q := range refused {
		// The query reads on an unrestricted connection: the authorizer,
		// not a missing table, refuses it.
		if _, err := s.ReadLocal(ctx, q, nil); err != nil {
			t.Fatalf("%s on a master's connection: %v", q, err)
		}
		if rows, err := s.ReadLocalUnproven(ctx, q, nil); !errors.Is(err, ErrReadRefused) {
			t.Errorf("%s: %v, %v; want refused", q, rows.Vals, err)
		}
	}
	allowed := map[string]int{
		`SELECT id FROM devices`:               1,
		`SELECT value FROM json_each('[1,2]')`: 2,
		`WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 3) SELECT i FROM n`: 3,
	}
	for q, want := range allowed {
		rows, err := s.ReadLocalUnproven(ctx, q, nil)
		if err != nil || len(rows.Vals) != want {
			t.Errorf("%s: %d rows, %v; want %d", q, len(rows.Vals), err, want)
		}
	}
	// The pool's connections hold no policy after it.
	for range 4 {
		if rows, err := s.ReadLocal(ctx, `SELECT hash FROM sessions`, nil); err != nil || len(rows.Vals) != 1 {
			t.Fatalf("a master's read after the refusals: %v, %v", rows.Vals, err)
		}
	}
}
