// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func openTest(t *testing.T) *Store {
	t.Helper()
	s, err := Open(t.Context(), filepath.Join(t.TempDir(), "hearth.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func tableNames(ctx context.Context, t *testing.T, db *sql.DB) []string {
	t.Helper()
	rows, err := db.QueryContext(ctx, `SELECT name FROM sqlite_master
		WHERE type = 'table' AND name NOT LIKE 'sqlite_%' AND name != 'goose_db_version'
		ORDER BY name`)
	if err != nil {
		t.Fatalf("list tables: %v", err)
	}
	defer rows.Close()
	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatalf("scan: %v", err)
		}
		names = append(names, n)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}
	return names
}

func TestMigrationsUpDownUp(t *testing.T) {
	ctx := t.Context()
	s := openTest(t) // Open runs all migrations up.
	want := []string{"admin", "approval_links", "approvals", "audit_log", "automation_runs", "certs", "cluster_hubs", "dashboard_tokens", "devices", "hub_certs", "join_tokens", "kube_clusters", "mcp_tokens", "network_hosts", "panel_links", "panels", "proxmox_servers", "runbook_runs", "sessions", "telemetry", "tokens"}
	if got := tableNames(ctx, t, s.db); !reflect.DeepEqual(got, want) {
		t.Fatalf("after up: tables = %v, want %v", got, want)
	}

	p, err := s.newMigrator()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.DownTo(ctx, 0); err != nil {
		t.Fatalf("down: %v", err)
	}
	if got := tableNames(ctx, t, s.db); len(got) != 0 {
		t.Fatalf("after down: tables = %v, want none", got)
	}

	if _, err := p.Up(ctx); err != nil {
		t.Fatalf("up again: %v", err)
	}
	if got := tableNames(ctx, t, s.db); !reflect.DeepEqual(got, want) {
		t.Fatalf("after up again: tables = %v, want %v", got, want)
	}
}

func TestOpenPragmas(t *testing.T) {
	s := openTest(t)
	tests := []struct {
		pragma string
		want   string
	}{
		{"journal_mode", "wal"},
		{"foreign_keys", "1"},
		{"busy_timeout", "5000"},
		{"secure_delete", "1"},
		{"journal_size_limit", "0"},
	}
	for _, tt := range tests {
		t.Run(tt.pragma, func(t *testing.T) {
			var got string
			if err := s.db.QueryRowContext(t.Context(), "PRAGMA "+tt.pragma).Scan(&got); err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Errorf("PRAGMA %s = %q, want %q", tt.pragma, got, tt.want)
			}
		})
	}
}

func TestOpenReopenKeepsData(t *testing.T) {
	ctx := t.Context()
	path := filepath.Join(t.TempDir(), "hearth.db")
	s, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Tokens().Create(ctx, "secret", nil, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(ctx, path) // migrations are a no-op the second time
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s.Close()
	if _, err := s.Tokens().Consume(ctx, "secret", time.Now()); err != nil {
		t.Fatalf("consume after reopen: %v", err)
	}
}

func TestDevices(t *testing.T) {
	ctx := t.Context()
	s := openTest(t)
	devs := s.Devices()
	t0 := time.UnixMilli(1_700_000_000_000).UTC()
	t1 := t0.Add(time.Minute)

	if _, err := devs.Get(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get(missing) err = %v, want ErrNotFound", err)
	}
	if got, err := devs.List(ctx); err != nil || len(got) != 0 {
		t.Fatalf("List(empty) = %v, %v; want empty", got, err)
	}

	pi := Device{
		ID: "pi", Name: "pi", Hostname: "pi.lan", OS: "linux", Arch: "arm64",
		Facts:     json.RawMessage(`{"cpu_cores":4}`),
		Labels:    map[string]string{"room": "attic"},
		FirstSeen: t0, LastSeen: t0, Status: "online",
	}
	if err := devs.Upsert(ctx, pi); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	got, err := devs.Get(ctx, "pi")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, pi) {
		t.Fatalf("Get = %+v, want %+v", got, pi)
	}

	// Update: everything changes except FirstSeen.
	upd := pi
	upd.Hostname, upd.Status, upd.LastSeen, upd.FirstSeen = "pi2.lan", "offline", t1, t1
	upd.Labels = nil
	upd.Facts = nil
	if err := devs.Upsert(ctx, upd); err != nil {
		t.Fatalf("Upsert(update): %v", err)
	}
	got, err = devs.Get(ctx, "pi")
	if err != nil {
		t.Fatal(err)
	}
	want := upd
	want.FirstSeen = t0
	want.Labels = map[string]string{}
	want.Facts = json.RawMessage(`{}`)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Get after update = %+v, want %+v", got, want)
	}

	if err := devs.Upsert(ctx, Device{ID: "nas", FirstSeen: t0, LastSeen: t0}); err != nil {
		t.Fatal(err)
	}
	list, err := devs.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 || list[0].ID != "nas" || list[1].ID != "pi" {
		t.Fatalf("List = %+v, want [nas pi]", list)
	}

	if err := devs.Upsert(ctx, Device{ID: "bad", Facts: json.RawMessage(`{`)}); err == nil {
		t.Fatal("Upsert with invalid facts JSON: want error")
	}
}

func TestTokensConsume(t *testing.T) {
	now := time.UnixMilli(1_700_000_000_000)
	tests := []struct {
		name    string
		setup   func(ctx context.Context, tok Tokens) error
		secret  string
		want    map[string]string
		wantErr error
	}{
		{
			name: "valid",
			setup: func(ctx context.Context, tok Tokens) error {
				return tok.Create(ctx, "s", map[string]string{"role": "pi"}, now.Add(time.Minute))
			},
			secret: "s",
			want:   map[string]string{"role": "pi"},
		},
		{
			name: "unknown",
			setup: func(ctx context.Context, tok Tokens) error {
				return tok.Create(ctx, "s", nil, now.Add(time.Minute))
			},
			secret:  "other",
			wantErr: ErrNotFound,
		},
		{
			name: "expired",
			setup: func(ctx context.Context, tok Tokens) error {
				return tok.Create(ctx, "s", nil, now.Add(-time.Second))
			},
			secret:  "s",
			wantErr: ErrTokenExpired,
		},
		{
			name: "expires exactly now",
			setup: func(ctx context.Context, tok Tokens) error {
				return tok.Create(ctx, "s", nil, now)
			},
			secret:  "s",
			wantErr: ErrTokenExpired,
		},
		{
			name: "reused",
			setup: func(ctx context.Context, tok Tokens) error {
				if err := tok.Create(ctx, "s", nil, now.Add(time.Minute)); err != nil {
					return err
				}
				_, err := tok.Consume(ctx, "s", now)
				return err
			},
			secret:  "s",
			wantErr: ErrTokenUsed,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := t.Context()
			tok := openTest(t).Tokens()
			if err := tt.setup(ctx, tok); err != nil {
				t.Fatalf("setup: %v", err)
			}
			got, err := tok.Consume(ctx, tt.secret, now)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Consume err = %v, want %v", err, tt.wantErr)
			}
			if tt.wantErr == nil && !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("Consume labels = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTokensCreate(t *testing.T) {
	ctx := t.Context()
	s := openTest(t)
	tok := s.Tokens()
	exp := time.Now().Add(time.Hour)

	if err := tok.Create(ctx, "", nil, exp); err == nil {
		t.Error("Create with empty secret: want error")
	}
	if err := tok.Create(ctx, "dup", nil, exp); err != nil {
		t.Fatal(err)
	}
	if err := tok.Create(ctx, "dup", nil, exp); err == nil {
		t.Error("Create duplicate secret: want error")
	}

	// The secret itself is never stored.
	var hash []byte
	if err := s.db.QueryRowContext(ctx, `SELECT hash FROM tokens`).Scan(&hash); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(hash), "dup") || len(hash) != 32 {
		t.Errorf("stored hash = %x, want a 32-byte SHA-256 digest", hash)
	}
}

func TestTokensConsumeConcurrent(t *testing.T) {
	ctx := t.Context()
	tok := openTest(t).Tokens()
	now := time.Now()
	if err := tok.Create(ctx, "once", nil, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}

	const n = 20
	var (
		wg      sync.WaitGroup
		start   = make(chan struct{})
		errs    = make(chan error, n)
		success = make(chan struct{}, n)
	)
	for range n {
		wg.Go(func() {
			<-start
			if _, err := tok.Consume(ctx, "once", now); err != nil {
				errs <- err
				return
			}
			success <- struct{}{}
		})
	}
	close(start)
	wg.Wait()
	close(errs)
	close(success)

	if got := len(success); got != 1 {
		t.Fatalf("successful consumes = %d, want exactly 1", got)
	}
	for err := range errs {
		if !errors.Is(err, ErrTokenUsed) {
			t.Errorf("losing Consume err = %v, want ErrTokenUsed", err)
		}
	}
}

func TestAudit(t *testing.T) {
	ctx := t.Context()
	s := openTest(t)
	audit := s.Audit()
	ts := time.UnixMilli(1_700_000_000_000).UTC()

	first := AuditEntry{
		TS: ts, ActorKind: "user", ActorID: "admin", Action: "token.create",
		Decision: "allow", Result: "ok", Detail: json.RawMessage(`{"ttl":"15m"}`),
	}
	id1, err := audit.Append(ctx, first)
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	id2, err := audit.Append(ctx, AuditEntry{
		ActorKind: "agent", ActorID: "pi", Action: "enroll", Target: "pi", Decision: "deny",
	})
	if err != nil {
		t.Fatalf("Append: %v", err)
	}

	got, err := audit.List(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].ID != id2 || got[1].ID != id1 {
		t.Fatalf("List = %+v, want ids [%d %d]", got, id2, id1)
	}
	first.ID = id1
	if !reflect.DeepEqual(got[1], first) {
		t.Errorf("List[1] = %+v, want %+v", got[1], first)
	}
	if got[0].TS.IsZero() || string(got[0].Detail) != "{}" {
		t.Errorf("defaults: TS = %v, Detail = %s; want now and {}", got[0].TS, got[0].Detail)
	}
	if got, err := audit.List(ctx, 1); err != nil || len(got) != 1 || got[0].ID != id2 {
		t.Errorf("List(1) = %+v, %v; want newest only", got, err)
	}
}

func TestAuditRejects(t *testing.T) {
	ok := AuditEntry{ActorKind: "user", ActorID: "admin", Action: "x", Decision: "allow"}
	tests := []struct {
		name   string
		mutate func(*AuditEntry)
	}{
		{"missing actor kind", func(e *AuditEntry) { e.ActorKind = "" }},
		{"missing actor id", func(e *AuditEntry) { e.ActorID = "" }},
		{"missing action", func(e *AuditEntry) { e.Action = "" }},
		{"missing decision", func(e *AuditEntry) { e.Decision = "" }},
		{"invalid detail", func(e *AuditEntry) { e.Detail = json.RawMessage(`nope`) }},
	}
	audit := openTest(t).Audit()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := ok
			tt.mutate(&e)
			if _, err := audit.Append(t.Context(), e); err == nil {
				t.Fatal("Append: want error")
			}
		})
	}
	if _, err := audit.List(t.Context(), 0); err == nil {
		t.Error("List(0): want error")
	}
}

func TestAuditAppendOnly(t *testing.T) {
	ctx := t.Context()
	s := openTest(t)
	if _, err := s.Audit().Append(ctx, AuditEntry{
		ActorKind: "user", ActorID: "admin", Action: "x", Decision: "allow",
	}); err != nil {
		t.Fatal(err)
	}
	for _, stmt := range []string{
		`UPDATE audit_log SET decision = 'deny'`,
		`DELETE FROM audit_log`,
	} {
		if _, err := s.db.ExecContext(ctx, stmt); err == nil || !strings.Contains(err.Error(), "append-only") {
			t.Errorf("%s: err = %v, want append-only rejection", stmt, err)
		}
	}
}
