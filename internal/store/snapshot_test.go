// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"bytes"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func gooseVersion(t *testing.T, db *sql.DB) int64 {
	t.Helper()
	var v int64
	if err := db.QueryRowContext(t.Context(),
		`SELECT MAX(version_id) FROM goose_db_version WHERE is_applied`).Scan(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestSnapshotRestoreRoundTrip(t *testing.T) {
	ctx := t.Context()
	src := openTest(t)
	runScenario(t, src)

	var snap bytes.Buffer
	if err := src.Snapshot(ctx, &snap); err != nil {
		t.Fatalf("Snapshot: %v", err)
	}

	// The target has rows of its own that the restore must replace.
	dst := openTest(t)
	now := time.Now()
	if err := dst.Devices().Upsert(ctx, Device{ID: "stale", FirstSeen: now, LastSeen: now}); err != nil {
		t.Fatal(err)
	}
	if _, err := dst.Audit().Append(ctx, AuditEntry{ActorKind: "a", ActorID: "b", Action: "c", Decision: "d"}); err != nil {
		t.Fatal(err)
	}
	if err := dst.Restore(ctx, &snap); err != nil {
		t.Fatalf("Restore: %v", err)
	}

	if got, want := dumpTables(t, dst.db), dumpTables(t, src.db); !reflect.DeepEqual(got, want) {
		t.Fatalf("restored tables differ\n got: %v\nwant: %v", got, want)
	}
	if got, want := gooseVersion(t, dst.db), gooseVersion(t, src.db); got != want || got == 0 {
		t.Fatalf("goose version = %d, want %d", got, want)
	}
	if got, want := tableNames(ctx, t, dst.db), tableNames(ctx, t, src.db); !reflect.DeepEqual(got, want) {
		t.Fatalf("tables = %v, want %v", got, want)
	}

	// The restored store keeps working: WAL mode, writes, and the audit
	// log's append-only triggers.
	var mode string
	if err := dst.db.QueryRowContext(ctx, `PRAGMA journal_mode`).Scan(&mode); err != nil || mode != "wal" {
		t.Fatalf("journal_mode = %q, %v; want wal", mode, err)
	}
	if _, _, err := dst.Devices().MarkSeen(ctx, "pi", now); err != nil {
		t.Fatalf("MarkSeen after restore: %v", err)
	}
	if _, err := dst.Devices().Get(ctx, "stale"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("stale device after restore: err = %v, want ErrNotFound", err)
	}
	if _, err := dst.db.ExecContext(ctx, `DELETE FROM audit_log`); err == nil {
		t.Fatal("audit_log delete succeeded after restore; triggers lost")
	}

	// No staging files are left in the data dir.
	entries, err := os.ReadDir(filepath.Dir(dst.path))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".snapshot-") {
			t.Fatalf("leftover staging dir %s", e.Name())
		}
	}
}

func TestRestoreRejectsBadSnapshot(t *testing.T) {
	ctx := t.Context()
	var valid bytes.Buffer
	if err := openTest(t).Snapshot(ctx, &valid); err != nil {
		t.Fatal(err)
	}
	tests := map[string][]byte{
		"empty":     nil,
		"garbage":   []byte("definitely not a database"),
		"truncated": valid.Bytes()[:valid.Len()/2],
	}
	for name, snap := range tests {
		t.Run(name, func(t *testing.T) {
			s := openTest(t)
			now := time.Now()
			if err := s.Devices().Upsert(ctx, Device{ID: "pi", FirstSeen: now, LastSeen: now}); err != nil {
				t.Fatal(err)
			}
			if err := s.Restore(ctx, bytes.NewReader(snap)); err == nil {
				t.Fatal("Restore accepted a bad snapshot")
			}
			if _, err := s.Devices().Get(ctx, "pi"); err != nil {
				t.Fatalf("data lost after a rejected restore: %v", err)
			}
		})
	}
}
