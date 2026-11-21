// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"bytes"
	"database/sql"
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

// writeSnapshot writes a Snapshot of s to a new file and returns its path.
func writeSnapshot(t *testing.T, s *Store) string {
	t.Helper()
	var snap bytes.Buffer
	if err := s.Snapshot(t.Context(), &snap); err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	path := filepath.Join(t.TempDir(), "snapshot.db")
	if err := os.WriteFile(path, snap.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestSnapshotRoundTrip(t *testing.T) {
	ctx := t.Context()
	src := openTest(t)
	runScenario(t, src)
	path := writeSnapshot(t, src)
	if err := CheckSnapshotFile(ctx, path); err != nil {
		t.Fatalf("CheckSnapshotFile: %v", err)
	}
	dst, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("open the snapshot: %v", err)
	}
	t.Cleanup(func() { _ = dst.Close() })

	if got, want := dumpTables(t, dst.db), dumpTables(t, src.db); !reflect.DeepEqual(got, want) {
		t.Fatalf("snapshot tables differ\n got: %v\nwant: %v", got, want)
	}
	if got, want := gooseVersion(t, dst.db), gooseVersion(t, src.db); got != want || got == 0 {
		t.Fatalf("goose version = %d, want %d", got, want)
	}
	if got, want := tableNames(ctx, t, dst.db), tableNames(ctx, t, src.db); !reflect.DeepEqual(got, want) {
		t.Fatalf("tables = %v, want %v", got, want)
	}
	// The copy keeps working: writes, and the audit log's append-only
	// triggers.
	if _, _, err := dst.Devices().MarkSeen(ctx, "pi", time.Now()); err != nil {
		t.Fatalf("MarkSeen on the copy: %v", err)
	}
	if _, err := dst.db.ExecContext(ctx, `DELETE FROM audit_log`); err == nil {
		t.Fatal("audit_log delete succeeded on the copy; triggers lost")
	}

	// No staging files are left in the source's data dir.
	entries, err := os.ReadDir(filepath.Dir(src.path))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".snapshot-") {
			t.Fatalf("leftover staging dir %s", e.Name())
		}
	}
}

func TestCheckSnapshotFileRejectsBadSnapshot(t *testing.T) {
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
			path := filepath.Join(t.TempDir(), "snapshot.db")
			if err := os.WriteFile(path, snap, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := CheckSnapshotFile(ctx, path); err == nil {
				t.Fatal("CheckSnapshotFile accepted a bad snapshot")
			}
		})
	}
}
