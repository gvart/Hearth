// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// nextSchema is the version of testMigration: one past this binary's.
var nextSchema = SchemaVersion() + 1

// testMigration stands in for a newer release's migration. Its trigger makes
// an existing command (UpsertDevice) write the new table once it exists.
const testMigration = `
CREATE TABLE rolling_test (device_id TEXT PRIMARY KEY) STRICT;
CREATE TRIGGER rolling_test_insert AFTER INSERT ON devices
BEGIN
	INSERT INTO rolling_test (device_id) VALUES (NEW.id);
END;`

// openNewerBinary returns a store whose binary supports nextSchema, opened
// without upgrade on a database at SchemaVersion: a newer binary running at
// the older schema until it migrates (migrateTo).
func openNewerBinary(t *testing.T) *Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "hearth.db")
	s, err := Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	s, err = Open(t.Context(), path, WithoutUpgrade(), WithExtraMigration(nextSchema, testMigration))
	if err != nil {
		t.Fatalf("newer binary on an older database: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestSchemaVersionIsNewestMigration(t *testing.T) {
	s := openTest(t)
	if got, want := gooseVersion(t, s.db), SchemaVersion(); got != want || want < 4 {
		t.Fatalf("database at %d, SchemaVersion() = %d", got, want)
	}
	v, err := s.SchemaVersion(t.Context())
	if err != nil || v != SchemaVersion() || s.MaxSchemaVersion() != SchemaVersion() {
		t.Fatalf("Store.SchemaVersion = %d, %v; MaxSchemaVersion = %d", v, err, s.MaxSchemaVersion())
	}
}

func TestWithoutUpgrade(t *testing.T) {
	ctx := t.Context()

	// A new database is initialized.
	path := filepath.Join(t.TempDir(), "hearth.db")
	s, err := Open(ctx, path, WithoutUpgrade())
	if err != nil {
		t.Fatalf("Open new: %v", err)
	}
	if v := gooseVersion(t, s.db); v != SchemaVersion() {
		t.Fatalf("new database at %d", v)
	}
	// One at the binary's version opens.
	_ = s.Close()
	s, err = Open(ctx, path, WithoutUpgrade())
	if err != nil {
		t.Fatalf("Open current: %v", err)
	}

	// One behind opens and stays behind: the binary supports it, and the
	// hub whose database it is migrates it.
	p, err := s.newMigrator()
	if err != nil {
		t.Fatal(err)
	}
	// The migration before the newest: numbers may skip one reserved for a
	// change not merged yet.
	behind := previousSchema(t)
	if _, err := p.DownTo(ctx, behind); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	s, err = Open(ctx, path, WithoutUpgrade())
	if err != nil {
		t.Fatalf("Open behind: %v", err)
	}
	if v := gooseVersion(t, s.db); v != behind {
		t.Fatalf("Open behind migrated the database to %d", v)
	}
	_ = s.Close()

	// A hub (no option) migrates on open.
	s, err = Open(ctx, path)
	if err != nil {
		t.Fatalf("Open with upgrade: %v", err)
	}
	if v := gooseVersion(t, s.db); v != SchemaVersion() {
		t.Fatalf("upgraded database at %d", v)
	}
	_ = s.Close()

	// A database a newer binary migrated is refused by this older one.
	s, err = Open(ctx, path, WithExtraMigration(nextSchema, testMigration))
	if err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	_, err = Open(ctx, path, WithoutUpgrade())
	if !errors.Is(err, ErrSchemaMismatch) {
		t.Fatalf("older binary on a newer database: err = %v, want ErrSchemaMismatch", err)
	}
	t.Logf("refusal: %v", err)
}

// A snapshot of an older schema is accepted and opens in a newer binary, which
// migrates it; one of a newer schema is refused by an older binary.
func TestSnapshotAcrossSchemas(t *testing.T) {
	ctx := t.Context()
	older := openTest(t)
	if err := older.Devices().Upsert(ctx, Device{ID: "pi", FirstSeen: time.Now(), LastSeen: time.Now()}); err != nil {
		t.Fatal(err)
	}
	path := writeSnapshot(t, older)
	if err := CheckSnapshotFile(ctx, path); err != nil {
		t.Fatalf("check an older snapshot: %v", err)
	}
	newer, err := Open(ctx, path, WithExtraMigration(nextSchema, testMigration))
	if err != nil {
		t.Fatalf("open an older snapshot: %v", err)
	}
	t.Cleanup(func() { _ = newer.Close() })
	if v := gooseVersion(t, newer.db); v != nextSchema {
		t.Fatalf("opened at %d, want %d", v, nextSchema)
	}
	if _, err := newer.Devices().Get(ctx, "pi"); err != nil {
		t.Fatalf("snapshot data: %v", err)
	}
	if err := CheckSnapshotFile(ctx, writeSnapshot(t, newer)); !errors.Is(err, ErrSchemaMismatch) {
		t.Fatalf("check a newer snapshot: err = %v, want ErrSchemaMismatch", err)
	}
}

// migrateTo runs s's migrations up to schema to, as the newer binary that
// opens s migrates it.
func (s *Store) migrateTo(ctx context.Context, to int64) error {
	p, err := s.newMigrator()
	if err != nil {
		return err
	}
	defer s.columns.Clear()
	_, err = p.UpTo(ctx, to)
	return err
}

// gatedInsert is a command of a newer release: it writes testMigration's table.
type gatedInsert struct{ ID string }

func (gatedInsert) Op() string       { return "gated_insert" }
func (gatedInsert) minSchema() int64 { return nextSchema }
func (c gatedInsert) apply(ctx context.Context, w *writer) (Result, error) {
	_, err := w.tx.ExecContext(ctx, `INSERT INTO rolling_test (device_id) VALUES (?)`, c.ID)
	return Result{}, err
}

func TestSchemaGatedCommand(t *testing.T) {
	ctx := t.Context()
	s := openNewerBinary(t)
	_, err := s.ApplyLocal(ctx, gatedInsert{ID: "pi"})
	if !errors.Is(err, ErrSchemaTooOld) || !IsDomainError(err) {
		t.Fatalf("before the migrate: err = %v, want domain error ErrSchemaTooOld", err)
	}
	if err := s.migrateTo(ctx, nextSchema); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ApplyLocal(ctx, gatedInsert{ID: "pi"}); err != nil {
		t.Fatalf("after the migrate: %v", err)
	}
	// Commands without a gate never read the schema version.
	if _, err := s.ApplyLocal(ctx, MarkSeen{ID: "ghost", Now: 1}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("ungated command: err = %v", err)
	}
}

func TestIsDomainError(t *testing.T) {
	s := openTest(t)
	ctx := t.Context()
	now := time.Now()
	// Constraint violations are deterministic: every node rejects them alike.
	if err := s.Certs().Create(ctx, "0a", "ghost"); err == nil {
		t.Fatal("cert for an unknown device accepted")
	} else if !IsDomainError(err) {
		t.Errorf("foreign key violation %v: not a domain error", err)
	}
	if err := s.JoinTokens().Create(ctx, "j", now.Add(time.Hour), "storage"); err != nil {
		t.Fatal(err)
	}
	if err := s.JoinTokens().Create(ctx, "j", now.Add(time.Hour), "storage"); !IsDomainError(err) {
		t.Errorf("duplicate token %v: not a domain error", err)
	}
	for _, err := range []error{ErrNotFound, ErrTokenUsed, fmt.Errorf("x: %w", ErrTokenExpired), ErrSchemaTooOld} {
		if !IsDomainError(err) {
			t.Errorf("%v: not a domain error", err)
		}
	}
	if IsDomainError(ErrSchemaMismatch) {
		t.Error("ErrSchemaMismatch is a domain error; a node that cannot migrate must halt")
	}
	// A failure of this node is not.
	_ = s.Close()
	_, err := s.ApplyLocal(ctx, MarkSeen{ID: "pi", Now: 1})
	if err == nil || IsDomainError(err) {
		t.Errorf("closed database: err = %v, want a non-domain error", err)
	}
}

// previousSchema is the version of the migration before the newest.
func previousSchema(t *testing.T) int64 {
	t.Helper()
	names, err := fs.Glob(migrations, "migrations/*.sql")
	if err != nil {
		t.Fatal(err)
	}
	var prev int64
	for _, n := range names {
		v, err := strconv.ParseInt(strings.SplitN(path.Base(n), "_", 2)[0], 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		if v < SchemaVersion() {
			prev = max(prev, v)
		}
	}
	return prev
}
