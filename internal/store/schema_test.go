// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"slices"
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
// as a cluster member on a database at SchemaVersion: a newer binary
// running at the older schema until the cluster migrates.
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

	// One behind opens and stays behind: the binary supports it, and only
	// the cluster may migrate it.
	p, err := s.newMigrator()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.DownTo(ctx, SchemaVersion()-1); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	s, err = Open(ctx, path, WithoutUpgrade())
	if err != nil {
		t.Fatalf("Open behind: %v", err)
	}
	if v := gooseVersion(t, s.db); v != SchemaVersion()-1 {
		t.Fatalf("Open behind migrated the database to %d", v)
	}
	_ = s.Close()

	// A standalone hub (no option) migrates on open, as it always did.
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

func TestRestoreAcrossSchemas(t *testing.T) {
	ctx := t.Context()

	// An older snapshot restores into a newer binary's store, at its schema.
	older := openTest(t)
	if err := older.Devices().Upsert(ctx, Device{ID: "pi", FirstSeen: time.Now(), LastSeen: time.Now()}); err != nil {
		t.Fatal(err)
	}
	var snap bytes.Buffer
	if err := older.Snapshot(ctx, &snap); err != nil {
		t.Fatal(err)
	}
	newer, err := Open(ctx, filepath.Join(t.TempDir(), "hearth.db"), WithExtraMigration(nextSchema, testMigration))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = newer.Close() })
	if err := newer.Restore(ctx, &snap); err != nil {
		t.Fatalf("restore an older snapshot: %v", err)
	}
	if v := gooseVersion(t, newer.db); v != SchemaVersion() {
		t.Fatalf("restored at %d, want %d", v, SchemaVersion())
	}
	if _, err := newer.Devices().Get(ctx, "pi"); err != nil {
		t.Fatalf("restored data: %v", err)
	}
	if slices.Contains(tableNames(ctx, t, newer.db), "rolling_test") {
		t.Fatal("the newer binary's table survived restoring an older snapshot")
	}

	// It migrates later, and its snapshot is refused by the older binary.
	if _, err := newer.ApplyLocal(ctx, MigrateSchema{To: nextSchema}); err != nil {
		t.Fatal(err)
	}
	snap.Reset()
	if err := newer.Snapshot(ctx, &snap); err != nil {
		t.Fatal(err)
	}
	if err := older.Restore(ctx, &snap); !errors.Is(err, ErrSchemaMismatch) {
		t.Fatalf("restore a newer snapshot: err = %v, want ErrSchemaMismatch", err)
	}
	if v := gooseVersion(t, older.db); v != SchemaVersion() {
		t.Fatalf("rejected restore changed the schema to %d", v)
	}
	if _, err := older.Devices().Get(ctx, "pi"); err != nil {
		t.Fatalf("rejected restore changed the data: %v", err)
	}
}

func TestMigrateSchema(t *testing.T) {
	ctx := t.Context()
	s := openNewerBinary(t)
	if s.MaxSchemaVersion() != nextSchema {
		t.Fatalf("MaxSchemaVersion = %d, want %d", s.MaxSchemaVersion(), nextSchema)
	}
	// Not past the current version: a domain error, the same on every node.
	for _, to := range []int64{SchemaVersion() - 1, SchemaVersion()} {
		_, err := s.ApplyLocal(ctx, MigrateSchema{To: to})
		if !errors.Is(err, ErrSchemaNotNewer) || !IsDomainError(err) {
			t.Fatalf("migrate to %d: err = %v, want domain error ErrSchemaNotNewer", to, err)
		}
	}
	// Past what this binary supports: a failure of this node.
	_, err := s.ApplyLocal(ctx, MigrateSchema{To: nextSchema + 1})
	if !errors.Is(err, ErrSchemaMismatch) || IsDomainError(err) {
		t.Fatalf("migrate past the binary: err = %v, want non-domain ErrSchemaMismatch", err)
	}
	if v := gooseVersion(t, s.db); v != SchemaVersion() {
		t.Fatalf("refused migrations moved the schema to %d", v)
	}

	if _, err := s.ApplyLocal(ctx, MigrateSchema{To: nextSchema}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if v, err := s.SchemaVersion(ctx); err != nil || v != nextSchema {
		t.Fatalf("after migrate: schema %d, %v", v, err)
	}
	if !slices.Contains(tableNames(ctx, t, s.db), "rolling_test") {
		t.Fatal("migration did not run")
	}
	if _, err := s.ApplyLocal(ctx, MigrateSchema{To: nextSchema}); !errors.Is(err, ErrSchemaNotNewer) {
		t.Fatalf("migrate again: err = %v, want ErrSchemaNotNewer", err)
	}
}

// TestReplayWithMigrateIsDeterministic: replaying a log that migrates the
// schema halfway yields the same tables, rows and schema on every node.
func TestReplayWithMigrateIsDeterministic(t *testing.T) {
	now := int64(1_700_000_000_000)
	device := func(id string) Command {
		return UpsertDevice{ID: id, Name: id, Facts: "{}", Labels: "{}", FirstSeen: now, LastSeen: now, Status: StatusUnknown}
	}
	cmds := []Command{
		device("before"),
		MigrateSchema{To: nextSchema},
		device("after"),
		MigrateSchema{To: nextSchema}, // a duplicate: refused alike everywhere
		AppendAudit{TS: now, ActorKind: "admin", ActorID: "op", Action: "cluster.migrate", Decision: "allow", Result: "ok", Detail: "{}"},
		device("later"),
	}
	var log [][]byte
	for _, c := range cmds {
		b, err := EncodeCommand(c)
		if err != nil {
			t.Fatal(err)
		}
		log = append(log, b)
	}
	replay := func() (*Store, []string) {
		s := openNewerBinary(t)
		var errs []string
		for _, b := range log {
			cmd, err := DecodeCommand(b)
			if err != nil {
				t.Fatal(err)
			}
			_, err = s.ApplyLocal(t.Context(), cmd)
			errs = append(errs, fmt.Sprint(err))
		}
		return s, errs
	}
	a, aErrs := replay()
	b, bErrs := replay()
	if !reflect.DeepEqual(aErrs, bErrs) || aErrs[3] == "<nil>" {
		t.Fatalf("outcomes differ or the duplicate migrate was applied:\n%v\n%v", aErrs, bErrs)
	}
	if got, want := dumpTables(t, b.db), dumpTables(t, a.db); !reflect.DeepEqual(got, want) {
		t.Fatalf("replayed tables differ\n got: %v\nwant: %v", got, want)
	}
	if got, want := schemaSQL(t, b.db), schemaSQL(t, a.db); !reflect.DeepEqual(got, want) {
		t.Fatalf("replayed schemas differ\n got: %v\nwant: %v", got, want)
	}
	if got := gooseVersion(t, a.db); got != nextSchema {
		t.Fatalf("replayed schema at %d, want %d", got, nextSchema)
	}
	// Only devices inserted after the migrate reached the new table.
	if got := dumpTables(t, a.db)["rolling_test"]; !reflect.DeepEqual(got, [][]any{{"after"}, {"later"}}) {
		t.Fatalf("rolling_test = %v", got)
	}
}

// schemaSQL returns the SQL of every schema object, by name.
func schemaSQL(t *testing.T, db *sql.DB) map[string]string {
	t.Helper()
	rows, err := db.QueryContext(t.Context(), `SELECT name, COALESCE(sql, '') FROM sqlite_master`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var name, s string
		if err := rows.Scan(&name, &s); err != nil {
			t.Fatal(err)
		}
		out[name] = s
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// gatedInsert is a command of a newer release: it writes testMigration's table.
type gatedInsert struct{ ID string }

func (gatedInsert) Op() string       { return "gated_insert" }
func (gatedInsert) minSchema() int64 { return nextSchema }
func (c gatedInsert) apply(ctx context.Context, tx *sql.Tx) (Result, error) {
	_, err := tx.ExecContext(ctx, `INSERT INTO rolling_test (device_id) VALUES (?)`, c.ID)
	return Result{}, err
}

func TestSchemaGatedCommand(t *testing.T) {
	ctx := t.Context()
	s := openNewerBinary(t)
	_, err := s.ApplyLocal(ctx, gatedInsert{ID: "pi"})
	if !errors.Is(err, ErrSchemaTooOld) || !IsDomainError(err) {
		t.Fatalf("before the migrate: err = %v, want domain error ErrSchemaTooOld", err)
	}
	if _, err := s.ApplyLocal(ctx, MigrateSchema{To: nextSchema}); err != nil {
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
	if err := s.JoinTokens().Create(ctx, "j", now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := s.JoinTokens().Create(ctx, "j", now.Add(time.Hour)); !IsDomainError(err) {
		t.Errorf("duplicate token %v: not a domain error", err)
	}
	for _, err := range []error{ErrNotFound, ErrTokenUsed, fmt.Errorf("x: %w", ErrTokenExpired), ErrSchemaNotNewer, ErrSchemaTooOld} {
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
