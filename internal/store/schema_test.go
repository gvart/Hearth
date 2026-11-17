// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"bytes"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

func TestSchemaVersionIsNewestMigration(t *testing.T) {
	s := openTest(t)
	if got, want := gooseVersion(t, s.db), SchemaVersion(); got != want || want < 4 {
		t.Fatalf("database at %d, SchemaVersion() = %d", got, want)
	}
	v, err := s.SchemaVersion(t.Context())
	if err != nil || v != SchemaVersion() {
		t.Fatalf("Store.SchemaVersion = %d, %v", v, err)
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

	// One behind is refused and left untouched; without the option it migrates.
	p, err := newMigrator(s.db)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.DownTo(ctx, SchemaVersion()-1); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	if _, err := Open(ctx, path, WithoutUpgrade()); !errors.Is(err, ErrSchemaMismatch) {
		t.Fatalf("Open behind: err = %v, want ErrSchemaMismatch", err)
	}
	s, err = Open(ctx, path)
	if err != nil {
		t.Fatalf("Open with upgrade: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if v := gooseVersion(t, s.db); v != SchemaVersion() {
		t.Fatalf("upgraded database at %d", v)
	}
}

func TestRestoreRejectsOtherSchema(t *testing.T) {
	ctx := t.Context()
	src := openTest(t)
	p, err := newMigrator(src.db)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.DownTo(ctx, SchemaVersion()-1); err != nil {
		t.Fatal(err)
	}
	var snap bytes.Buffer
	if err := src.Snapshot(ctx, &snap); err != nil {
		t.Fatal(err)
	}
	dst := openTest(t)
	if err := dst.Restore(ctx, &snap); !errors.Is(err, ErrSchemaMismatch) {
		t.Fatalf("Restore: err = %v, want ErrSchemaMismatch", err)
	}
	if v := gooseVersion(t, dst.db); v != SchemaVersion() {
		t.Fatalf("rejected restore changed the schema to %d", v)
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
	for _, err := range []error{ErrNotFound, ErrTokenUsed, fmt.Errorf("x: %w", ErrTokenExpired)} {
		if !IsDomainError(err) {
			t.Errorf("%v: not a domain error", err)
		}
	}
	// A failure of this node is not.
	_ = s.Close()
	_, err := s.ApplyLocal(ctx, MarkSeen{ID: "pi", Now: 1})
	if err == nil || IsDomainError(err) {
		t.Errorf("closed database: err = %v, want a non-domain error", err)
	}
}
