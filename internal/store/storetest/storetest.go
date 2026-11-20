// SPDX-License-Identifier: AGPL-3.0-only

// Package storetest gives tests a migrated hub database without running
// the migrations again for each one. Migrating a new database is the
// costliest part of store.Open (SQLite parses the whole schema again after
// every ALTER TABLE, and under -race that takes most of a second), so a
// test binary migrates one template database once and every test gets a
// copy of its file.
package storetest

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/gvart/hearth/internal/store"
)

var template = sync.OnceValues(build)

// build migrates a new database to store.SchemaVersion and returns its
// file. A store opened on a copy behaves as one opened on a new file: it
// holds no rows, and its clock and origin are the Open options'.
func build() ([]byte, error) {
	dir, err := os.MkdirTemp("", "hearth-storetest-")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(dir, "migrated.db"))
	if err != nil {
		return nil, err
	}
	defer func() { _ = st.Close() }()
	// A snapshot is one self-contained file, without a WAL to copy.
	var b bytes.Buffer
	if err := st.Snapshot(ctx, &b); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// Migrated writes, at path, a database migrated to store.SchemaVersion,
// for a test to open with store.Open as it would a new file.
func Migrated(tb testing.TB, path string) {
	tb.Helper()
	b, err := template()
	if err != nil {
		tb.Fatalf("storetest: migrate the template database: %v", err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		tb.Fatal(err)
	}
}

// Open opens a store on a migrated database in a temporary directory of
// tb, closed when tb ends.
func Open(tb testing.TB, opts ...store.Option) *store.Store {
	tb.Helper()
	path := filepath.Join(tb.TempDir(), "hearth.db")
	Migrated(tb, path)
	st, err := store.Open(tb.Context(), path, opts...)
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { _ = st.Close() })
	return st
}
