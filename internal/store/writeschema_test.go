// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"errors"
	"fmt"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// WithWriteSchema caps what writes use: a command needing a newer schema
// is refused, and a column written only from some schema on is left out
// below it.
func TestWriteSchemaGatesWrites(t *testing.T) {
	ctx := t.Context()
	var w atomic.Int64
	s := openTestWith(t, WithWriteSchema(w.Load))
	tests := []struct {
		name     string
		schema   int64
		wantErr  error
		wantPins bool
	}{
		{"below the rotation's schema", CARotationSchema - 1, ErrSchemaTooOld, true},
		{"below the pins' schema", CertPinsSchema - 1, ErrSchemaTooOld, false},
		{"at the database's schema", SchemaVersion(), nil, true},
		{"above the database's schema", SchemaVersion() + 5, nil, true},
	}
	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w.Store(tc.schema)
			fp := fmt.Sprintf("new-%d", i)
			_, err := s.ApplyLocal(ctx, StartCARotation{NewCAFP: fp, OldCAFP: "old", Now: 1})
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("start a rotation at write schema %d: err = %v, want %v", tc.schema, err, tc.wantErr)
			}
			if err == nil {
				if _, err := s.ApplyLocal(ctx, AdvanceCARotation{NewCAFP: fp, From: CAStageStarted, To: CAStageAborted, Now: 2}); err != nil {
					t.Fatal(err)
				}
			}
			node := fmt.Sprintf("hub-%d", i)
			if _, err := s.ApplyLocal(ctx, RecordHubCert{Serial: fmt.Sprint(i), NodeID: node, Fingerprint: "fp", CAFP: "ca"}); err != nil {
				t.Fatal(err)
			}
			certs, err := s.Hubs().Certs(ctx, node)
			if err != nil || len(certs) != 1 {
				t.Fatalf("certs: %+v, %v", certs, err)
			}
			if got := certs[0].Fingerprint != ""; got != tc.wantPins {
				t.Fatalf("fingerprint written = %v at write schema %d, want %v", got, tc.schema, tc.wantPins)
			}
		})
	}
}

// Merge leaves out the columns this member's database lacks: a newer
// member's row carries the columns its schema added.
func TestMergeDropsUnknownColumns(t *testing.T) {
	ctx := t.Context()
	newer, err := Open(ctx, filepath.Join(t.TempDir(), "hearth.db"), WithDigest(),
		WithExtraMigration(nextSchema, `ALTER TABLE devices ADD COLUMN rolling TEXT NOT NULL DEFAULT 'x'`))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = newer.Close() })
	older := openTestWith(t, WithDigest())
	now := time.Now().UnixMilli()
	_, muts, err := newer.ApplyLocalMutations(ctx, UpsertDevice{ID: "pi", Name: "pi", Facts: "{}", Labels: "{}", FirstSeen: now, LastSeen: now})
	if err != nil {
		t.Fatal(err)
	}
	if len(muts) == 0 {
		t.Fatal("no mutations")
	}
	// A row read back and written again carries every column it has.
	muts[0].Row["rolling"] = "y"
	if err := older.Merge(ctx, muts); err != nil {
		t.Fatalf("merge into the older member: %v", err)
	}
	if _, ok := muts[0].Row["rolling"]; !ok {
		t.Fatal("Merge changed the caller's mutations")
	}
	if _, err := older.Devices().Get(ctx, "pi"); err != nil {
		t.Fatalf("merged device: %v", err)
	}
	// And the newer member takes the older member's rows, without the column.
	_, muts, err = older.ApplyLocalMutations(ctx, UpsertDevice{ID: "tv", Name: "tv", Facts: "{}", Labels: "{}", FirstSeen: now, LastSeen: now})
	if err != nil {
		t.Fatal(err)
	}
	if err := newer.Merge(ctx, muts); err != nil {
		t.Fatalf("merge into the newer member: %v", err)
	}
}
