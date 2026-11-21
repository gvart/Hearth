// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/backup"
	"github.com/gvart/hearth/internal/store"
)

// TestWebBackupCopiesTheClusterStore: the web UI's download of an AP
// member holds the whole cluster store its snapshot copies, not the
// member's own shards; without a snapshot, the local store.
func TestWebBackupCopiesTheClusterStore(t *testing.T) {
	dir, _ := initHub(t)
	st := openStore(t, dir)
	now := time.Now()
	if err := st.Devices().Upsert(t.Context(), store.Device{ID: "here", Name: "here", FirstSeen: now, LastSeen: now}); err != nil {
		t.Fatal(err)
	}
	// The cluster's rows, as APNode.Snapshot gathers them from every member.
	whole := openStore(t, t.TempDir())
	for _, id := range []string{"here", "elsewhere"} {
		if err := whole.Devices().Upsert(t.Context(), store.Device{ID: id, Name: id, FirstSeen: now, LastSeen: now}); err != nil {
			t.Fatal(err)
		}
	}
	tests := []struct {
		name     string
		snapshot func(context.Context, string) error
		want     map[string]bool
	}{
		{"an AP member", whole.VacuumInto, map[string]bool{"here": true, "elsewhere": true}},
		{"no snapshot", nil, map[string]bool{"here": true, "elsewhere": false}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file := filepath.Join(t.TempDir(), "web.hbk")
			if err := webBackup(hubOptions{dataDir: dir}, st, func() bool { return tt.snapshot != nil }, tt.snapshot)(t.Context(), file, testBackupPassphrase); err != nil {
				t.Fatal(err)
			}
			target := filepath.Join(t.TempDir(), "restored")
			if _, err := backup.Restore(t.Context(), backup.RestoreOptions{
				Input: file, Passphrase: testBackupPassphrase, DataDir: target,
			}); err != nil {
				t.Fatal(err)
			}
			restored := openStore(t, target)
			for id, want := range tt.want {
				_, err := restored.Devices().Get(t.Context(), id)
				if got := err == nil; got != want || (err != nil && !errors.Is(err, store.ErrNotFound)) {
					t.Errorf("device %s in the backup: %v, want present %v", id, err, want)
				}
			}
		})
	}
}
