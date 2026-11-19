// SPDX-License-Identifier: AGPL-3.0-only

//go:build !windows

package store

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// tempDirEntry makes a temporary directory that went through the lock protocol.
func tempDirEntry(t *testing.T, name string) (string, os.DirEntry, *os.File) {
	t.Helper()
	parent := t.TempDir()
	dir := filepath.Join(parent, name)
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	lock, err := os.OpenFile(filepath.Join(dir, tempLockFile), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lock.Close() })
	if err := os.WriteFile(filepath.Join(dir, tempLockedFile), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(parent)
	if err != nil || len(entries) != 1 {
		t.Fatalf("entries = %v, %v", entries, err)
	}
	return parent, entries[0], lock
}

// TestAbandonedTempDirGoesByTheLock: process IDs say nothing after a crash, when
// the ID is reused, or across containers that share a data volume.
func TestAbandonedTempDirGoesByTheLock(t *testing.T) {
	t.Run("unlocked, under the ID of a running process", func(t *testing.T) {
		parent, e, _ := tempDirEntry(t, fmt.Sprintf(".restore-%d-abc", os.Getppid()))
		if !AbandonedTempDir(parent, e) {
			t.Error("a directory nobody holds counts as in use")
		}
	})
	t.Run("locked, under an ID unknown here", func(t *testing.T) {
		parent, e, lock := tempDirEntry(t, ".snapshot-99999999-abc")
		if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
			t.Fatal(err)
		}
		if AbandonedTempDir(parent, e) {
			t.Error("a directory another process holds counts as abandoned")
		}
	})
}
