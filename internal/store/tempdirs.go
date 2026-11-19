// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Private directories in a hub data dir that hold plaintext copies of the
// database while an operation runs.
const (
	snapshotTempPrefix = ".snapshot-"
	// BackupTempPrefix names the working directory of a backup.
	BackupTempPrefix = ".backup-"
	// RestoreTempPrefix names the staging directory of a restore.
	RestoreTempPrefix = ".restore-"
)

// The owner of a temporary directory holds an advisory lock on tempLockFile for
// as long as it runs, and the system releases it when the owner dies, however it
// dies. Unlike a process ID, the lock means the same across a restart and across
// containers that share a data volume. tempLockedFile appears once the lock is
// held, so a directory caught between the two steps is not taken for abandoned.
const (
	tempLockFile   = ".lock"
	tempLockedFile = ".locked"
)

// unlockedTempAge is how old a directory without a held-lock marker must be to
// count as abandoned: its owner died before it locked it, or predates the lock.
const unlockedTempAge = time.Hour

// NewTempDir creates a private (0700) directory in parent and locks it for this
// process. remove releases the lock and deletes the directory.
func NewTempDir(parent, prefix string) (dir string, remove func(), err error) {
	dir, err = os.MkdirTemp(parent, prefix)
	if err != nil {
		return "", nil, err
	}
	lock, err := lockTempDir(dir)
	if err != nil {
		_ = os.RemoveAll(dir) //nolint:gosec // dir is created here, in the hub's data dir
		return "", nil, fmt.Errorf("lock temp dir: %w", err)
	}
	return dir, func() {
		// Closed first: Windows cannot delete an open file.
		_ = lock.Close()
		_ = os.RemoveAll(dir) //nolint:gosec // dir is created here, in the hub's data dir
	}, nil
}

func lockTempDir(dir string) (*os.File, error) {
	lock, err := os.OpenFile(filepath.Join(dir, tempLockFile), os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600) //nolint:gosec // dir is created here, in the hub's data dir
	if err != nil {
		return nil, err
	}
	locked, err := tryLock(lock)
	if err == nil && !locked {
		err = errors.New("already locked")
	}
	if err == nil {
		err = os.WriteFile(filepath.Join(dir, tempLockedFile), nil, 0o600) //nolint:gosec // dir is created here, in the hub's data dir
	}
	if err != nil {
		_ = lock.Close()
		return nil, err
	}
	return lock, nil
}

// IsTempDir reports whether name is one of the temporary directories above.
func IsTempDir(name string) bool {
	for _, p := range []string{snapshotTempPrefix, BackupTempPrefix, RestoreTempPrefix} {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// AbandonedTempDir reports whether e is a temporary directory whose owner is
// gone. When that cannot be told, the directory counts as in use.
func AbandonedTempDir(parent string, e fs.DirEntry) bool {
	if !e.IsDir() || !IsTempDir(e.Name()) {
		return false
	}
	dir := filepath.Join(parent, e.Name())
	if _, err := os.Lstat(filepath.Join(dir, tempLockedFile)); err != nil {
		info, err := e.Info()
		return err == nil && time.Since(info.ModTime()) > unlockedTempAge
	}
	lock, err := os.OpenFile(filepath.Join(dir, tempLockFile), os.O_RDWR, 0)
	if err != nil {
		return false
	}
	defer func() { _ = lock.Close() }()
	locked, err := tryLock(lock)
	return err == nil && locked
}

// RemoveAbandonedTempDirs deletes the temporary directories in parent whose
// owners are gone. A missing parent has none.
func RemoveAbandonedTempDirs(parent string) error {
	entries, err := os.ReadDir(parent)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("remove abandoned temp dirs: %w", err)
	}
	for _, e := range entries {
		if AbandonedTempDir(parent, e) {
			if err := os.RemoveAll(filepath.Join(parent, e.Name())); err != nil {
				return fmt.Errorf("remove abandoned temp dirs: %w", err)
			}
		}
	}
	return nil
}
