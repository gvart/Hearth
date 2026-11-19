// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Private directories in a hub data dir that hold plaintext copies of the
// database while an operation runs. Their names carry the owner's process ID,
// so a later process can tell a running operation from one that was killed.
const (
	snapshotTempPrefix = ".snapshot-"
	// BackupTempPrefix names the working directory of a backup.
	BackupTempPrefix = ".backup-"
	// RestoreTempPrefix names the staging directory of a restore.
	RestoreTempPrefix = ".restore-"
)

// unownedTempAge is how old a directory without a process ID in its name, left
// by an older version, must be to count as abandoned.
const unownedTempAge = time.Hour

// NewTempDir creates a private (0700) directory in parent, owned by this process.
func NewTempDir(parent, prefix string) (string, error) {
	return os.MkdirTemp(parent, prefix+strconv.Itoa(os.Getpid())+"-")
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

// AbandonedTempDir reports whether e is a temporary directory whose owner has
// exited. With selfStale, this process's own ID counts as exited: a process
// that has created none yet may have inherited the ID, as PID 1 in a container
// does after a restart.
func AbandonedTempDir(e fs.DirEntry, selfStale bool) bool {
	if !e.IsDir() || !IsTempDir(e.Name()) {
		return false
	}
	_, rest, _ := strings.Cut(e.Name()[1:], "-")
	owner, _, owned := strings.Cut(rest, "-")
	pid, err := strconv.Atoi(owner)
	if !owned || err != nil {
		info, err := e.Info()
		return err == nil && time.Since(info.ModTime()) > unownedTempAge
	}
	if pid == os.Getpid() {
		return selfStale
	}
	return !processAlive(pid)
}

// processAlive reports whether a process with this ID exists. When it cannot
// tell, the process counts as alive, and its files are left alone.
func processAlive(pid int) bool {
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	defer func() { _ = p.Release() }()
	err = p.Signal(syscall.Signal(0))
	return !errors.Is(err, os.ErrProcessDone) && !errors.Is(err, syscall.ESRCH)
}

// RemoveAbandonedTempDirs deletes the temporary directories in parent whose
// owners have exited. A missing parent has none.
func RemoveAbandonedTempDirs(parent string, selfStale bool) error {
	entries, err := os.ReadDir(parent)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("remove abandoned temp dirs: %w", err)
	}
	for _, e := range entries {
		if AbandonedTempDir(e, selfStale) {
			if err := os.RemoveAll(filepath.Join(parent, e.Name())); err != nil {
				return fmt.Errorf("remove abandoned temp dirs: %w", err)
			}
		}
	}
	return nil
}
