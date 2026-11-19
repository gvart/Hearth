// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func abandoned(t *testing.T, dir string) bool {
	t.Helper()
	parent := filepath.Dir(dir)
	entries, err := os.ReadDir(parent)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() == filepath.Base(dir) {
			return AbandonedTempDir(parent, e)
		}
	}
	t.Fatalf("%s is gone", dir)
	return false
}

func TestTempDirInUseIsNotAbandoned(t *testing.T) {
	parent := t.TempDir()
	dir, remove, err := NewTempDir(parent, BackupTempPrefix)
	if err != nil {
		t.Fatal(err)
	}
	if abandoned(t, dir) {
		t.Error("a directory in use counts as abandoned")
	}
	if err := RemoveAbandonedTempDirs(parent); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Errorf("a directory in use was removed: %v", err)
	}
	remove()
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("remove left the directory: %v", err)
	}
}

// TestTempDirOfAKilledProcessIsAbandoned kills a real owner, which gets no
// chance to clean up.
func TestTempDirOfAKilledProcessIsAbandoned(t *testing.T) {
	if parent := os.Getenv("HEARTH_TEST_TEMPDIR_PARENT"); parent != "" {
		dir, _, err := NewTempDir(parent, RestoreTempPrefix)
		if err != nil {
			fmt.Println("error:", err)
			os.Exit(1)
		}
		fmt.Println(dir)
		_, _ = io.Copy(io.Discard, os.Stdin) // held until the parent kills this process
		os.Exit(0)
	}
	parent := t.TempDir()
	cmd := exec.Command(os.Args[0], "-test.run=^TestTempDirOfAKilledProcessIsAbandoned$") //nolint:gosec // this test binary
	cmd.Env = append(os.Environ(), "HEARTH_TEST_TEMPDIR_PARENT="+parent)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = stdin.Close() }()
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil {
		_ = cmd.Process.Kill()
		t.Fatal(err)
	}
	dir := strings.TrimSpace(line)
	if abandoned(t, dir) {
		t.Error("the directory of a running process counts as abandoned")
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	if !abandoned(t, dir) {
		t.Error("the directory of a killed process still counts as in use")
	}
	if err := RemoveAbandonedTempDirs(parent); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("the abandoned directory is still there: %v", err)
	}
}

// TestTempDirWithoutALockGoesByAge: its owner may be about to lock it.
func TestTempDirWithoutALockGoesByAge(t *testing.T) {
	dir := filepath.Join(t.TempDir(), ".snapshot-123")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if abandoned(t, dir) {
		t.Error("a new directory without a lock counts as abandoned")
	}
	old := time.Now().Add(-2 * unlockedTempAge)
	if err := os.Chtimes(dir, old, old); err != nil {
		t.Fatal(err)
	}
	if !abandoned(t, dir) {
		t.Error("an old directory without a lock counts as in use")
	}
}
