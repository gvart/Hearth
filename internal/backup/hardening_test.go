// SPDX-License-Identifier: AGPL-3.0-only

package backup

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/gvart/hearth/internal/cluster"
	"github.com/gvart/hearth/internal/pki"
)

// deadPID returns the process ID of a process that has exited.
func deadPID(t *testing.T) int {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^$") //nolint:gosec // this test binary
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	return cmd.Process.Pid
}

func TestCreateRefusesNamesItCouldNotRestore(t *testing.T) {
	names := map[string]string{"too long": strings.Repeat("x", 250) + ".yaml"}
	if runtime.GOOS != "windows" {
		names["backslash"] = `a\b.yaml`
	}
	for label, name := range names {
		t.Run(label, func(t *testing.T) {
			dir, st := newHub(t)
			writeTestFile(t, filepath.Join(dir, automationsDir, name), "id: x\n")
			out := filepath.Join(t.TempDir(), "hub.hbk")
			_, err := Create(t.Context(), createOpts(dir, st, out))
			if err == nil || !strings.Contains(err.Error(), name) {
				t.Fatalf("Create = %v, want an error naming %q", err, name)
			}
			if _, err := os.Stat(out); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("a backup was written: %v", err)
			}
		})
	}
}

// TestWriteAtomicNeverReplaces: a file that appears while the backup is being
// written is kept.
func TestWriteAtomicNeverReplaces(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hub.hbk")
	err := writeAtomic(path, func(w io.Writer) error {
		writeTestFile(t, path, "someone else's file")
		_, err := w.Write([]byte("backup"))
		return err
	})
	if !errors.Is(err, ErrOutputExists) {
		t.Fatalf("writeAtomic = %v, want ErrOutputExists", err)
	}
	if b, _ := os.ReadFile(path); string(b) != "someone else's file" {
		t.Errorf("the existing file was replaced: %q", b)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil || len(entries) != 1 {
		t.Errorf("left behind: %v, %v", entries, err)
	}
}

// TestCommitNeverReplaces: a file that appears in the data dir after the
// emptiness check survives, and the restore takes back what it moved.
func TestCommitNeverReplaces(t *testing.T) {
	for _, foreign := range []string{pki.CAKeyFile, dbName, "automations/lights.yaml"} {
		t.Run(foreign, func(t *testing.T) {
			stage, dataDir := t.TempDir(), t.TempDir()
			for _, name := range []string{pki.CACertFile, pki.CAKeyFile, dbName, "automations/lights.yaml"} {
				writeTestFile(t, filepath.Join(stage, filepath.FromSlash(name)), "restored")
			}
			writeTestFile(t, filepath.Join(dataDir, filepath.FromSlash(foreign)), "foreign")
			if err := commit(stage, dataDir); err == nil {
				t.Fatal("commit replaced or merged with an existing file")
			}
			b, err := os.ReadFile(filepath.Join(dataDir, filepath.FromSlash(foreign)))
			if err != nil || string(b) != "foreign" {
				t.Errorf("%s = %q, %v", foreign, b, err)
			}
			if _, err := os.Stat(filepath.Join(dataDir, pki.CACertFile)); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("a failed commit left ca.crt behind: %v", err)
			}
		})
	}
}

func TestRestoreWritesACompletionMarker(t *testing.T) {
	target := filepath.Join(t.TempDir(), "restored")
	if _, err := Restore(t.Context(), RestoreOptions{Input: newBackup(t), Passphrase: testPassphrase, DataDir: target}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(target, "restore-complete")); err != nil {
		t.Errorf("no completion marker: %v", err)
	}
}

// TestRestoreStartsANewClusterEpoch: every restore gets its own epoch, so hubs
// of the old cluster are told apart, recorded in the backup or not.
func TestRestoreStartsANewClusterEpoch(t *testing.T) {
	input := newBackup(t)
	epochs := map[string]bool{}
	for range 2 {
		target := filepath.Join(t.TempDir(), "restored")
		if _, err := Restore(t.Context(), RestoreOptions{Input: input, Passphrase: testPassphrase, DataDir: target}); err != nil {
			t.Fatal(err)
		}
		b, err := os.ReadFile(filepath.Join(target, cluster.EpochFile))
		if err != nil || len(b) == 0 {
			t.Fatalf("epoch file = %q, %v", b, err)
		}
		epochs[string(b)] = true
	}
	if len(epochs) != 2 {
		t.Errorf("two restores share an epoch: %v", epochs)
	}
}

func TestAbandonedRestoreDoesNotBlockTheRetry(t *testing.T) {
	target := t.TempDir()
	stale := filepath.Join(target, fmt.Sprintf(".restore-%d-abc", deadPID(t)))
	writeTestFile(t, filepath.Join(stale, pki.CAKeyFile), "plaintext left by a killed restore")
	if err := CheckDataDir(target); err != nil {
		t.Fatalf("CheckDataDir = %v", err)
	}
	if _, err := Restore(t.Context(), RestoreOptions{Input: newBackup(t), Passphrase: testPassphrase, DataDir: target}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stale); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the abandoned stage is still there: %v", err)
	}
}

func TestRunningRestoreStillBlocks(t *testing.T) {
	target := t.TempDir()
	writeTestFile(t, filepath.Join(target, fmt.Sprintf(".restore-%d-abc", os.Getppid()), "x"), "in use")
	if err := CheckDataDir(target); !errors.Is(err, ErrDataDirNotEmpty) {
		t.Fatalf("CheckDataDir = %v, want ErrDataDirNotEmpty", err)
	}
}

// TestRestoreStoppedMidCommitIsDetected: some files were moved, no marker.
func TestRestoreStoppedMidCommitIsDetected(t *testing.T) {
	target := t.TempDir()
	writeTestFile(t, filepath.Join(target, fmt.Sprintf(".restore-%d-abc", deadPID(t)), dbName), "x")
	writeTestFile(t, filepath.Join(target, pki.CACertFile), "moved already")
	err := CheckDataDir(target)
	if !errors.Is(err, ErrIncompleteRestore) || !errors.Is(err, ErrDataDirNotEmpty) {
		t.Fatalf("CheckDataDir = %v, want ErrIncompleteRestore", err)
	}
}

func TestCreateRemovesAbandonedTempDirs(t *testing.T) {
	dir, st := newHub(t)
	dead := deadPID(t)
	stale := []string{
		fmt.Sprintf(".snapshot-%d-a", dead), fmt.Sprintf(".backup-%d-b", dead), fmt.Sprintf(".restore-%d-c", dead),
	}
	for _, name := range stale {
		writeTestFile(t, filepath.Join(dir, name, dbName), "plaintext")
	}
	// A restore that finished, but was killed before it removed its stage.
	writeTestFile(t, filepath.Join(dir, completeMarker), "")
	live := fmt.Sprintf(".snapshot-%d-d", os.Getppid())
	writeTestFile(t, filepath.Join(dir, live, dbName), "in use by a running hub")
	if _, err := Create(t.Context(), createOpts(dir, st, filepath.Join(t.TempDir(), "hub.hbk"))); err != nil {
		t.Fatal(err)
	}
	for _, name := range stale {
		if _, err := os.Stat(filepath.Join(dir, name)); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("%s is still there: %v", name, err)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, live)); err != nil {
		t.Errorf("a directory in use was removed: %v", err)
	}
}

func TestKDFLimits(t *testing.T) {
	tests := []struct {
		name string
		p    kdfParams
		want bool
	}{
		{"the cost of format 1", defaultKDF(), true},
		{"modest headroom", kdfParams{time: 6, memory: 128 * 1024, threads: 4}, true},
		{"too much memory", kdfParams{time: 3, memory: 128*1024 + 1, threads: 1}, false},
		{"too many passes", kdfParams{time: 7, memory: 64 * 1024, threads: 1}, false},
		{"too many lanes", kdfParams{time: 3, memory: 64 * 1024, threads: 5}, false},
		{"no passes", kdfParams{time: 0, memory: 64 * 1024, threads: 1}, false},
		{"no lanes", kdfParams{time: 3, memory: 64 * 1024, threads: 0}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.p.valid(); got != tt.want {
				t.Errorf("valid(%+v) = %v, want %v", tt.p, got, tt.want)
			}
		})
	}
}

func TestFailedRestoreKeepsTheDataDirMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no POSIX modes")
	}
	b, err := os.ReadFile(newBackup(t))
	if err != nil {
		t.Fatal(err)
	}
	damaged := filepath.Join(t.TempDir(), "damaged.hbk")
	if err := os.WriteFile(damaged, b[:len(b)-1], 0o600); err != nil { //nolint:gosec // a path under t.TempDir
		t.Fatal(err)
	}
	target := t.TempDir()
	if err := os.Chmod(target, 0o755); err != nil { //nolint:gosec // the mode under test
		t.Fatal(err)
	}
	if _, err := Restore(t.Context(), RestoreOptions{Input: damaged, Passphrase: testPassphrase, DataDir: target}); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("Restore = %v, want ErrCorrupt", err)
	}
	info, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o755 {
		t.Errorf("mode after a failed restore = %o, want 755", info.Mode().Perm())
	}
}
