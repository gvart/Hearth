// SPDX-License-Identifier: AGPL-3.0-only

//go:build !windows

package main

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/store"
)

// TestBackupStopsCleanlyOnHangup closes the terminal on a running backup. It
// waits for an approval, a point it reliably reaches, in a real process.
func TestBackupStopsCleanlyOnHangup(t *testing.T) {
	if os.Getenv("HEARTH_TEST_RUN_CLI") == "1" {
		root := newRootCmd(buildInfo{Version: "test"})
		root.SetArgs(strings.Split(os.Getenv("HEARTH_TEST_CLI_ARGS"), "\n"))
		if err := root.ExecuteContext(context.Background()); err != nil {
			os.Exit(3)
		}
		os.Exit(0)
	}
	dir, _ := initHub(t)
	if err := os.WriteFile(filepath.Join(dir, "policy.yaml"), []byte("classes: {dangerous: confirm}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "hub.hbk")
	cmd := exec.Command(os.Args[0], "-test.run=^TestBackupStopsCleanlyOnHangup$") //nolint:gosec // this test binary
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	cmd.Env = append(os.Environ(), "HEARTH_TEST_RUN_CLI=1", passphraseEnv+"="+testBackupPassphrase,
		"HEARTH_TEST_CLI_ARGS="+strings.Join([]string{"backup", output, "--data-dir", dir}, "\n"))
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		_ = cmd.Wait() // judged by the wait status below
		close(done)
	}()
	st := openStore(t, dir)
	waitFor(t, "the backup to wait for approval", 20*time.Second, func() bool {
		held, err := st.Approvals().List(t.Context(), store.ApprovalPending, 5)
		return err == nil && len(held) == 1
	})
	if err := cmd.Process.Signal(syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("the backup did not stop on SIGHUP")
	}
	status, _ := cmd.ProcessState.Sys().(syscall.WaitStatus)
	if status.Signaled() {
		t.Fatalf("the backup was killed by %v instead of cleaning up:\n%s", status.Signal(), out.String())
	}
	if _, err := os.Stat(output); !os.IsNotExist(err) {
		t.Errorf("a stopped backup left a file: %v", err)
	}
}
