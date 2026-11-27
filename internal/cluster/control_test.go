// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/store"
)

// shortDir returns a fresh directory whose path is short enough for a unix
// socket (104 bytes on macOS), whatever TMPDIR is. The socket path of a data
// dir that is too long falls back to TMPDIR, so a long TMPDIR can't be used.
func shortDir(t *testing.T) string {
	t.Helper()
	base := os.TempDir()
	if runtime.GOOS != "windows" {
		base = "/tmp"
	}
	dir, err := os.MkdirTemp(base, "hc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if p := ControlSocketPath(dir); len(p) > maxSocketPath {
		t.Fatalf("socket path %q is too long for a unix socket", p)
	}
	return dir
}

// waitForSocket waits until path exists. It fails the test at once if
// ServeAPControl returned (its result is read from done and put back for the
// caller), and after waitFor otherwise.
func waitForSocket(t *testing.T, path string, done chan error, sleep time.Duration) os.FileInfo {
	t.Helper()
	deadline := time.Now().Add(waitFor)
	for {
		if info, err := os.Lstat(path); err == nil {
			return info
		}
		select {
		case err := <-done:
			done <- err
			t.Fatalf("ServeAPControl returned before the socket appeared: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for control socket %s", path)
		}
		time.Sleep(sleep)
	}
}

func TestControlSocketPath(t *testing.T) {
	short := "/var/lib/hearth/hub"
	if got := ControlSocketPath(short); got != filepath.Join(short, ControlSocket) {
		t.Errorf("short data dir: %s", got)
	}
	long := "/" + strings.Repeat("d", 120)
	got := ControlSocketPath(long)
	if !strings.HasPrefix(got, os.TempDir()) || got != ControlSocketPath(long) {
		t.Errorf("long data dir: %s", got)
	}
	if ControlSocketPath(long+"x") == got {
		t.Error("two data dirs share a socket")
	}
}

func TestDialControlWithoutHub(t *testing.T) {
	if _, err := DialControl(t.TempDir()); err == nil {
		t.Fatal("DialControl succeeded with no hub running")
	}
}

// TestControlSocketNeverLoose watches the socket path while ServeAPControl
// starts: no observer may ever see it with a mode other than 0600 (#103).
func TestControlSocketNeverLoose(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix permissions")
	}
	for range 30 {
		dir := shortDir(t)
		path := ControlSocketPath(dir)
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan error, 1)
		go func() { done <- ServeAPControl(ctx, dir, nil, testLogger(t)) }()
		info := waitForSocket(t, path, done, 50*time.Microsecond)
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("control socket seen with mode %o, want 600", perm)
		}
		cancel()
		if err := <-done; err != nil {
			t.Fatalf("ServeControl: %v", err)
		}
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("socket left behind after shutdown: %v", err)
		}
		if t.Failed() {
			return
		}
	}
}

// ErrNoMajority keeps its kind across the wire, though it is also
// ErrUnavailable.
func TestWireErrorNoMajority(t *testing.T) {
	for range 20 {
		w := toWireError(fmt.Errorf("apply save_runbook_run: %w", store.ErrNoMajority))
		if w.Kind != "no_majority" {
			t.Fatalf("kind %q, want no_majority", w.Kind)
		}
		err := w.toError()
		if !errors.Is(err, store.ErrNoMajority) || !errors.Is(err, store.ErrUnavailable) {
			t.Fatalf("%v is not ErrNoMajority and ErrUnavailable", err)
		}
	}
}
