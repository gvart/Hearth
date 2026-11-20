// SPDX-License-Identifier: AGPL-3.0-only

//go:build unix

package plugins

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/gvart/hearth/internal/policy"
)

// A plugin started through a wrapper leaves no process behind when it is
// restarted: the hub kills its whole process group.
func TestRestartKillsWhatThePluginStarted(t *testing.T) {
	exe := helperExe
	man := helperManifest(t, "wrapped", "crash")
	pids := filepath.Join(man.Dir, "pids")
	script := "sleep 300 &\necho $! >> " + pids + "\nexec \"$@\"\n"
	if err := os.WriteFile(filepath.Join(man.Dir, "wrapper.sh"), []byte(script), 0o600); err != nil {
		t.Fatal(err)
	}
	man.Command, man.Args = "/bin/sh", []string{"wrapper.sh", exe, helperArg, "crash"}
	m, _ := startManager(t, policy.Config{}, man)
	waitFor(t, "two restarts", func() bool { return status(m, "wrapped").Restarts >= 2 })
	b, err := os.ReadFile(pids)
	if err != nil {
		t.Fatal(err)
	}
	first, err := strconv.Atoi(strings.Fields(string(b))[0])
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the first wrapper's child to be gone", func() bool {
		return errors.Is(syscall.Kill(first, 0), syscall.ESRCH)
	})
}

func TestTrustChecks(t *testing.T) {
	good := "protocol: 1\nname: lamp\nversion: 1.0.0\ncommand: ./lamp\ncapabilities: [discover]\n"
	write := func(t *testing.T, dir, body string, mode os.FileMode) string {
		t.Helper()
		path := filepath.Join(dir, "plugin.yaml")
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		return path
	}
	t.Run("group-writable directory above the manifest", func(t *testing.T) {
		dir := filepath.Join(tempDir(t), "shared")
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		path := write(t, filepath.Join(dir), good, 0o644)
		if err := os.Chmod(dir, 0o775); err != nil { //nolint:gosec // the point of the test
			t.Fatal(err)
		}
		_, err := LoadManifest(path)
		if err == nil || !strings.Contains(err.Error(), "run chmod go-w") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("env in a manifest others can read", func(t *testing.T) {
		body := good + "env: {TOKEN: secret}\n"
		_, err := LoadManifest(write(t, tempDir(t), body, 0o644))
		if err == nil || !strings.Contains(err.Error(), "run chmod 600") {
			t.Fatalf("err = %v", err)
		}
		if _, err := LoadManifest(write(t, tempDir(t), body, 0o600)); err != nil {
			t.Fatalf("0600: %v", err)
		}
	})
	t.Run("group-writable program is not started", func(t *testing.T) {
		b, err := os.ReadFile(helperExe)
		if err != nil {
			t.Fatal(err)
		}
		man := helperManifest(t, "p", "good")
		man.Command = filepath.Join(man.Dir, "plugin")
		if err := os.WriteFile(man.Command, b, 0o700); err != nil { //nolint:gosec // an executable
			t.Fatal(err)
		}
		if err := os.Chmod(man.Command, 0o775); err != nil { //nolint:gosec // the point of the test
			t.Fatal(err)
		}
		m, audit := startManager(t, policy.Config{}, man)
		waitFor(t, "a refused start", func() bool { return strings.Contains(status(m, "p").Error, "run chmod go-w") })
		if starts := audit.find(string(policy.PluginStart), policy.Allow); len(starts) != 0 {
			t.Errorf("started: %+v", starts)
		}
		// Fixed on disk, it starts on the next attempt: checked at every start.
		if err := os.Chmod(man.Command, 0o755); err != nil { //nolint:gosec // an executable
			t.Fatal(err)
		}
		waitFor(t, "the plugin", func() bool { return status(m, "p").State == StateRunning })
	})
	t.Run("group-writable script in args", func(t *testing.T) {
		man := helperManifest(t, "p", "good")
		script := filepath.Join(man.Dir, "plugin.py")
		if err := os.WriteFile(script, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(script, 0o664); err != nil { //nolint:gosec // the point of the test
			t.Fatal(err)
		}
		p := &plugin{m: Manifest{Name: "p", Dir: man.Dir, Args: []string{"plugin.py"}}}
		_, _, err := p.trustedProgram(man.Command)
		if err == nil || !strings.Contains(err.Error(), "plugin.py is writable") {
			t.Fatalf("err = %v", err)
		}
	})
}
