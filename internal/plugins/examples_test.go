// SPDX-License-Identifier: AGPL-3.0-only

package plugins

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/gvart/hearth/internal/policy"
)

// copyExample copies files of examples/plugins/<name> into a new directory,
// 0644, so that the test does not depend on the checkout's modes.
func copyExample(t *testing.T, name string, files ...string) string {
	t.Helper()
	dir := t.TempDir()
	for _, f := range files {
		b, err := os.ReadFile(filepath.Join("..", "..", "examples", "plugins", name, f))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, f), b, 0o644); err != nil { //nolint:gosec // a test's copy
			t.Fatal(err)
		}
	}
	return dir
}

func entityState(m *Manager, plugin, device, entity string) string {
	for _, d := range status(m, plugin).Devices {
		if d.ID != device {
			continue
		}
		for _, e := range d.Entities {
			if e.ID == entity {
				return string(e.State)
			}
		}
	}
	return ""
}

func TestGoExamplePlugin(t *testing.T) {
	dir := copyExample(t, "go-lamp", "plugin.yaml")
	build := exec.Command("go", "build", "-o", filepath.Join(dir, "lamp"), "../../examples/plugins/go-lamp") //nolint:gosec // a fixed build of the example
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	man, err := LoadManifest(filepath.Join(dir, "plugin.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	m, audit := startManager(t, policy.Config{}, man)
	waitFor(t, "the lamp", func() bool { return entityState(m, "go-lamp", "lamp", "on") == "false" })
	res, err := m.Command(t.Context(), policy.ActorWeb, "x", "go-lamp", CommandRequest{Command: "turn_on", Device: "lamp"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Output != "lamp is on" {
		t.Errorf("output = %q", res.Output)
	}
	waitFor(t, "the lamp's state", func() bool { return entityState(m, "go-lamp", "lamp", "on") == "true" })
	if e := audit.find(string(policy.PluginCommandSafe), policy.Allow); len(e) != 2 {
		t.Errorf("entries = %+v", e)
	}
}

func TestPythonExamplePlugin(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not installed")
	}
	dir := copyExample(t, "python-load", "plugin.yaml", "plugin.py")
	man, err := LoadManifest(filepath.Join(dir, "plugin.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	m, audit := startManager(t, policy.Config{}, man)
	waitFor(t, "the host's load", func() bool { return entityState(m, "python-load", "host", "load1") != "" })
	if s := status(m, "python-load"); len(s.Devices) != 1 || len(s.Devices[0].Entities) != 3 {
		t.Fatalf("devices = %+v", s.Devices)
	}
	res, err := m.Command(t.Context(), policy.ActorWeb, "x", "python-load", CommandRequest{Command: "refresh"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Output != "refreshed" {
		t.Errorf("output = %q", res.Output)
	}
	// A read that succeeds writes one entry.
	if e := audit.find(string(policy.PluginCommandRead), policy.Allow); len(e) != 1 {
		t.Errorf("entries = %+v", e)
	}
}
