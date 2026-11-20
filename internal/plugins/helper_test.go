// SPDX-License-Identifier: AGPL-3.0-only

package plugins

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

// helperArg makes the test binary run as a plugin, in the mode after it.
const helperArg = "hearth-test-plugin"

// helperExe is a copy of the test binary the hub trusts whatever the umask:
// go test may build it in a group-writable directory.
var helperExe string

func TestMain(m *testing.M) {
	if len(os.Args) == 3 && os.Args[1] == helperArg {
		os.Exit(runHelper(os.Args[2]))
	}
	os.Exit(runTests(m))
}

func runTests(m *testing.M) int {
	dir, err := os.MkdirTemp("", "hearth-plugins-test") // 0700
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer func() { _ = os.RemoveAll(dir) }()
	exe, err := os.Executable()
	if err == nil {
		var b []byte
		if b, err = os.ReadFile(exe); err == nil {
			helperExe = filepath.Join(dir, "plugin")
			err = os.WriteFile(helperExe, b, 0o700) //nolint:gosec // an executable
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return m.Run()
}

// tempDir is t.TempDir, owner-only whatever the umask, as the hub wants a
// plugin's directory.
func tempDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil { //nolint:gosec // a directory
		t.Fatal(err)
	}
	return dir
}

// runHelper is a plugin that behaves well, or misbehaves as mode says.
func runHelper(mode string) int {
	name := os.Getenv("HEARTH_PLUGIN")
	out := bufio.NewWriter(os.Stdout)
	var outMu sync.Mutex
	send := func(m map[string]any) {
		b, _ := json.Marshal(m)
		outMu.Lock()
		defer outMu.Unlock()
		_, _ = out.Write(append(b, '\n'))
		_ = out.Flush()
	}
	in := bufio.NewScanner(os.Stdin)
	if !in.Scan() || mode == "silent" {
		time.Sleep(time.Hour)
	}
	if mode == "badhello" {
		name = "someone-else"
	}
	send(map[string]any{"type": "hello", "protocol": 1, "name": name, "version": "test"})
	switch mode {
	case "crash":
		fmt.Fprintln(os.Stderr, "about to crash")
		return 3
	case "hang":
		time.Sleep(time.Hour)
	case "junk":
		_, _ = out.WriteString("this is not json\n")
		_ = out.Flush()
		time.Sleep(time.Hour)
	case "huge":
		_, _ = out.WriteString(`{"type":"pong","id":"` + strings.Repeat("x", 2<<20) + "\"}\n")
		_ = out.Flush()
		time.Sleep(time.Hour)
	case "flood":
		for {
			_, _ = out.WriteString(`{"type":"pong","id":"0"}` + "\n")
		}
	}
	commands := 0
	for in.Scan() {
		var m struct {
			Type, ID, Command, Device string
		}
		if json.Unmarshal(in.Bytes(), &m) != nil {
			return 2
		}
		switch m.Type {
		case "ping":
			if mode == "nopong" {
				continue
			}
			send(map[string]any{"type": "pong", "id": m.ID})
		case "discover":
			send(map[string]any{"type": "devices", "id": m.ID, "devices": []any{map[string]any{
				"id": "lamp", "name": "Lamp", "kind": "light",
				"entities": []any{map[string]any{"id": "commands", "name": "Commands run", "state": commands}},
			}}})
		case "command":
			commands++
			send(map[string]any{"type": "state", "device": "lamp", "entity": "commands", "state": commands})
			switch m.Command {
			case "slow":
				// One message at a time: no pong while it sleeps.
				time.Sleep(15 * time.Second)
			case "async":
				go func(id string) {
					time.Sleep(300 * time.Millisecond)
					send(map[string]any{"type": "result", "id": id, "ok": true})
				}(m.ID)
				continue
			}
			if m.Command == "fail" {
				send(map[string]any{"type": "result", "id": m.ID, "ok": false, "error": "boom"})
				continue
			}
			send(map[string]any{"type": "result", "id": m.ID, "ok": true, "output": m.Command + " " + m.Device})
		}
	}
	return 0
}

// helperManifest is a manifest that runs the test binary in mode.
func helperManifest(t *testing.T, name, mode string) Manifest {
	t.Helper()
	return Manifest{
		Protocol: 1, Name: name, Version: "test", Command: helperExe, Args: []string{helperArg, mode},
		Capabilities: []string{CapDiscover, CapState, CapCommand},
		Commands: []CommandSpec{
			{Name: "toggle", Class: policy.Safe},
			{Name: "fail", Class: policy.Read},
			{Name: "wipe", Class: policy.Dangerous},
			{Name: "slow", Class: policy.Read},
			{Name: "async", Class: policy.Read},
		},
		Dir: tempDir(t),
	}
}

// fastOptions make failures and restarts quick.
var fastOptions = Options{
	BackoffMin: 10 * time.Millisecond, BackoffMax: 50 * time.Millisecond,
	StartTimeout: 5 * time.Second, PingEvery: 50 * time.Millisecond, ReplyTimeout: 500 * time.Millisecond,
	CommandTimeout: 2 * time.Second, MaxLine: 64 << 10, MaxRate: 100,
}

// memAudit is an in-memory audit log.
type memAudit struct {
	mu      sync.Mutex
	entries []store.AuditEntry
}

func (a *memAudit) Append(_ context.Context, e store.AuditEntry) (int64, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.entries = append(a.entries, e)
	return int64(len(a.entries)), nil
}

func (a *memAudit) find(action, decision string) []store.AuditEntry {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []store.AuditEntry
	for _, e := range a.entries {
		if e.Action == action && e.Decision == decision {
			out = append(out, e)
		}
	}
	return out
}

// startManager runs a manager of manifests with cfg's policy until the test
// ends, and checks that Run is still running then.
func startManager(t *testing.T, cfg policy.Config, manifests ...Manifest) (*Manager, *memAudit) {
	t.Helper()
	audit := &memAudit{}
	m, err := New(Config{Manifests: manifests, Policy: policy.NewWithConfig(audit, nil, cfg), Options: fastOptions})
	if err != nil {
		t.Fatal(err)
	}
	// Not t.Context(): it is cancelled before cleanups run, which would end
	// Run before the check below.
	ctx, cancel := context.WithCancel(context.WithoutCancel(t.Context()))
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = m.Run(ctx)
	}()
	t.Cleanup(func() {
		select {
		case <-done:
			t.Error("Run returned before the test ended")
		default:
		}
		cancel()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("Run did not return after cancel")
		}
	})
	return m, audit
}

func status(m *Manager, name string) Status {
	for _, s := range m.Plugins() {
		if s.Name == name {
			return s
		}
	}
	return Status{}
}

// waitFor polls cond until it holds or fails the test after 30s.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// commandsRun is the state the helper plugin keeps of how many commands it
// got.
func commandsRun(m *Manager, name string) string {
	for _, d := range status(m, name).Devices {
		for _, e := range d.Entities {
			if e.ID == "commands" {
				return string(e.State)
			}
		}
	}
	return ""
}
