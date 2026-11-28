// SPDX-License-Identifier: AGPL-3.0-only

package plugins

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/policy"
)

var (
	wasmBuildsMu sync.Mutex
	wasmBuilds   = map[string]string{}
)

// buildWasm builds the Go package pkg, relative to this directory, with
// GOOS=wasip1 GOARCH=wasm, once per test binary, and copies the module into
// a new directory the hub trusts. It returns the module's path there.
func buildWasm(t *testing.T, pkg string) string {
	t.Helper()
	wasmBuildsMu.Lock()
	built, ok := wasmBuilds[pkg]
	if !ok {
		built = filepath.Join(filepath.Dir(helperExe), strings.NewReplacer("/", "_", ".", "_").Replace(pkg)+".wasm")
		cmd := exec.Command("go", "build", "-o", built, pkg)
		cmd.Env = append(os.Environ(), "GOOS=wasip1", "GOARCH=wasm", "CGO_ENABLED=0")
		if out, err := cmd.CombinedOutput(); err != nil {
			wasmBuildsMu.Unlock()
			t.Fatalf("build %s: %v\n%s", pkg, err, out)
		}
		wasmBuilds[pkg] = built
	}
	wasmBuildsMu.Unlock()
	b, err := os.ReadFile(built)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(tempDir(t), "plugin.wasm")
	if err := os.WriteFile(path, b, 0o600); err != nil { //nolint:gosec // a test's temporary directory
		t.Fatal(err)
	}
	return path
}

// guestManifest is a manifest of the test guest module.
func guestManifest(t *testing.T, name string) Manifest {
	t.Helper()
	path := buildWasm(t, "./testdata/wasmguest")
	m := Manifest{
		Protocol: 1, Name: name, Version: "test", Runtime: RuntimeWasm, Command: "./plugin.wasm",
		Args: []string{"a1", "a2"}, Memory: 32, Dir: filepath.Dir(path),
		Capabilities: []string{CapDiscover, CapState, CapCommand},
	}
	for _, c := range []string{"echo", "files", "http", "raw", "flood", "spin", "alloc", "sleep", "tick"} {
		m.Commands = append(m.Commands, CommandSpec{Name: c, Class: policy.Read})
	}
	return m
}

func run(t *testing.T, m *Manager, plugin, command string, args any) (CommandResult, error) {
	t.Helper()
	req := CommandRequest{Command: command, Device: "d"}
	if args != nil {
		b, _ := json.Marshal(args)
		req.Args = b
	}
	return m.Command(t.Context(), policy.ActorWeb, "x", plugin, req)
}

func TestWasmPluginRoundTrip(t *testing.T) {
	man := guestManifest(t, "guest")
	m, audit := startManager(t, policy.Config{}, man)
	waitFor(t, "the guest's devices", func() bool { return entityState(m, "guest", "d", "e") == "0" })
	res, err := run(t, m, "guest", "echo", map[string]any{"k": "v"})
	if err != nil {
		t.Fatal(err)
	}
	// Its args, and no environment but HEARTH_PLUGIN.
	if want := `d {"k":"v"} [a1 a2] env=["HEARTH_PLUGIN=guest"]`; res.Output != want {
		t.Errorf("output = %q, want %q", res.Output, want)
	}
	waitFor(t, "the pushed state", func() bool { return entityState(m, "guest", "d", "e") == "42" })
	// No filesystem.
	if res, err := run(t, m, "guest", "files", nil); err != nil || res.Output == "<nil>" {
		t.Errorf("files = %q, %v: want an error", res.Output, err)
	}
	// Timers run while the module waits on stdin.
	if _, err := run(t, m, "guest", "tick", nil); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "ticks", func() bool {
		s := entityState(m, "guest", "d", "e")
		return s != "42" && s != "0" && s != "1"
	})

	b, _ := os.ReadFile(filepath.Join(man.Dir, "plugin.wasm"))
	sum := sha256.Sum256(b)
	starts := audit.find(string(policy.PluginStart), policy.Allow)
	if len(starts) == 0 {
		t.Fatal("no plugin.start entry")
	}
	var d map[string]any
	if err := json.Unmarshal(starts[0].Detail, &d); err != nil {
		t.Fatal(err)
	}
	if d["runtime"] != "wasm" || d["sha256"] != hex.EncodeToString(sum[:]) || d["digest"] != wasmDigest(man, hex.EncodeToString(sum[:])) {
		t.Errorf("plugin.start detail = %v", d)
	}
	if s := status(m, "guest"); s.Restarts != 0 {
		t.Errorf("restarted: %+v", s)
	}
}

func TestWasmLimitsStopThePlugin(t *testing.T) {
	tests := []struct{ command, wantErr, wantStderr string }{
		{"spin", "command spin: no reply within", ""},
		{"sleep", "command sleep: no reply within", ""},
		// Go's runtime dies of it, past the manifest's 32 MiB, with a
		// goroutine dump.
		{"alloc", "", "runtime."},
		{"flood", "more than 10 host calls a second", ""},
	}
	for _, tt := range tests {
		t.Run(tt.command, func(t *testing.T) {
			m, _ := startManager(t, policy.Config{}, guestManifest(t, "guest"))
			waitFor(t, "the guest", func() bool { return status(m, "guest").State == StateRunning })
			start := time.Now()
			if _, err := run(t, m, "guest", tt.command, nil); err == nil {
				t.Fatal("the command succeeded")
			}
			var last Status
			waitFor(t, "a restart", func() bool {
				last = status(m, "guest")
				return last.Restarts >= 1
			})
			if !strings.Contains(last.Error, tt.wantErr) {
				t.Errorf("error = %q, want %q", last.Error, tt.wantErr)
			}
			if !strings.Contains(strings.Join(last.Stderr, "\n"), tt.wantStderr) {
				t.Errorf("stderr = %q, want %q", last.Stderr, tt.wantStderr)
			}
			if d := time.Since(start); d > 10*time.Second {
				t.Errorf("stopped after %s", d)
			}
			// It comes back, and works.
			waitFor(t, "the guest again", func() bool { return status(m, "guest").State == StateRunning })
			if _, err := run(t, m, "guest", "echo", nil); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestWasmMemoryIsCappedPerPlugin(t *testing.T) {
	// The same module, under two caps: compiled once, capped each by its
	// own manifest.
	small, large := guestManifest(t, "small"), guestManifest(t, "large")
	small.Memory, large.Memory = 32, 256
	m, _ := startManager(t, policy.Config{}, small, large)
	waitFor(t, "the guests", func() bool {
		return status(m, "small").State == StateRunning && status(m, "large").State == StateRunning
	})
	if res, err := run(t, m, "large", "alloc", map[string]int{"mib": 48}); err != nil || res.Output != "allocated" {
		t.Fatalf("48 MiB under 256 = %q, %v", res.Output, err)
	}
	if _, err := run(t, m, "small", "alloc", map[string]int{"mib": 48}); err == nil {
		t.Fatal("48 MiB under 32 succeeded")
	}
	waitFor(t, "the small one's restart", func() bool { return status(m, "small").Restarts >= 1 })
	if s := status(m, "large"); s.Restarts != 0 {
		t.Errorf("the large one restarted: %+v", s)
	}
}

func TestWasmHostCalls(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "http://198.51.100.1/", http.StatusFound)
			return
		}
		_, _ = w.Write([]byte("hi " + r.URL.Query().Get("q"))) //nolint:gosec // a test server
	}))
	defer srv.Close()
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())

	granted := guestManifest(t, "granted")
	granted.Host.HTTP = &HTTPGrant{Allow: []string{"127.0.0.1:" + port}}
	ungranted := guestManifest(t, "ungranted")
	m, audit := startManager(t, policy.Config{}, granted, ungranted)
	waitFor(t, "the guests", func() bool {
		return status(m, "granted").State == StateRunning && status(m, "ungranted").State == StateRunning
	})

	res, err := run(t, m, "granted", "http", map[string]string{"url": srv.URL + "/?q=x"})
	if err != nil || res.Output != "200 hi x" {
		t.Fatalf("allowed http = %q, %v", res.Output, err)
	}
	// A redirect is a response: it is not followed elsewhere.
	if res, err := run(t, m, "granted", "http", map[string]string{"url": srv.URL + "/redirect"}); err != nil || !strings.HasPrefix(res.Output, "302") {
		t.Errorf("redirect = %q, %v", res.Output, err)
	}
	if allowed := audit.find(string(policy.PluginHostCall), policy.Allow); len(allowed) == 0 || allowed[0].Target != "granted/http" {
		t.Errorf("allowed entries = %+v", allowed)
	}

	denied := []struct {
		plugin, command string
		args            map[string]string
		target, reason  string
	}{
		{"granted", "http", map[string]string{"url": "http://localhost:" + port + "/"}, "granted/http", "does not allow http to localhost:" + port},
		{"granted", "http", map[string]string{"url": "http://127.0.0.1:1/"}, "granted/http", "does not allow http to 127.0.0.1:1"},
		{"ungranted", "http", map[string]string{"url": srv.URL}, "ungranted/http", "grants no http host function"},
		{"granted", "raw", map[string]string{"name": "exec"}, "granted/exec", `no host function "exec"`},
		// A malformed request ({}) of a function not granted is denied all the same.
		{"ungranted", "raw", map[string]string{"name": "http"}, "ungranted/http", "grants no http host function"},
	}
	for _, d := range denied {
		res, err := run(t, m, d.plugin, d.command, d.args)
		if err == nil && !strings.Contains(res.Output, "denied") {
			t.Errorf("%s %v = %q: want it denied", d.plugin, d.args, res.Output)
		}
		if err != nil && !strings.Contains(err.Error(), "denied") {
			t.Errorf("%s %v: err = %v, want denied", d.plugin, d.args, err)
		}
		found := false
		for _, e := range audit.find(string(policy.PluginHostCall), policy.Deny) {
			if e.Target == d.target && strings.Contains(e.Result, d.reason) {
				found = true
			}
		}
		if !found {
			t.Errorf("no denied %s entry with %q: %+v", d.target, d.reason, audit.find(string(policy.PluginHostCall), policy.Deny))
		}
	}
	// Nothing of a URL but its host goes into the audit log.
	for _, e := range append(audit.find(string(policy.PluginHostCall), policy.Allow), audit.find(string(policy.PluginHostCall), policy.Deny)...) {
		if strings.Contains(string(e.Detail), "q=x") || strings.Contains(string(e.Detail), "/redirect") {
			t.Errorf("detail holds the URL: %s", e.Detail)
		}
	}
	for _, p := range []string{"granted", "ungranted"} {
		if s := status(m, p); s.Restarts != 0 {
			t.Errorf("%s restarted: %+v", p, s)
		}
	}
}

func TestWasmPinMismatchIsRefused(t *testing.T) {
	man := guestManifest(t, "pinned")
	b, _ := os.ReadFile(filepath.Join(man.Dir, "plugin.wasm"))
	sum := sha256.Sum256(b)
	good := man
	good.Name, good.SHA256 = "good", hex.EncodeToString(sum[:])
	man.SHA256 = strings.Repeat("0", 64)
	m, audit := startManager(t, policy.Config{}, man, good)
	var last Status
	waitFor(t, "a refused start", func() bool {
		last = status(m, "pinned")
		return last.Restarts >= 1
	})
	if !strings.Contains(last.Error, ErrPinMismatch.Error()) {
		t.Errorf("error = %q", last.Error)
	}
	waitFor(t, "the good one", func() bool { return status(m, "good").State == StateRunning })
	for _, e := range audit.find(string(policy.PluginStart), policy.Allow) {
		if e.Target == "pinned" {
			t.Errorf("the pinned plugin started: %+v", e)
		}
	}
	// A module changed on disk after the manifest pinned it is refused at
	// its next start.
	if err := os.WriteFile(filepath.Join(good.Dir, "plugin.wasm"), append(b, 0), 0o600); err != nil { //nolint:gosec // a test's temporary directory
		t.Fatal(err)
	}
	if _, err := run(t, m, "good", "spin", nil); err == nil {
		t.Fatal("spin succeeded")
	}
	waitFor(t, "the refused restart", func() bool { return strings.Contains(status(m, "good").Error, ErrPinMismatch.Error()) })
}

func TestWasmManifest(t *testing.T) {
	base := func() Manifest {
		return Manifest{Protocol: 1, Name: "w", Runtime: RuntimeWasm, Command: "./w.wasm"}
	}
	tests := []struct {
		name    string
		edit    func(*Manifest)
		wantErr string
	}{
		{"ok", func(*Manifest) {}, ""},
		{"granted", func(m *Manifest) { m.Host.HTTP = &HTTPGrant{Allow: []string{"lamp.lan:80", "[::1]:8080"}} }, ""},
		{"bad runtime", func(m *Manifest) { m.Runtime = "docker" }, `runtime "docker"`},
		{"env", func(m *Manifest) { m.Env = map[string]string{"K": "v"} }, "env is not for a wasm plugin"},
		{"bare command", func(m *Manifest) { m.Command = "w.wasm" }, "module is a path"},
		{"memory", func(m *Manifest) { m.Memory = 2048 }, "memory: want 1-1024"},
		{"no port", func(m *Manifest) { m.Host.HTTP = &HTTPGrant{Allow: []string{"lamp.lan"}} }, "want host:port"},
		{"bad port", func(m *Manifest) { m.Host.HTTP = &HTTPGrant{Allow: []string{"lamp.lan:0"}} }, "invalid port"},
		{"empty grant", func(m *Manifest) { m.Host.HTTP = &HTTPGrant{} }, "want 1-32"},
		{"bad pin", func(m *Manifest) { m.SHA256 = "ABC" }, "sha256: want 64"},
		{"exec memory", func(m *Manifest) { m.Runtime, m.Command = "", "lamp"; m.Memory = 8 }, "memory is for a wasm plugin"},
		{"exec host", func(m *Manifest) {
			m.Runtime, m.Command = RuntimeExec, "lamp"
			m.Host.HTTP = &HTTPGrant{Allow: []string{"a:1"}}
		}, "host functions are for a wasm plugin"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := base()
			tt.edit(&m)
			err := m.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("err = %v, want %q", err, tt.wantErr)
			}
		})
	}
	// A device plugin is an exec plugin.
	if _, err := ParseManifest([]byte("protocol: 1\nname: w\nruntime: wasm\ncommand: ./w.wasm\n")); err == nil || !strings.Contains(err.Error(), "hub only") {
		t.Errorf("ParseManifest(wasm) = %v", err)
	}
	if _, err := RunOnce(t.Context(), base(), "", CommandRequest{Command: "x"}, Options{}); err == nil || !strings.Contains(err.Error(), "hub only") {
		t.Errorf("RunOnce(wasm) = %v", err)
	}
}

func TestExecPinMismatchIsRefused(t *testing.T) {
	man := helperManifest(t, "pinned", "good")
	man.SHA256 = strings.Repeat("0", 64)
	m, _ := startManager(t, policy.Config{}, man)
	waitFor(t, "a refused start", func() bool { return strings.Contains(status(m, "pinned").Error, ErrPinMismatch.Error()) })
}

func TestGoWasmExamplePlugin(t *testing.T) {
	var calls []string
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls = append(calls, r.URL.RawQuery)
		mu.Unlock()
	}))
	defer srv.Close()

	// The same source, as a WASM plugin and as an exec plugin.
	wasmDir := copyExample(t, "go-wasm-lamp", "plugin.yaml")
	if err := os.Rename(buildWasm(t, "../../examples/plugins/go-wasm-lamp"), filepath.Join(wasmDir, "lamp.wasm")); err != nil {
		t.Fatal(err)
	}
	wasmMan, err := LoadManifest(filepath.Join(wasmDir, "plugin.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	wasmMan.Args = []string{srv.URL + "/relay/0"}
	wasmMan.Host.HTTP = &HTTPGrant{Allow: []string{srv.Listener.Addr().String()}}

	execMan := wasmMan
	execMan.Name, execMan.Runtime, execMan.Command, execMan.Host, execMan.Memory = "go-wasm-lamp", "", "./lamp", HostGrants{}, 0
	execMan.Dir = tempDir(t)
	build := exec.Command("go", "build", "-o", filepath.Join(execMan.Dir, "lamp"), "../../examples/plugins/go-wasm-lamp") //nolint:gosec // a fixed build of the example
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	if err := os.Chmod(filepath.Join(execMan.Dir, "lamp"), 0o700); err != nil { //nolint:gosec // an executable
		t.Fatal(err)
	}

	for _, man := range []Manifest{wasmMan, execMan} {
		t.Run(man.Runtime, func(t *testing.T) {
			m, audit := startManager(t, policy.Config{}, man)
			waitFor(t, "the lamp", func() bool { return entityState(m, man.Name, "lamp", "on") == "false" })
			res, err := m.Command(t.Context(), policy.ActorWeb, "x", man.Name, CommandRequest{Command: "turn_on", Device: "lamp"})
			if err != nil {
				t.Fatal(err)
			}
			if res.Output != "lamp is on" {
				t.Errorf("output = %q", res.Output)
			}
			waitFor(t, "the lamp's state", func() bool { return entityState(m, man.Name, "lamp", "on") == "true" })
			mu.Lock()
			if len(calls) == 0 || calls[len(calls)-1] != "turn=on" {
				t.Errorf("relay calls = %q", calls)
			}
			mu.Unlock()
			if man.IsWasm() {
				if e := audit.find(string(policy.PluginHostCall), policy.Allow); len(e) != 2 {
					t.Errorf("host call entries = %+v", e)
				}
			}
		})
	}
}

// TestRustExamplePlugin builds examples/plugins/rust-lamp when a Rust
// toolchain with the wasm32-wasip1 target is there, and runs it. Or it runs
// the module HEARTH_TEST_RUST_WASM names, built elsewhere (such as in a
// rust container).
func TestRustExamplePlugin(t *testing.T) {
	module := os.Getenv("HEARTH_TEST_RUST_WASM")
	if module == "" {
		module = buildRustExample(t)
	}
	dir := copyExample(t, "rust-lamp", "plugin.yaml")
	b, err := os.ReadFile(module) //nolint:gosec // the test's build
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "lamp.wasm"), b, 0o600); err != nil { //nolint:gosec // a test's temporary directory
		t.Fatal(err)
	}
	man, err := LoadManifest(filepath.Join(dir, "plugin.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	m, _ := startManager(t, policy.Config{}, man)
	waitFor(t, "the lamp", func() bool { return entityState(m, "rust-lamp", "lamp", "on") == "false" })
	res, err := m.Command(t.Context(), policy.ActorWeb, "x", "rust-lamp", CommandRequest{Command: "turn_on", Device: "lamp"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Output != "lamp is on" {
		t.Errorf("output = %q", res.Output)
	}
	waitFor(t, "the lamp's state", func() bool { return entityState(m, "rust-lamp", "lamp", "on") == "true" })
	if _, err := m.Command(t.Context(), policy.ActorWeb, "x", "rust-lamp", CommandRequest{Command: "nope"}); !errors.Is(err, policy.ErrDenied) {
		t.Errorf("undeclared command: %v", err)
	}
}

// buildRustExample builds examples/plugins/rust-lamp with cargo, or skips
// the test without a Rust toolchain for wasm32-wasip1.
func buildRustExample(t *testing.T) string {
	t.Helper()
	cargo, err := exec.LookPath("cargo")
	if err != nil {
		t.Skip("no cargo")
	}
	if out, err := exec.Command("rustc", "--print", "target-libdir", "--target", "wasm32-wasip1").Output(); err != nil ||
		!dirExists(strings.TrimSpace(string(out))) {
		t.Skip("no wasm32-wasip1 target (rustup target add wasm32-wasip1)")
	}
	target := filepath.Join(filepath.Dir(helperExe), "rust-target")
	build := exec.Command(cargo, "build", "--release", "--target", "wasm32-wasip1", "--target-dir", target)
	build.Dir = filepath.Join("..", "..", "examples", "plugins", "rust-lamp")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("cargo build: %v\n%s", err, out)
	}
	return filepath.Join(target, "wasm32-wasip1", "release", "rust-lamp.wasm")
}

func dirExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}
