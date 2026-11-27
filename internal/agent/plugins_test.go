// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/gvart/hearth/internal/plugins"
	"github.com/gvart/hearth/internal/policy"
	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
)

func sum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// blobServer serves programs by SHA-256 at plugins.BlobPath, as the hub
// does, and counts the fetches.
type blobServer struct {
	*httptest.Server
	blobs   map[string]io.Reader
	fetches atomic.Int32
}

func newBlobServer(t *testing.T, programs ...[]byte) *blobServer {
	t.Helper()
	s := &blobServer{blobs: map[string]io.Reader{}}
	for _, p := range programs {
		s.blobs[sum(p)] = bytes.NewReader(p)
	}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.fetches.Add(1)
		b, ok := s.blobs[strings.TrimPrefix(r.URL.Path, plugins.BlobPath)]
		if !ok {
			http.NotFound(w, r)
			return
		}
		if rs, ok := b.(io.Seeker); ok {
			_, _ = rs.Seek(0, io.SeekStart)
		}
		_, _ = io.Copy(w, b)
	}))
	t.Cleanup(s.Close)
	return s
}

func testHost(t *testing.T, c *Ceiling) *pluginHost {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil { //nolint:gosec // a data dir
		t.Fatal(err)
	}
	return newPluginHost(dir, slog.New(slog.DiscardHandler), func() Ceiling { return *c })
}

func binaryOf(name string, program []byte, commands ...*agentv1.PluginCommandSpec) *agentv1.PluginBinary {
	return &agentv1.PluginBinary{
		Name: name, Version: "1.0", Os: runtime.GOOS, Arch: runtime.GOARCH, Sha256: sum(program), Size: uint64(len(program)),
		Capabilities: []string{"command"}, Commands: commands,
	}
}

func syncOnce(t *testing.T, h *pluginHost, srv *blobServer, bins ...*agentv1.PluginBinary) *agentv1.PluginStatus {
	t.Helper()
	st := h.sync(t.Context(), srv.Client(), srv.URL, &agentv1.PluginConfig{Plugins: bins}, h.next())
	if st == nil {
		t.Fatal("sync skipped")
	}
	return st
}

func TestPluginSync(t *testing.T) {
	program := []byte("#!/bin/sh\nexit 0\n")
	allow := &Ceiling{Plugins: []PluginGrant{{Name: "lamp", Class: policy.Safe}}}

	t.Run("installs, once", func(t *testing.T) {
		h, srv := testHost(t, allow), newBlobServer(t, program)
		b := binaryOf("lamp", program)
		st := syncOnce(t, h, srv, b)
		if len(st.GetPlugins()) != 1 || st.GetPlugins()[0].GetError() != "" || st.GetPlugins()[0].GetSha256() != b.GetSha256() {
			t.Fatalf("status = %v", st)
		}
		if st.GetOs() != runtime.GOOS || st.GetArch() != runtime.GOARCH {
			t.Errorf("platform = %s/%s", st.GetOs(), st.GetArch())
		}
		path := filepath.Join(h.dir, "lamp", b.GetSha256())
		fi, err := os.Stat(path)
		if err != nil || fi.Mode().Perm() != 0o700 {
			t.Fatalf("program: %v %v", fi, err)
		}
		if di, err := os.Stat(h.dir); err != nil || di.Mode().Perm() != 0o700 {
			t.Fatalf("plugins dir: %v %v", di, err)
		}
		syncOnce(t, h, srv, b)
		if n := srv.fetches.Load(); n != 1 {
			t.Errorf("fetched %d times, want once", n)
		}
		// Removed from the config, it is removed from the disk.
		syncOnce(t, h, srv)
		if _, err := os.Stat(filepath.Join(h.dir, "lamp")); !os.IsNotExist(err) {
			t.Errorf("plugin left behind: %v", err)
		}
	})

	tests := []struct {
		name    string
		ceiling *Ceiling
		serve   []byte // what the hub serves
		bin     func(b *agentv1.PluginBinary)
		want    string
		fetched bool
	}{
		{name: "wrong hash", ceiling: allow, serve: []byte("#!/bin/sh\necho evil\n"), want: "SHA-256", fetched: true},
		{name: "not in the ceiling", ceiling: &Ceiling{Plugins: []PluginGrant{{Name: "other", Class: policy.Dangerous}}}, want: "not allowed"},
		{name: "no ceiling", ceiling: &Ceiling{}, want: "not allowed"},
		{name: "declared oversize", ceiling: allow, bin: func(b *agentv1.PluginBinary) { b.Size = plugins.MaxProgramSize + 1 }, want: "larger than"},
		{name: "wrong platform only", ceiling: allow, bin: func(b *agentv1.PluginBinary) { b.Os = "plan9" }, want: "no program uploaded for this device's platform"},
		{name: "path in name", ceiling: &Ceiling{Plugins: []PluginGrant{{Name: "..", Class: policy.Read}}}, bin: func(b *agentv1.PluginBinary) { b.Name = ".." }, want: "invalid plugin name"},
		{name: "bad sha", ceiling: allow, bin: func(b *agentv1.PluginBinary) { b.Sha256 = "../../etc/passwd" }, want: "invalid SHA-256"},
		{name: "bad manifest", ceiling: allow, bin: func(b *agentv1.PluginBinary) {
			b.Commands = []*agentv1.PluginCommandSpec{{Name: "x", Class: "root"}}
		}, want: "manifest"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := testHost(t, tt.ceiling)
			srv := newBlobServer(t, program)
			b := binaryOf("lamp", program)
			if tt.serve != nil {
				srv.blobs[b.GetSha256()] = bytes.NewReader(tt.serve)
			}
			if tt.bin != nil {
				tt.bin(b)
			}
			st := syncOnce(t, h, srv, b)
			if len(st.GetPlugins()) != 1 || !strings.Contains(st.GetPlugins()[0].GetError(), tt.want) || st.GetPlugins()[0].GetSha256() != "" {
				t.Fatalf("status = %v, want an error with %q", st, tt.want)
			}
			if got := srv.fetches.Load() > 0; got != tt.fetched {
				t.Errorf("fetched = %v, want %v", got, tt.fetched)
			}
			entries, _ := os.ReadDir(filepath.Join(h.dir, "lamp"))
			if len(entries) != 0 {
				t.Errorf("left on disk: %v", entries)
			}
		})
	}

	t.Run("served oversize", func(t *testing.T) {
		h := testHost(t, allow)
		srv := newBlobServer(t, program)
		b := binaryOf("lamp", program)
		srv.blobs[b.GetSha256()] = io.LimitReader(zeros{}, plugins.MaxProgramSize+1)
		st := syncOnce(t, h, srv, b)
		if !strings.Contains(st.GetPlugins()[0].GetError(), "larger than") {
			t.Fatalf("status = %v", st)
		}
		entries, _ := os.ReadDir(filepath.Join(h.dir, "lamp"))
		if len(entries) != 0 {
			t.Errorf("left on disk: %v", entries)
		}
	})

	t.Run("wrong platform", func(t *testing.T) {
		h := testHost(t, allow)
		b := binaryOf("lamp", program)
		b.Arch = "mips"
		if _, err := h.install(t.Context(), http.DefaultClient, "http://127.0.0.1:1", allow.proto(), map[string]pluginPin{}, b); err == nil ||
			!strings.Contains(err.Error(), "not this device's") {
			t.Fatalf("install = %v", err)
		}
	})

	t.Run("local ceiling ignores the hub's grant", func(t *testing.T) {
		cs := newCeilings(Ceiling{}, Ceiling{Plugins: []PluginGrant{{Name: "lamp", Class: policy.Dangerous}}}, 1, true)
		h := testHost(t, &Ceiling{})
		h.ceiling = cs.get
		srv := newBlobServer(t, program)
		st := syncOnce(t, h, srv, binaryOf("lamp", program))
		if !strings.Contains(st.GetPlugins()[0].GetError(), "not allowed") || srv.fetches.Load() != 0 {
			t.Fatalf("status = %v, fetches %d", st, srv.fetches.Load())
		}
	})
}

type zeros struct{}

func (zeros) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

// buildLamp builds the go-lamp example plugin.
func buildLamp(t *testing.T) []byte {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "lamp")
	build := exec.Command("go", "build", "-o", bin, "../../examples/plugins/go-lamp")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	b, err := os.ReadFile(bin)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestPluginCommand(t *testing.T) {
	lamp := buildLamp(t)
	ceiling := &Ceiling{Plugins: []PluginGrant{{Name: "go-lamp", Class: policy.Safe}}}
	h, srv := testHost(t, ceiling), newBlobServer(t, lamp)
	b := binaryOf("go-lamp", lamp,
		&agentv1.PluginCommandSpec{Name: "turn_on", Class: "safe"},
		&agentv1.PluginCommandSpec{Name: "turn_off", Class: "dangerous"})
	b.Capabilities = []string{"discover", "state", "command"}
	if st := syncOnce(t, h, srv, b); st.GetPlugins()[0].GetError() != "" {
		t.Fatalf("status = %v", st)
	}
	run := func(req *agentv1.PluginCommand) *agentv1.PluginResult {
		t.Helper()
		if req.Plugin == "" {
			req.Plugin = "go-lamp"
		}
		if req.Sha256 == "" {
			req.Sha256 = b.GetSha256()
		}
		return h.command(t.Context(), req)
	}
	res := run(&agentv1.PluginCommand{Id: "1", Command: "turn_on", Device: "lamp"})
	if !res.GetOk() || res.GetOutput() != "lamp is on" || res.GetId() != "1" {
		t.Fatalf("result = %v", res)
	}

	denied := []struct {
		name string
		req  *agentv1.PluginCommand
		want string
	}{
		{"class above the ceiling", &agentv1.PluginCommand{Command: "turn_off"}, "above"},
		{"undeclared", &agentv1.PluginCommand{Command: "self_destruct"}, "declares no command"},
		{"not installed", &agentv1.PluginCommand{Plugin: "other", Command: "turn_on"}, "not installed"},
		{"another program", &agentv1.PluginCommand{Command: "turn_on", Sha256: strings.Repeat("0", 64)}, "asked for program"},
		{"bad args", &agentv1.PluginCommand{Command: "turn_on", ArgsJson: "[1]"}, "JSON object"},
	}
	for _, tt := range denied {
		t.Run(tt.name, func(t *testing.T) {
			res := run(tt.req)
			if res.GetOk() || !res.GetDenied() || !strings.Contains(res.GetError(), tt.want) {
				t.Fatalf("result = %v, want denied with %q", res, tt.want)
			}
		})
	}

	t.Run("ceiling lowered", func(t *testing.T) {
		*ceiling = Ceiling{Plugins: []PluginGrant{{Name: "go-lamp", Class: policy.Read}}}
		defer func() { *ceiling = Ceiling{Plugins: []PluginGrant{{Name: "go-lamp", Class: policy.Safe}}} }()
		if res := run(&agentv1.PluginCommand{Command: "turn_on"}); !res.GetDenied() {
			t.Fatalf("result = %v", res)
		}
	})

	t.Run("program changed on disk", func(t *testing.T) {
		path := filepath.Join(h.dir, "go-lamp", b.GetSha256())
		if err := os.WriteFile(path, []byte("#!/bin/sh\necho pwned\n"), 0o700); err != nil { //nolint:gosec // an executable
			t.Fatal(err)
		}
		res := run(&agentv1.PluginCommand{Command: "turn_on"})
		if !res.GetDenied() || !strings.Contains(res.GetError(), "SHA-256") {
			t.Fatalf("result = %v", res)
		}
	})
}

func TestParsePluginGrant(t *testing.T) {
	tests := []struct {
		in   string
		want PluginGrant
		ok   bool
	}{
		{"lamp", PluginGrant{"lamp", policy.Read, ""}, true},
		{"lamp:safe", PluginGrant{"lamp", policy.Safe, ""}, true},
		{"go-lamp:dangerous", PluginGrant{"go-lamp", policy.Dangerous, ""}, true},
		{"lamp@" + strings.Repeat("a", 64), PluginGrant{"lamp", policy.Read, strings.Repeat("a", 64)}, true},
		{"lamp:safe@" + strings.Repeat("a", 64), PluginGrant{"lamp", policy.Safe, strings.Repeat("a", 64)}, true},
		{"lamp@", PluginGrant{}, false},
		{"lamp@xyz", PluginGrant{}, false},
		{"lamp:root", PluginGrant{}, false},
		{"../x", PluginGrant{}, false},
		{":safe", PluginGrant{}, false},
	}
	for _, tt := range tests {
		g, err := ParsePluginGrant(tt.in)
		if tt.ok != (err == nil) || g != tt.want {
			t.Errorf("ParsePluginGrant(%q) = %v, %v", tt.in, g, err)
		}
	}
}

func TestUnionGrants(t *testing.T) {
	d := strings.Repeat("d", 64)
	a := []PluginGrant{{"b", policy.Read, ""}, {"a", policy.Dangerous, ""}}
	b := []PluginGrant{{"b", policy.Safe, ""}, {"c", policy.Read, ""}, {"a", policy.Read, ""}, {"a", policy.Read, d}}
	got := unionGrants(a, b)
	want := []PluginGrant{{"a", policy.Dangerous, ""}, {"a", policy.Read, d}, {"b", policy.Safe, ""}, {"c", policy.Read, ""}}
	if len(got) != len(want) {
		t.Fatalf("union = %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("union = %v, want %v", got, want)
		}
	}
}

// TestPluginCommandRelativeDataDir: an agent started with a relative
// --data-dir runs its plugins too.
func TestPluginCommandRelativeDataDir(t *testing.T) {
	lamp := buildLamp(t)
	t.Chdir(t.TempDir())
	if err := os.Mkdir("data", 0o700); err != nil {
		t.Fatal(err)
	}
	ceiling := &Ceiling{Plugins: []PluginGrant{{Name: "go-lamp", Class: policy.Safe}}}
	h := newPluginHost("data", slog.New(slog.DiscardHandler), func() Ceiling { return *ceiling })
	b := binaryOf("go-lamp", lamp, &agentv1.PluginCommandSpec{Name: "turn_on", Class: "safe"})
	b.Capabilities = []string{"discover", "state", "command"}
	if st := syncOnce(t, h, newBlobServer(t, lamp), b); st.GetPlugins()[0].GetError() != "" {
		t.Fatalf("status = %v", st)
	}
	res := h.command(t.Context(), &agentv1.PluginCommand{Plugin: "go-lamp", Sha256: b.GetSha256(), Command: "turn_on"})
	if !res.GetOk() || res.GetOutput() != "lamp is on" {
		t.Fatalf("result = %v", res)
	}
}

// TestPluginReleasePinning: a grant allows one release of a plugin, its
// program and manifest together. A new program, or the same one relabelled,
// is refused until the ceiling allows it; the release running stays.
func TestPluginReleasePinning(t *testing.T) {
	program, other := []byte("#!/bin/sh\nexit 0\n"), []byte("#!/bin/sh\necho new\n")
	spec := func(class string) *agentv1.PluginCommandSpec {
		return &agentv1.PluginCommandSpec{Name: "reflash", Class: class}
	}
	v1 := binaryOf("lamp", program, spec("dangerous"))
	relabelled := binaryOf("lamp", program, spec("read"))
	renewed := binaryOf("lamp", other, spec("dangerous"))
	digest := releaseOf(v1).Digest()
	if releaseOf(relabelled).Digest() == digest || releaseOf(renewed).Digest() == digest {
		t.Fatal("a new manifest or program kept the digest")
	}

	t.Run("hub pin", func(t *testing.T) {
		c := &Ceiling{Plugins: []PluginGrant{{Name: "lamp", Class: policy.Dangerous, Digest: digest}}}
		h, srv := testHost(t, c), newBlobServer(t, program, other)
		if st := syncOnce(t, h, srv, v1); st.GetPlugins()[0].GetError() != "" || st.GetPlugins()[0].GetRelease().GetSha256() != v1.GetSha256() {
			t.Fatalf("status = %v", st)
		}
		for name, b := range map[string]*agentv1.PluginBinary{"relabelled": relabelled, "new program": renewed} {
			st := syncOnce(t, h, srv, b)
			ps := st.GetPlugins()[0]
			if !strings.Contains(ps.GetError(), "approve it") || ps.GetSha256() != v1.GetSha256() {
				t.Fatalf("%s: status = %v, want refused and v1 kept", name, st)
			}
			h.mu.Lock()
			inst := h.installed["lamp"]
			h.mu.Unlock()
			if inst.digest != digest {
				t.Fatalf("%s: runs %s", name, inst.digest)
			}
		}
		// The ceiling allows the new one: it replaces the old, whose
		// commands in flight are cancelled.
		h.mu.Lock()
		old := h.installed["lamp"]
		h.mu.Unlock()
		*c = Ceiling{Plugins: []PluginGrant{{Name: "lamp", Class: policy.Dangerous, Digest: releaseOf(renewed).Digest()}}}
		if st := syncOnce(t, h, srv, renewed); st.GetPlugins()[0].GetSha256() != renewed.GetSha256() {
			t.Fatalf("status = %v", st)
		}
		if old.life.Err() == nil {
			t.Error("the replaced release's commands were not cancelled")
		}
	})

	t.Run("pinned on first use", func(t *testing.T) {
		c := &Ceiling{Plugins: []PluginGrant{{Name: "lamp", Class: policy.Dangerous}}}
		h, srv := testHost(t, c), newBlobServer(t, program, other)
		if st := syncOnce(t, h, srv, v1); st.GetPlugins()[0].GetError() != "" {
			t.Fatalf("status = %v", st)
		}
		if pins := h.loadPins(); pins["lamp"].Digest != digest || pins["lamp"].Flag != "lamp:dangerous" {
			t.Fatalf("pins = %v", pins)
		}
		// A restart: the pin holds.
		h2 := newPluginHost(filepath.Dir(h.dir), slog.New(slog.DiscardHandler), func() Ceiling { return *c })
		for _, b := range []*agentv1.PluginBinary{relabelled, renewed} {
			if st := syncOnce(t, h2, srv, b); !strings.Contains(st.GetPlugins()[0].GetError(), "approve it") {
				t.Fatalf("status = %v, want refused", st)
			}
		}
		// Another flag pins anew.
		*c = Ceiling{Plugins: []PluginGrant{{Name: "lamp", Class: policy.Safe}}}
		if st := syncOnce(t, h2, srv, renewed); st.GetPlugins()[0].GetError() != "" {
			t.Fatalf("status = %v", st)
		}
		if pins := h2.loadPins(); pins["lamp"].Digest != releaseOf(renewed).Digest() {
			t.Fatalf("pins = %v", pins)
		}
	})

	t.Run("digest flag", func(t *testing.T) {
		c := &Ceiling{Plugins: []PluginGrant{{Name: "lamp", Class: policy.Dangerous, Digest: releaseOf(renewed).Digest()}}}
		h, srv := testHost(t, c), newBlobServer(t, program)
		if st := syncOnce(t, h, srv, v1); !strings.Contains(st.GetPlugins()[0].GetError(), "approve it") || srv.fetches.Load() != 0 {
			t.Fatalf("status = %v, fetches %d", st, srv.fetches.Load())
		}
	})
}

// TestPluginsUnsupported: a platform without plugins installs and runs
// none, as on Windows.
func TestPluginsUnsupported(t *testing.T) {
	program := []byte("#!/bin/sh\nexit 0\n")
	h, srv := testHost(t, &Ceiling{Plugins: []PluginGrant{{Name: "lamp", Class: policy.Safe}}}), newBlobServer(t, program)
	h.unsupported = "device plugins are not supported on Windows yet"
	st := syncOnce(t, h, srv, binaryOf("lamp", program))
	if !strings.Contains(st.GetPlugins()[0].GetError(), "Windows") || srv.fetches.Load() != 0 {
		t.Fatalf("status = %v", st)
	}
	res := h.command(t.Context(), &agentv1.PluginCommand{Plugin: "lamp", Sha256: sum(program), Command: "x"})
	if !res.GetDenied() || !strings.Contains(res.GetError(), "Windows") {
		t.Fatalf("result = %v", res)
	}
}

// TestPluginCommandSlots: the agent runs a few plugin commands at once and
// refuses more.
func TestPluginCommandSlots(t *testing.T) {
	program := []byte("#!/bin/sh\nexit 0\n")
	h, srv := testHost(t, &Ceiling{Plugins: []PluginGrant{{Name: "lamp", Class: policy.Safe}}}), newBlobServer(t, program)
	b := binaryOf("lamp", program, &agentv1.PluginCommandSpec{Name: "on", Class: "read"})
	if st := syncOnce(t, h, srv, b); st.GetPlugins()[0].GetError() != "" {
		t.Fatalf("status = %v", st)
	}
	for range maxPluginCommands {
		h.slots <- struct{}{}
	}
	res := h.command(t.Context(), &agentv1.PluginCommand{Plugin: "lamp", Sha256: b.GetSha256(), Command: "on"})
	if !res.GetDenied() || !strings.Contains(res.GetError(), "already run") {
		t.Fatalf("result = %v", res)
	}
}
