// SPDX-License-Identifier: AGPL-3.0-only

package plugins

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/policy"
)

func newIndexKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func sum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// testEntry is an entry of the test guest module, as file.
func testEntry(name, version, file string, module []byte) IndexEntry {
	return IndexEntry{
		Name: name, Version: version, Description: "A test plugin", Author: "Tests", License: "Apache-2.0",
		Runtime: RuntimeWasm, URL: file, SHA256: sum(module), Memory: 32,
		Capabilities: []string{CapDiscover, CapState, CapCommand},
		Commands:     []CommandSpec{{Name: "echo", Class: policy.Read}, {Name: "http", Class: policy.Safe}},
		Host:         HostGrants{HTTP: &HTTPGrant{Allow: []string{"192.0.2.1:80"}}},
	}
}

// writeIndex writes idx, signed with key (unless nil), into dir and returns
// its path.
func writeIndex(t *testing.T, dir string, key ed25519.PrivateKey, idx Index) string {
	t.Helper()
	b, err := json.Marshal(idx)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "index.json")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if key != nil {
		if err := os.WriteFile(p+IndexSigSuffix, SignIndex(key, b), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return p
}

// guestModule is the test guest module's bytes.
func guestModule(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(buildWasm(t, "./testdata/wasmguest"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestVerifyIndex(t *testing.T) {
	pub, priv := newIndexKey(t)
	other, otherPriv := newIndexKey(t)
	index := []byte(`{"format":1,"plugins":[]}`)
	good := SignIndex(priv, index)
	tests := []struct {
		name  string
		keys  []ed25519.PublicKey
		index []byte
		sig   []byte
		ok    bool
	}{
		{name: "good", keys: []ed25519.PublicKey{pub}, index: index, sig: good, ok: true},
		{name: "second key", keys: []ed25519.PublicKey{other, pub}, index: index, sig: good, ok: true},
		{name: "tampered index", keys: []ed25519.PublicKey{pub}, index: []byte(`{"format":1,"plugins":[ ]}`), sig: good},
		{name: "missing signature", keys: []ed25519.PublicKey{pub}, index: index, sig: nil},
		{name: "malformed signature", keys: []ed25519.PublicKey{pub}, index: index, sig: []byte("not base64!")},
		{name: "short signature", keys: []ed25519.PublicKey{pub}, index: index, sig: []byte(base64.StdEncoding.EncodeToString([]byte("short")))},
		{name: "key not trusted", keys: []ed25519.PublicKey{other}, index: index, sig: good},
		{name: "signed by another key", keys: []ed25519.PublicKey{pub}, index: index, sig: SignIndex(otherPriv, index)},
		{name: "no key", keys: nil, index: index, sig: good},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := VerifyIndex(tt.keys, tt.index, tt.sig)
			if tt.ok != (err == nil) {
				t.Fatalf("err %v, want ok %v", err, tt.ok)
			}
			if err != nil && !errors.Is(err, ErrIndexSignature) {
				t.Fatalf("err %v, want ErrIndexSignature", err)
			}
		})
	}
}

func TestFetchVerifiesBeforeParsing(t *testing.T) {
	pub, priv := newIndexKey(t)
	other, _ := newIndexKey(t)
	dir := tempDir(t)
	src := writeIndex(t, dir, priv, Index{Format: 1, Plugins: []IndexEntry{testEntry("p", "1.0.0", "p.wasm", []byte("m"))}})
	if idx, err := (&Registry{Source: src, Keys: []ed25519.PublicKey{pub}}).Fetch(t.Context()); err != nil || len(idx.Plugins) != 1 {
		t.Fatalf("Fetch: %v, %v", idx, err)
	}
	if _, err := (&Registry{Source: src, Keys: []ed25519.PublicKey{other}}).Fetch(t.Context()); !errors.Is(err, ErrIndexSignature) {
		t.Fatalf("untrusted key: %v", err)
	}
	// Garbage signed is refused as garbage; garbage unsigned for its signature.
	if err := os.WriteFile(src, []byte("{garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := (&Registry{Source: src, Keys: []ed25519.PublicKey{pub}}).Fetch(t.Context()); !errors.Is(err, ErrIndexSignature) {
		t.Fatalf("tampered: %v", err)
	}
	if err := os.Remove(src + IndexSigSuffix); err != nil {
		t.Fatal(err)
	}
	if _, err := (&Registry{Source: src, Keys: []ed25519.PublicKey{pub}}).Fetch(t.Context()); !errors.Is(err, ErrIndexSignature) {
		t.Fatalf("no signature: %v", err)
	}
	if _, err := (*Registry)(nil).Fetch(t.Context()); !errors.Is(err, ErrRegistryOff) {
		t.Fatalf("no registry: %v", err)
	}
}

func TestParseIndex(t *testing.T) {
	ok := testEntry("p", "1.0.0", "p.wasm", []byte("m"))
	with := func(f func(*IndexEntry)) IndexEntry {
		e := ok
		e.Host = HostGrants{HTTP: &HTTPGrant{Allow: slices.Clone(ok.Host.HTTP.Allow)}}
		f(&e)
		return e
	}
	marshal := func(v any) []byte { b, _ := json.Marshal(v); return b }
	tests := []struct {
		name  string
		index []byte
		want  string
	}{
		{name: "ok", index: marshal(Index{Format: 1, Plugins: []IndexEntry{ok, with(func(e *IndexEntry) { e.Version = "1.1.0" })}})},
		{name: "format", index: marshal(Index{Format: 2}), want: "format 2"},
		{name: "unknown field", index: []byte(`{"format":1,"plugins":[],"extra":1}`), want: "unknown field"},
		{name: "exec", index: marshal(Index{Format: 1, Plugins: []IndexEntry{with(func(e *IndexEntry) { e.Runtime = RuntimeExec })}}), want: "wasm plugins only"},
		{name: "version", index: marshal(Index{Format: 1, Plugins: []IndexEntry{with(func(e *IndexEntry) { e.Version = "latest" })}}), want: "semantic version"},
		{name: "sha256", index: marshal(Index{Format: 1, Plugins: []IndexEntry{with(func(e *IndexEntry) { e.SHA256 = "abc" })}}), want: "sha256"},
		{name: "climbing url", index: marshal(Index{Format: 1, Plugins: []IndexEntry{with(func(e *IndexEntry) { e.URL = "../x.wasm" })}}), want: "climb"},
		{name: "absolute url", index: marshal(Index{Format: 1, Plugins: []IndexEntry{with(func(e *IndexEntry) { e.URL = "/etc/x.wasm" })}}), want: "climb"},
		{name: "file url", index: marshal(Index{Format: 1, Plugins: []IndexEntry{with(func(e *IndexEntry) { e.URL = "file:///x.wasm" })}}), want: "url"},
		{name: "credentials", index: marshal(Index{Format: 1, Plugins: []IndexEntry{with(func(e *IndexEntry) { e.URL = "https://u:p@example.com/x.wasm" })}}), want: "credentials"},
		{name: "bad grant", index: marshal(Index{Format: 1, Plugins: []IndexEntry{with(func(e *IndexEntry) { e.Host.HTTP.Allow = []string{"no port here/x"} })}}), want: "host.http.allow"},
		{name: "bad class", index: marshal(Index{Format: 1, Plugins: []IndexEntry{with(func(e *IndexEntry) { e.Commands = []CommandSpec{{Name: "x", Class: "root"}} })}}), want: "class"},
		{name: "twice", index: marshal(Index{Format: 1, Plugins: []IndexEntry{ok, ok}}), want: "listed twice"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseIndex(tt.index)
			if tt.want == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err %v, want %q", err, tt.want)
			}
		})
	}
}

func TestNewRegistry(t *testing.T) {
	pub, _ := newIndexKey(t)
	key := base64.StdEncoding.EncodeToString(pub)
	tests := []struct {
		name, source string
		keys         []string
		want         string
	}{
		{name: "off"},
		{name: "file", source: "/srv/index.json", keys: []string{key}},
		{name: "https", source: "https://plugins.example.com/index.json", keys: []string{key}},
		{name: "no key", source: "https://plugins.example.com/index.json", want: "needs --plugin-index-key"},
		{name: "no index", keys: []string{key}, want: "needs --plugin-index"},
		{name: "bad key", source: "/srv/index.json", keys: []string{"nope"}, want: "32-byte"},
		{name: "credentials", source: "https://u:p@example.com/index.json", keys: []string{key}, want: "credentials"}, //nolint:gosec // a test URL
		{name: "query", source: "https://example.com/index.json?t=1", keys: []string{key}, want: "query"},
		{name: "scheme", source: "ftp://example.com/index.json", keys: []string{key}, want: "http(s)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := NewRegistry(tt.source, tt.keys)
			if tt.want != "" {
				if err == nil || !strings.Contains(err.Error(), tt.want) {
					t.Fatalf("err %v, want %q", err, tt.want)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if (r == nil) != (tt.source == "") {
				t.Fatalf("registry %v", r)
			}
		})
	}
}

func TestDownloadChecksTheModule(t *testing.T) {
	module := []byte("\x00asm module")
	e := testEntry("p", "1.0.0", "mods/p.wasm", module)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/reg/mods/p.wasm":
			_, _ = w.Write(module)
		case "/reg/mods/bad.wasm":
			_, _ = w.Write([]byte("something else"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	r := &Registry{Source: srv.URL + "/reg/index.json"}
	if b, err := r.Download(t.Context(), e); err != nil || string(b) != string(module) {
		t.Fatalf("relative URL: %q, %v", b, err)
	}
	bad := e
	bad.URL = "mods/bad.wasm"
	if _, err := r.Download(t.Context(), bad); !errors.Is(err, ErrPinMismatch) {
		t.Fatalf("mismatch: %v", err)
	}
	abs := e
	abs.URL = srv.URL + "/reg/mods/p.wasm"
	if _, err := r.Download(t.Context(), abs); err != nil {
		t.Fatalf("absolute URL: %v", err)
	}
	// From a file index, relative to its directory.
	dir := tempDir(t)
	if err := os.MkdirAll(filepath.Join(dir, "mods"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "mods", "p.wasm"), []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	fr := &Registry{Source: filepath.Join(dir, "index.json")}
	if _, err := fr.Download(t.Context(), e); !errors.Is(err, ErrPinMismatch) {
		t.Fatalf("file mismatch: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "mods", "p.wasm"), module, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := fr.Download(t.Context(), e); err != nil {
		t.Fatalf("file: %v", err)
	}
}

func TestPlans(t *testing.T) {
	st := NewInstalledStore(tempDir(t))
	m1, m2, m0 := []byte("one"), []byte("two"), []byte("zero")
	e1 := testEntry("p", "1.0.0", "p1.wasm", m1)
	e2 := testEntry("p", "1.2.0", "p2.wasm", m2)
	e0 := testEntry("p", "0.9.0", "p0.wasm", m0)
	idx := &Index{Format: 1, Plugins: []IndexEntry{e0, e2, e1}}
	if _, err := PlanUpdate(idx, "src", st, "p", "", false); !errors.Is(err, ErrNotInstalled) {
		t.Fatalf("update of nothing: %v", err)
	}
	c, err := PlanInstall(idx, "src", st, "p", "1.0.0")
	if err != nil || c.Entry.Version != "1.0.0" || c.Action != policy.PluginRegistryInstall {
		t.Fatalf("install: %+v, %v", c, err)
	}
	if _, err := PlanInstall(idx, "src", st, "p", "3.0.0"); !errors.Is(err, ErrNotInIndex) {
		t.Fatalf("missing version: %v", err)
	}
	if err := st.Put(e1, m1, "src", "admin/test", time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := PlanInstall(idx, "src", st, "p", ""); !errors.Is(err, ErrInstalled) {
		t.Fatalf("install twice: %v", err)
	}
	if got := Updates(idx, mustList(t, st)); len(got) != 1 || got[0].Available != "1.2.0" {
		t.Fatalf("updates %+v", got)
	}
	c, err = PlanUpdate(idx, "src", st, "p", "", false)
	if err != nil || c.Entry.Version != "1.2.0" || c.Previous.Entry.Version != "1.0.0" {
		t.Fatalf("update: %+v, %v", c, err)
	}
	// An index that only offers an older version offers no update.
	older := &Index{Format: 1, Plugins: []IndexEntry{e0}}
	if got := Updates(older, mustList(t, st)); len(got) != 0 {
		t.Fatalf("older index offers %+v", got)
	}
	if _, err := PlanUpdate(older, "src", st, "p", "", false); !errors.Is(err, ErrDowngrade) {
		t.Fatalf("downgrade: %v", err)
	}
	if c, err := PlanUpdate(older, "src", st, "p", "0.9.0", true); err != nil || c.Entry.Version != "0.9.0" {
		t.Fatalf("explicit downgrade: %+v, %v", c, err)
	}
	if _, err := PlanUpdate(idx, "src", st, "p", "1.0.0", false); !errors.Is(err, ErrUpToDate) {
		t.Fatalf("same version: %v", err)
	}
	swapped := e1
	swapped.SHA256 = sum([]byte("other"))
	if _, err := PlanUpdate(&Index{Format: 1, Plugins: []IndexEntry{swapped}}, "src", st, "p", "", false); err == nil || !strings.Contains(err.Error(), "another module") {
		t.Fatalf("same version, other module: %v", err)
	}
}

func mustList(t *testing.T, st InstalledStore) []Installed {
	t.Helper()
	l, err := st.List()
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func TestChangeConfirmedAndRequest(t *testing.T) {
	e := testEntry("p", "1.0.0", "p.wasm", []byte("m"))
	c := Change{Action: policy.PluginRegistryInstall, Entry: e, Source: "https://example.com/index.json"}
	if err := c.Confirmed("1.0.0", e.SHA256, e.Digest()); err != nil {
		t.Fatal(err)
	}
	if err := c.Confirmed("", "", ""); err != nil {
		t.Fatal(err)
	}
	if err := c.Confirmed("1.0.1", e.SHA256, ""); !errors.Is(err, ErrIndexChanged) {
		t.Fatalf("other version: %v", err)
	}
	if err := c.Confirmed("1.0.0", sum([]byte("x")), ""); !errors.Is(err, ErrIndexChanged) {
		t.Fatalf("other module: %v", err)
	}
	// The same module with wider grants is another entry.
	wider := e
	wider.Host = HostGrants{HTTP: &HTTPGrant{Allow: []string{"192.0.2.1:80", "203.0.113.5:443"}}}
	if err := (Change{Entry: wider}).Confirmed("1.0.0", e.SHA256, e.Digest()); !errors.Is(err, ErrIndexChanged) {
		t.Fatalf("wider grants: %v", err)
	}
	req := c.Request()
	if req.Action != policy.PluginRegistryInstall || req.Target != "p" {
		t.Fatalf("request %+v", req)
	}
	if got := req.Detail["http_allow"].([]string); !slices.Equal(got, []string{"192.0.2.1:80"}) {
		t.Fatalf("http_allow %v", got)
	}
	if got := req.Detail["commands"].([]string); !slices.Equal(got, []string{"echo:read", "http:safe"}) {
		t.Fatalf("commands %v", got)
	}
	if req.Detail["sha256"] != e.SHA256 || req.Detail["source"] != c.Source || req.Detail["memory"] != 32 {
		t.Fatalf("detail %v", req.Detail)
	}
}

// TestInstalledPluginsRun installs, updates and removes a plugin, and checks
// that a manager runs what is installed, and nothing more.
func TestInstalledPluginsRun(t *testing.T) {
	module := guestModule(t)
	st := NewInstalledStore(tempDir(t))
	mgr, audit := startManager(t, policy.Config{}, helperManifest(t, "static", "ok"))
	sync := &RegistrySync{Store: st, Manager: mgr}

	e1 := testEntry("guest", "1.0.0", "g.wasm", module)
	if err := st.Put(e1, module, "src", "admin/test", time.Now()); err != nil {
		t.Fatal(err)
	}
	sync.Sync(t.Context())
	waitFor(t, "guest running", func() bool { return status(mgr, "guest").State == StateRunning })
	if errs := sync.Errors(); len(errs) != 0 {
		t.Fatalf("errors %v", errs)
	}
	// Its grants are the entry's, and nothing else.
	if r, err := run(t, mgr, "guest", "echo", nil); err != nil || r.Output == "" {
		t.Fatalf("echo: %+v, %v", r, err)
	}
	if _, err := run(t, mgr, "guest", "files", nil); !errors.Is(err, policy.ErrDenied) {
		t.Fatalf("undeclared command: %v", err)
	}
	if len(audit.find(string(policy.PluginStart), "allow")) < 2 {
		t.Fatal("plugin.start not audited")
	}

	e2 := e1
	e2.Version = "1.1.0"
	if err := st.Put(e2, module, "src", "admin/test", time.Now()); err != nil {
		t.Fatal(err)
	}
	sync.Sync(t.Context())
	waitFor(t, "guest 1.1.0 running", func() bool {
		s := status(mgr, "guest")
		return s.State == StateRunning && s.Version == "1.1.0"
	})
	if n := len(mgr.Plugins()); n != 2 {
		t.Fatalf("%d plugins, want 2", n)
	}

	// A module changed on disk is refused at its next start.
	if err := os.WriteFile(filepath.Join(st.Dir, "guest", e2.SHA256, moduleFile), []byte("evil"), 0o600); err != nil {
		t.Fatal(err)
	}
	e3 := e2
	e3.Version = "1.1.1"
	man := e3.Manifest(filepath.Join(st.Dir, "guest", e2.SHA256))
	mgr.Reconcile([]Manifest{man})
	waitFor(t, "a tampered module refused", func() bool {
		s := status(mgr, "guest")
		return s.Version == "1.1.1" && strings.Contains(s.Error, ErrPinMismatch.Error())
	})

	// The same name as a configured plugin is not run.
	clash := e1
	clash.Name = "static"
	if errs := mgr.Reconcile([]Manifest{clash.Manifest(st.Dir)}); errs["static"] == nil {
		t.Fatal("a registry plugin replaced a configured one")
	}

	if err := st.Remove("guest"); err != nil {
		t.Fatal(err)
	}
	if err := st.Remove("guest"); !errors.Is(err, ErrNotInstalled) {
		t.Fatalf("remove twice: %v", err)
	}
	sync.Sync(t.Context())
	if s := status(mgr, "guest"); s.Name != "" {
		t.Fatalf("removed plugin still listed: %+v", s)
	}
	if status(mgr, "static").Name == "" {
		t.Fatal("the configured plugin went too")
	}
	if _, err := os.Stat(filepath.Join(st.Dir, "guest")); !os.IsNotExist(err) {
		t.Fatalf("files left: %v", err)
	}
}

func TestInstalledFilesArePrivate(t *testing.T) {
	module := []byte("m")
	st := NewInstalledStore(tempDir(t))
	e1 := testEntry("p", "1.0.0", "p.wasm", module)
	if err := st.Put(e1, module, "src", "admin/x", time.Now()); err != nil {
		t.Fatal(err)
	}
	e2 := e1
	e2.Version, e2.SHA256 = "2.0.0", sum([]byte("n"))
	if err := st.Put(e2, []byte("n"), "src", "admin/x", time.Now()); err != nil {
		t.Fatal(err)
	}
	ents, err := os.ReadDir(filepath.Join(st.Dir, "p"))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, d := range ents {
		names = append(names, d.Name())
	}
	if !slices.Equal(names, []string{e2.SHA256, releaseFile}) {
		t.Fatalf("files %v: want only the new release and its record", names)
	}
	for _, f := range []string{moduleFile, manifestFile} {
		fi, err := os.Stat(filepath.Join(st.Dir, "p", e2.SHA256, f))
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode %v", f, fi.Mode())
		}
	}
	ms, errs := st.Manifests()
	if len(errs) != 0 || len(ms) != 1 || ms[0].Version != "2.0.0" || ms[0].SHA256 != e2.SHA256 {
		t.Fatalf("manifests %+v, %v", ms, errs)
	}
}
