// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gvart/hearth/internal/plugins"
	"github.com/gvart/hearth/internal/policy"
)

// testRegistry is a signed index in a directory, with its modules.
type testRegistry struct {
	t     *testing.T
	dir   string
	pub   ed25519.PublicKey
	priv  ed25519.PrivateKey
	index string
}

func newTestRegistry(t *testing.T) *testRegistry {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	return &testRegistry{t: t, dir: dir, pub: pub, priv: priv, index: filepath.Join(dir, "index.json")}
}

// module writes a module for version and returns its entry.
func (r *testRegistry) module(version string) plugins.IndexEntry {
	r.t.Helper()
	b := []byte("\x00asm\x01\x00\x00\x00" + version)
	file := "lamp-" + version + ".wasm"
	if err := os.WriteFile(filepath.Join(r.dir, file), b, 0o600); err != nil {
		r.t.Fatal(err)
	}
	s := sha256.Sum256(b)
	return plugins.IndexEntry{
		Name: "lamp", Version: version, Description: "A lamp", Author: "Tests", License: "MIT",
		Runtime: plugins.RuntimeWasm, URL: file, SHA256: hex.EncodeToString(s[:]),
		Capabilities: []string{plugins.CapCommand},
		Commands:     []plugins.CommandSpec{{Name: "turn_on", Class: policy.Safe}},
		Host:         plugins.HostGrants{HTTP: &plugins.HTTPGrant{Allow: []string{"192.0.2.7:80"}}},
	}
}

// publish writes the index of entries, signed.
func (r *testRegistry) publish(entries ...plugins.IndexEntry) {
	r.t.Helper()
	b, err := json.Marshal(plugins.Index{Format: plugins.IndexFormat, Plugins: entries})
	if err != nil {
		r.t.Fatal(err)
	}
	if err := os.WriteFile(r.index, b, 0o600); err != nil {
		r.t.Fatal(err)
	}
	if err := os.WriteFile(r.index+plugins.IndexSigSuffix, plugins.SignIndex(r.priv, b), 0o600); err != nil {
		r.t.Fatal(err)
	}
}

// withPluginRegistry serves reg (nil: no index) and the plugins installed
// in dataDir.
func withPluginRegistry(reg *testRegistry, dataDir string) func(*Config) {
	return func(c *Config) {
		mgr, err := plugins.New(plugins.Config{Policy: c.Policy})
		if err != nil {
			panic(err)
		}
		c.Plugins = mgr
		c.RegistryPlugins = &plugins.RegistrySync{Store: plugins.NewInstalledStore(dataDir), Manager: mgr}
		if reg != nil {
			c.PluginRegistry = &plugins.Registry{Source: reg.index, Keys: []ed25519.PublicKey{reg.pub}}
		}
	}
}

func changeBody(e plugins.IndexEntry, extra string) string {
	return fmt.Sprintf(`{"name":%q,"version":%q,"sha256":%q,"digest":%q%s}`, e.Name, e.Version, e.SHA256, e.Digest(), extra)
}

func registrySession(t *testing.T, f *apiFixture) *http.Cookie {
	t.Helper()
	c := staleSession(t, f)
	if resp := f.do(t, http.MethodPost, "/api/v1/session/reauth", passwordBody(testPassword), c); resp.StatusCode != http.StatusOK {
		t.Fatalf("reauth = %d", resp.StatusCode)
	}
	return c
}

func TestPluginRegistryOff(t *testing.T) {
	f := newAPIFixture(t, true, withPluginRegistry(nil, t.TempDir()))
	f.api.argon = testArgon
	cookie := registrySession(t, f)
	resp := f.do(t, http.MethodGet, "/api/v1/plugin-registry", "", cookie)
	got := decode[PluginRegistryJSON](t, resp)
	if got.Enabled || len(got.Installed) != 0 || len(got.Available) != 0 {
		t.Fatalf("registry %+v", got)
	}
	resp = f.do(t, http.MethodPost, "/api/v1/plugin-registry/install", changeBody(plugins.IndexEntry{Name: "lamp", Version: "1.0.0", SHA256: strings.Repeat("a", 64)}, ""), cookie)
	if resp.StatusCode != http.StatusConflict || errorCode(t, resp) != "registry_off" {
		t.Fatalf("install = %d %s", resp.StatusCode, resp.body)
	}
	if resp := f.do(t, http.MethodGet, "/api/v1/plugin-registry", "", nil); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("without a session = %d", resp.StatusCode)
	}
}

// TestPluginRegistryInstallUpdateRemove walks a plugin through the API:
// each change through policy and audited, install and update only with the
// password again and only what the caller reviewed, never a downgrade
// unless asked for.
func TestPluginRegistryInstallUpdateRemove(t *testing.T) {
	reg := newTestRegistry(t)
	v1, v2, v0 := reg.module("1.0.0"), reg.module("1.1.0"), reg.module("0.9.0")
	reg.publish(v1)
	dataDir := t.TempDir()
	f := newAPIFixture(t, true, withPolicy(policy.Config{}), withPluginRegistry(reg, dataDir))
	f.api.argon = testArgon
	st := plugins.NewInstalledStore(dataDir)

	stale := staleSession(t, f)
	resp := f.do(t, http.MethodPost, "/api/v1/plugin-registry/install", changeBody(v1, ""), stale)
	if resp.StatusCode != http.StatusForbidden || errorCode(t, resp) != "reauth_required" {
		t.Fatalf("install without re-auth = %d %s", resp.StatusCode, resp.body)
	}
	if e := auditOf(t, f, policy.PluginRegistryInstall); len(e) != 1 || e[0].Decision != policy.Deny {
		t.Fatalf("refused install audit = %+v", e)
	}

	cookie := registrySession(t, f)
	got := decode[PluginRegistryJSON](t, f.do(t, http.MethodGet, "/api/v1/plugin-registry", "", cookie))
	if !got.Enabled || got.IndexError != "" || len(got.Available) != 1 || len(got.Keys) != 1 {
		t.Fatalf("registry %+v", got)
	}
	if a := got.Available[0]; a.Name != "lamp" || len(a.HTTPAllow) != 1 || a.HTTPAllow[0] != "192.0.2.7:80" ||
		len(a.Commands) != 1 || a.Commands[0].Class != policy.Safe || a.Memory != 64 {
		t.Fatalf("available %+v", a)
	}
	if got.Decisions["install"] != policy.Allow || got.Decisions["remove"] != policy.Allow {
		t.Fatalf("decisions %v", got.Decisions)
	}

	for _, tt := range []struct {
		name, body, code string
		status           int
	}{
		{"no sha256", `{"name":"lamp","version":"1.0.0"}`, "bad_request", http.StatusBadRequest},
		{"no digest", fmt.Sprintf(`{"name":"lamp","version":"1.0.0","sha256":%q}`, v1.SHA256), "bad_request", http.StatusBadRequest},
		{"other sha256", changeBody(plugins.IndexEntry{Name: "lamp", Version: "1.0.0", SHA256: v2.SHA256}, ""), "index_changed", http.StatusConflict},
		{"other version", changeBody(plugins.IndexEntry{Name: "lamp", Version: "1.0.1", SHA256: v1.SHA256}, ""), "not_in_index", http.StatusNotFound},
		{"unknown", changeBody(plugins.IndexEntry{Name: "fan", Version: "1.0.0", SHA256: v1.SHA256}, ""), "not_in_index", http.StatusNotFound},
		{"update of nothing", "", "not_installed", http.StatusNotFound},
	} {
		t.Run(tt.name, func(t *testing.T) {
			path, body := "/api/v1/plugin-registry/install", tt.body
			if body == "" {
				path, body = "/api/v1/plugin-registry/update", changeBody(v1, "")
			}
			resp := f.do(t, http.MethodPost, path, body, cookie)
			if resp.StatusCode != tt.status || errorCode(t, resp) != tt.code {
				t.Fatalf("= %d %s, want %d %s", resp.StatusCode, resp.body, tt.status, tt.code)
			}
		})
	}

	// Re-signed meanwhile: the same version and module, wider grants.
	wider := v1
	wider.Host = plugins.HostGrants{HTTP: &plugins.HTTPGrant{Allow: []string{"192.0.2.7:80", "198.51.100.1:443"}}}
	reg.publish(wider)
	if resp := f.do(t, http.MethodPost, "/api/v1/plugin-registry/install", changeBody(v1, ""), cookie); errorCode(t, resp) != "index_changed" {
		t.Fatalf("install of an entry with wider grants = %d %s", resp.StatusCode, resp.body)
	}
	reg.publish(v1)

	resp = f.do(t, http.MethodPost, "/api/v1/plugin-registry/install", changeBody(v1, ""), cookie)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("install = %d %s", resp.StatusCode, resp.body)
	}
	if in, ok, err := st.Get("lamp"); err != nil || !ok || in.Entry.SHA256 != v1.SHA256 || !strings.HasPrefix(in.InstalledBy, "web/") {
		t.Fatalf("installed %+v %v %v", in, ok, err)
	}
	e := auditOf(t, f, policy.PluginRegistryInstall)
	if len(e) != 2 || e[0].Decision != policy.Allow || !strings.Contains(string(e[0].Detail), v1.SHA256) ||
		!strings.Contains(string(e[0].Detail), "192.0.2.7:80") || !strings.Contains(string(e[0].Detail), "turn_on:safe") {
		t.Fatalf("install audit = %+v", e)
	}
	if s := f.api.plugins.Plugins(); len(s) != 1 || s[0].Name != "lamp" {
		t.Fatalf("plugins %+v: the installed plugin is not run", s)
	}
	if resp := f.do(t, http.MethodPost, "/api/v1/plugin-registry/install", changeBody(v1, ""), cookie); errorCode(t, resp) != "installed" {
		t.Fatalf("install twice = %d %s", resp.StatusCode, resp.body)
	}

	// A newer version is offered, never applied by itself.
	reg.publish(v0, v1, v2)
	got = decode[PluginRegistryJSON](t, f.do(t, http.MethodGet, "/api/v1/plugin-registry", "", cookie))
	if len(got.Installed) != 1 || got.Installed[0].Version != "1.0.0" || got.Installed[0].Update == nil || got.Installed[0].Update.Version != "1.1.0" {
		t.Fatalf("installed %+v", got.Installed)
	}
	resp = f.do(t, http.MethodPost, "/api/v1/plugin-registry/update", changeBody(v2, ""), cookie)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("update = %d %s", resp.StatusCode, resp.body)
	}
	if e := auditOf(t, f, policy.PluginRegistryUpdate); len(e) != 1 || !strings.Contains(string(e[0].Detail), `"previous_version":"1.0.0"`) {
		t.Fatalf("update audit = %+v", e)
	}

	// An index that offers an older version offers no update, and a
	// downgrade happens only when asked for.
	reg.publish(v0)
	got = decode[PluginRegistryJSON](t, f.do(t, http.MethodGet, "/api/v1/plugin-registry", "", cookie))
	if got.Installed[0].Update != nil {
		t.Fatalf("an older version offered as an update: %+v", got.Installed[0].Update)
	}
	if resp := f.do(t, http.MethodPost, "/api/v1/plugin-registry/update", changeBody(v0, ""), cookie); errorCode(t, resp) != "downgrade" {
		t.Fatalf("downgrade = %d %s", resp.StatusCode, resp.body)
	}
	if resp := f.do(t, http.MethodPost, "/api/v1/plugin-registry/update", changeBody(v0, `,"allow_downgrade":true`), cookie); resp.StatusCode != http.StatusOK {
		t.Fatalf("explicit downgrade = %d %s", resp.StatusCode, resp.body)
	}

	resp = f.do(t, http.MethodDelete, "/api/v1/plugin-registry/lamp", "", stale)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("remove = %d %s", resp.StatusCode, resp.body)
	}
	if e := auditOf(t, f, policy.PluginRegistryRemove); len(e) != 1 || e[0].Decision != policy.Allow || e[0].Result != "ok" {
		t.Fatalf("remove audit = %+v", e)
	}
	if s := f.api.plugins.Plugins(); len(s) != 0 {
		t.Fatalf("plugins %+v after removal", s)
	}
	if resp := f.do(t, http.MethodDelete, "/api/v1/plugin-registry/lamp", "", cookie); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("remove twice = %d", resp.StatusCode)
	}
}

// A module that is not the one the index pins, and an index whose
// signature does not verify, install nothing.
func TestPluginRegistryRefusesUntrusted(t *testing.T) {
	reg := newTestRegistry(t)
	v1 := reg.module("1.0.0")
	reg.publish(v1)
	dataDir := t.TempDir()
	f := newAPIFixture(t, true, withPluginRegistry(reg, dataDir))
	f.api.argon = testArgon
	cookie := registrySession(t, f)
	st := plugins.NewInstalledStore(dataDir)

	if err := os.WriteFile(filepath.Join(reg.dir, v1.URL), []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	resp := f.do(t, http.MethodPost, "/api/v1/plugin-registry/install", changeBody(v1, ""), cookie)
	if resp.StatusCode != http.StatusBadGateway || errorCode(t, resp) != "pin_mismatch" {
		t.Fatalf("tampered module = %d %s", resp.StatusCode, resp.body)
	}

	// Signed by a key the hub does not trust.
	other := newTestRegistry(t)
	other.index = reg.index
	other.publish(reg.module("1.0.0"))
	resp = f.do(t, http.MethodPost, "/api/v1/plugin-registry/install", changeBody(v1, ""), cookie)
	if resp.StatusCode != http.StatusBadGateway || errorCode(t, resp) != "index_untrusted" {
		t.Fatalf("untrusted index = %d %s", resp.StatusCode, resp.body)
	}
	got := decode[PluginRegistryJSON](t, f.do(t, http.MethodGet, "/api/v1/plugin-registry", "", cookie))
	if !strings.Contains(got.IndexError, "does not verify") || len(got.Available) != 0 {
		t.Fatalf("registry %+v", got)
	}
	// No signature at all.
	if err := os.Remove(reg.index + plugins.IndexSigSuffix); err != nil {
		t.Fatal(err)
	}
	if resp := f.do(t, http.MethodPost, "/api/v1/plugin-registry/install", changeBody(v1, ""), cookie); errorCode(t, resp) != "index_untrusted" {
		t.Fatalf("unsigned index = %d %s", resp.StatusCode, resp.body)
	}
	if l, _ := st.List(); len(l) != 0 {
		t.Fatalf("installed %+v", l)
	}
	if e := auditOf(t, f, policy.PluginRegistryInstall); len(e) != 0 {
		t.Fatalf("an unverified install reached policy: %+v", e)
	}
}

// Policy decides every change: one it denies is audited and installs or
// removes nothing.
func TestPluginRegistryPolicyDenies(t *testing.T) {
	reg := newTestRegistry(t)
	v1 := reg.module("1.0.0")
	reg.publish(v1)
	dataDir := t.TempDir()
	f := newAPIFixture(t, true, withPolicy(policy.Config{Actors: map[string]map[policy.Class]policy.Mode{
		policy.ActorWeb: {policy.Dangerous: policy.ModeDeny, policy.Safe: policy.ModeDeny},
	}}), withPluginRegistry(reg, dataDir))
	f.api.argon = testArgon
	cookie := registrySession(t, f)
	st := plugins.NewInstalledStore(dataDir)

	got := decode[PluginRegistryJSON](t, f.do(t, http.MethodGet, "/api/v1/plugin-registry", "", cookie))
	if got.Decisions["install"] != policy.Deny || got.Decisions["update"] != policy.Deny || got.Decisions["remove"] != policy.Deny {
		t.Fatalf("decisions %v", got.Decisions)
	}
	resp := f.do(t, http.MethodPost, "/api/v1/plugin-registry/install", changeBody(v1, ""), cookie)
	if resp.StatusCode != http.StatusForbidden || errorCode(t, resp) != "forbidden" {
		t.Fatalf("denied install = %d %s", resp.StatusCode, resp.body)
	}
	if l, _ := st.List(); len(l) != 0 {
		t.Fatalf("a denied install installed %+v", l)
	}
	if e := auditOf(t, f, policy.PluginRegistryInstall); len(e) != 1 || e[0].Decision != policy.Deny {
		t.Fatalf("denied install audit = %+v", e)
	}

	// Installed by the CLI meanwhile; the web may not remove it.
	b, _ := os.ReadFile(filepath.Join(reg.dir, v1.URL))
	if err := st.Put(v1, b, reg.index, "admin/root", f.api.now()); err != nil {
		t.Fatal(err)
	}
	if resp := f.do(t, http.MethodDelete, "/api/v1/plugin-registry/lamp", "", cookie); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("denied remove = %d %s", resp.StatusCode, resp.body)
	}
	if _, ok, _ := st.Get("lamp"); !ok {
		t.Fatal("a denied removal removed the plugin")
	}
	if e := auditOf(t, f, policy.PluginRegistryRemove); len(e) != 1 || e[0].Decision != policy.Deny {
		t.Fatalf("denied remove audit = %+v", e)
	}
}
