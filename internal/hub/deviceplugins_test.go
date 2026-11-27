// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/gvart/hearth/internal/plugins"
	"github.com/gvart/hearth/internal/policy"
	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
	"github.com/gvart/hearth/internal/store"
)

const lampManifest = `protocol: 1
name: go-lamp
version: 0.1.0
command: ./lamp
capabilities: [discover, state, command]
commands:
  - name: turn_on
    class: safe
`

// saveRelease records an upload of plugin name for linux/arm64, its
// program being program, and returns its release digest.
func saveRelease(t *testing.T, st *store.Store, name, program string) string {
	t.Helper()
	m, err := plugins.ParseManifest([]byte(strings.Replace(lampManifest, "name: go-lamp", "name: "+name, 1)))
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256([]byte(program))
	u := DevicePluginUpload{Manifest: m, OS: "linux", Arch: "arm64", SHA256: hex.EncodeToString(h[:]), Size: int64(len(program))}
	if err := u.Save(t.Context(), st, "", "test", time.Now()); err != nil {
		t.Fatal(err)
	}
	return u.Release().Digest()
}

// piHello is the hello of an agent on linux/arm64.
func piHello(minor uint32, locked bool, local *agentv1.Ceiling) *agentv1.Hello {
	h := agentHello(minor, locked, local)
	h.Os, h.Arch = "debian 12", "arm64"
	return h
}

// withDevicePlugins gives the fixture's API agents and a store of programs.
func withDevicePlugins(dir string) func(*Config) {
	return func(c *Config) {
		c.Agents, c.PluginBlobs = NewAgents(c.Store.Devices()), NewPluginBlobs(dir)
	}
}

// uploadBody is a multipart upload: the manifest, then the program, read
// from program.
func uploadBody(t *testing.T, manifest string, program io.Reader) (string, io.Reader) {
	t.Helper()
	pr, pw := io.Pipe()
	mw := multipart.NewWriter(pw)
	go func() {
		err := mw.WriteField("manifest", manifest)
		if err == nil {
			var w io.Writer
			if w, err = mw.CreateFormFile("program", "lamp"); err == nil {
				_, err = io.Copy(w, program)
			}
		}
		if err == nil {
			err = mw.Close()
		}
		_ = pw.CloseWithError(err)
	}()
	return mw.FormDataContentType(), pr
}

func (f *apiFixture) upload(t *testing.T, query, manifest string, program io.Reader, c *http.Cookie) apiResp {
	t.Helper()
	ct, body := uploadBody(t, manifest, program)
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, f.srv.URL+"/api/v1/device-plugins"+query, body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", ct)
	req.AddCookie(c)
	resp, err := f.srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return apiResp{StatusCode: resp.StatusCode, Header: resp.Header, body: b}
}

func blobFiles(t *testing.T, dir string) []string {
	t.Helper()
	entries, _ := os.ReadDir(filepath.Join(dir, PluginBlobsDir))
	var out []string
	for _, e := range entries {
		out = append(out, e.Name())
	}
	return out
}

// TestDevicePluginUpload: an upload is plugin.binary.upload, dangerous, and
// needs the password again; it stores the program by its SHA-256 and the
// plugin; bad and oversize uploads are refused and leave nothing.
func TestDevicePluginUpload(t *testing.T) {
	dir := t.TempDir()
	f := newAPIFixture(t, true, withPolicy(policy.Config{}), withDevicePlugins(dir))
	f.api.argon = testArgon
	stale := staleSession(t, f)
	program := []byte("#!/bin/sh\necho lamp\n")

	resp := f.upload(t, "?os=linux&arch=arm64", lampManifest, bytes.NewReader(program), stale)
	if resp.StatusCode != http.StatusForbidden || errorCode(t, resp) != "reauth_required" {
		t.Fatalf("upload without re-auth = %d %s, want 403 reauth_required", resp.StatusCode, resp.body)
	}
	if e := auditOf(t, f, policy.PluginBinaryUpload); len(e) != 1 || e[0].Decision != policy.Deny {
		t.Fatalf("refused upload audit = %+v", e)
	}
	if files := blobFiles(t, dir); len(files) != 0 {
		t.Fatalf("a refused upload left %v", files)
	}

	if resp := f.do(t, http.MethodPost, "/api/v1/session/reauth", passwordBody(testPassword), stale); resp.StatusCode != http.StatusOK {
		t.Fatalf("reauth = %d", resp.StatusCode)
	}
	resp = f.upload(t, "?os=linux&arch=arm64", lampManifest, bytes.NewReader(program), stale)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("upload = %d %s", resp.StatusCode, resp.body)
	}
	got := decode[DevicePluginJSON](t, resp)
	if got.Name != "go-lamp" || got.OS != "linux" || got.Arch != "arm64" || got.Size != int64(len(program)) ||
		!plugins.ValidSHA256(got.SHA256) || len(got.Commands) != 1 || got.Commands[0].Class != policy.Safe {
		t.Fatalf("uploaded = %+v", got)
	}
	if files := blobFiles(t, dir); len(files) != 1 || files[0] != got.SHA256 {
		t.Fatalf("programs = %v, want %s", files, got.SHA256)
	}
	e := auditOf(t, f, policy.PluginBinaryUpload)
	if len(e) != 2 || e[0].Decision != policy.Allow || !strings.Contains(string(e[0].Detail), got.SHA256) {
		t.Fatalf("upload audit = %+v", e)
	}

	refused := []struct {
		name, query, manifest string
		program               io.Reader
		status                int
	}{
		{"env", "?os=linux&arch=arm64", lampManifest + "env: {TOKEN: secret}\n", bytes.NewReader(program), http.StatusBadRequest},
		{"bad manifest", "?os=linux&arch=arm64", "protocol: 9\nname: x\n", bytes.NewReader(program), http.StatusBadRequest},
		{"bad platform", "?os=../x&arch=arm64", lampManifest, bytes.NewReader(program), http.StatusBadRequest},
		{"no platform", "", lampManifest, bytes.NewReader(program), http.StatusBadRequest},
		{"oversize", "?os=linux&arch=amd64", lampManifest, io.LimitReader(zeros{}, plugins.MaxProgramSize+1), http.StatusRequestEntityTooLarge},
	}
	for _, tt := range refused {
		t.Run(tt.name, func(t *testing.T) {
			if resp := f.upload(t, tt.query, tt.manifest, tt.program, stale); resp.StatusCode != tt.status {
				t.Fatalf("= %d %s, want %d", resp.StatusCode, resp.body, tt.status)
			}
			if files := blobFiles(t, dir); len(files) != 1 {
				t.Fatalf("programs = %v", files)
			}
		})
	}

	// A new program for the same platform replaces the old one, on disk too.
	resp = f.upload(t, "?os=linux&arch=arm64", lampManifest, strings.NewReader("#!/bin/sh\necho v2\n"), stale)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("re-upload = %d %s", resp.StatusCode, resp.body)
	}
	got = decode[DevicePluginJSON](t, resp)
	if files := blobFiles(t, dir); len(files) != 1 || files[0] != got.SHA256 {
		t.Fatalf("programs after a re-upload = %v, want %s only", files, got.SHA256)
	}
	list := decode[DevicePluginsJSON](t, f.do(t, http.MethodGet, "/api/v1/device-plugins", "", stale))
	if len(list.Plugins) != 1 || list.MaxSize != plugins.MaxProgramSize {
		t.Fatalf("list = %+v", list)
	}
	// Removing needs no password again, and removes the program.
	other := staleSession(t, f)
	if resp := f.do(t, http.MethodDelete, "/api/v1/device-plugins/"+got.ID, "", other); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete = %d %s", resp.StatusCode, resp.body)
	}
	if files := blobFiles(t, dir); len(files) != 0 {
		t.Fatalf("programs after delete = %v", files)
	}
	if e := auditOf(t, f, policy.PluginBinaryDelete); len(e) != 1 || e[0].Decision != policy.Allow {
		t.Fatalf("delete audit = %+v", e)
	}
	if resp := f.do(t, http.MethodDelete, "/api/v1/device-plugins/"+got.ID, "", other); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("second delete = %d", resp.StatusCode)
	}
}

type zeros struct{}

func (zeros) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

// TestCapabilitiesPlugins: allowing a plugin or raising its class is
// device.capabilities.raise and needs the password again; lowering is
// device.capabilities.set; an agent too old for plugins says so.
func TestCapabilitiesPlugins(t *testing.T) {
	f := newWebAdminFixture(t, policy.Config{})
	reportHello(t, f, "pi", piHello(13, false, &agentv1.Ceiling{}))
	stale := staleSession(t, f)
	if got := decode[CapabilitiesJSON](t, f.do(t, http.MethodGet, capsPath, "", stale)); got.PluginsManageable || got.Hub.Plugins == nil {
		t.Fatalf("minor 13 = %+v, want plugins not manageable", got)
	}
	reportHello(t, f, "pi", piHello(14, false, &agentv1.Ceiling{}))
	lampV1, zeta := saveRelease(t, f.st, "go-lamp", "v1"), saveRelease(t, f.st, "zeta", "z")

	resp := f.do(t, http.MethodPut, capsPath, `{"hub":{"plugins":[{"name":"go-lamp","class":"read"}]}}`, stale)
	if resp.StatusCode != http.StatusForbidden || errorCode(t, resp) != "reauth_required" {
		t.Fatalf("allow a plugin without re-auth = %d %s", resp.StatusCode, resp.body)
	}
	if e := auditOf(t, f, policy.DeviceCapabilitiesRaise); len(e) != 1 || e[0].Decision != policy.Deny ||
		!strings.Contains(string(e[0].Detail), "plugin:go-lamp") {
		t.Fatalf("refused raise audit = %+v", e)
	}
	for _, body := range []string{
		`{"hub":{"plugins":[{"name":"../x","class":"read"}]}}`,
		`{"hub":{"plugins":[{"name":"lamp","class":"root"}]}}`,
		`{"hub":{"plugins":[{"name":"go-lamp","class":"read"},{"name":"go-lamp","class":"safe"}]}}`,
		`{"hub":{"plugins":[{"name":"nowhere","class":"read"}]}}`,
		`{"hub":{"plugins":[{"name":"go-lamp","class":"read","digest":"abc"}]}}`,
	} {
		if resp := f.do(t, http.MethodPut, capsPath, body, stale); resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s = %d, want 400", body, resp.StatusCode)
		}
	}
	if resp := f.do(t, http.MethodPost, "/api/v1/session/reauth", passwordBody(testPassword), stale); resp.StatusCode != http.StatusOK {
		t.Fatalf("reauth = %d", resp.StatusCode)
	}
	resp = f.do(t, http.MethodPut, capsPath, `{"hub":{"plugins":[{"name":"zeta","class":"dangerous"},{"name":"go-lamp","class":"safe"}]}}`, stale)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("allow after re-auth = %d %s", resp.StatusCode, resp.body)
	}
	got := decode[CapabilitiesJSON](t, resp)
	if !got.PluginsManageable || len(got.Hub.Plugins) != 2 || got.Hub.Plugins[0].Name != "go-lamp" ||
		got.Hub.Plugins[0].Digest != lampV1 || got.Hub.Plugins[1].Digest != zeta {
		t.Fatalf("after allow = %+v, want sorted grants pinned to the uploads", got.Hub.Plugins)
	}
	if len(got.PluginReleases) != 2 || got.PluginReleases[0].Digest != lampV1 {
		t.Fatalf("releases = %+v", got.PluginReleases)
	}
	// Lowering a class, or removing one, never asks.
	other := staleSession(t, f)
	if resp := f.do(t, http.MethodPut, capsPath, `{"hub":{"plugins":[{"name":"go-lamp","class":"read"}]}}`, other); resp.StatusCode != http.StatusOK {
		t.Fatalf("lower = %d %s", resp.StatusCode, resp.body)
	}
	if e := auditOf(t, f, policy.DeviceCapabilitiesSet); len(e) == 0 || !strings.Contains(string(e[0].Detail), "plugin:zeta") {
		t.Fatalf("lower audit = %+v", e)
	}

	// A new release uploaded: the grant stays on the old one until moved,
	// and moving it is a raise.
	lampV2 := saveRelease(t, f.st, "go-lamp", "v2")
	got = decode[CapabilitiesJSON](t, f.do(t, http.MethodGet, capsPath, "", other))
	if got.Hub.Plugins[0].Digest != lampV1 || got.PluginReleases[0].Digest != lampV2 {
		t.Fatalf("after a new upload = %+v / %+v", got.Hub.Plugins, got.PluginReleases)
	}
	if resp := f.do(t, http.MethodPut, capsPath, `{"hub":{"plugins":[{"name":"go-lamp","class":"read"}]}}`, other); resp.StatusCode != http.StatusOK ||
		decode[CapabilitiesJSON](t, resp).Hub.Plugins[0].Digest != lampV1 {
		t.Fatalf("set without a digest = %d %s, want the release kept", resp.StatusCode, resp.body)
	}
	for _, d := range []string{LatestRelease, lampV2} {
		resp := f.do(t, http.MethodPut, capsPath, `{"hub":{"plugins":[{"name":"go-lamp","class":"read","digest":"`+d+`"}]}}`, other)
		if resp.StatusCode != http.StatusForbidden || errorCode(t, resp) != "reauth_required" {
			t.Fatalf("move to %s without re-auth = %d %s", d, resp.StatusCode, resp.body)
		}
	}
	if resp := f.do(t, http.MethodPut, capsPath, `{"hub":{"plugins":[{"name":"go-lamp","class":"read","digest":"latest"}]}}`, stale); resp.StatusCode != http.StatusOK ||
		decode[CapabilitiesJSON](t, resp).Hub.Plugins[0].Digest != lampV2 {
		t.Fatalf("approve the new release = %d %s", resp.StatusCode, resp.body)
	}

	// A device on --local-ceiling refuses them too.
	reportHello(t, f, "pi", piHello(14, true, &agentv1.Ceiling{}))
	if resp := f.do(t, http.MethodPut, capsPath, `{"hub":{}}`, other); resp.StatusCode != http.StatusConflict {
		t.Fatalf("locked = %d", resp.StatusCode)
	}
}

func TestChangeOfPlugins(t *testing.T) {
	g := func(gs ...string) *agentv1.Ceiling {
		c := &agentv1.Ceiling{}
		for _, s := range gs {
			rest, digest, _ := strings.Cut(s, "@")
			name, class, _ := strings.Cut(rest, ":")
			c.Plugins = append(c.Plugins, &agentv1.PluginGrant{Name: name, MaxClass: class, Digest: strings.Repeat(digest, 64)})
		}
		return c
	}
	for _, tt := range []struct {
		old, next *agentv1.Ceiling
		want      policy.Action
	}{
		{g(), g("lamp:read@a"), policy.DeviceCapabilitiesRaise},
		{g("lamp:read@a"), g("lamp:safe@a"), policy.DeviceCapabilitiesRaise},
		{g("lamp:safe@a"), g("lamp:read@a"), policy.DeviceCapabilitiesSet},
		{g("lamp:safe@a"), g(), policy.DeviceCapabilitiesSet},
		{g("lamp:safe@a"), g("lamp:safe@a"), policy.DeviceCapabilitiesSet},
		{g("lamp:dangerous@a"), g("lamp:read@a", "load:read@b"), policy.DeviceCapabilitiesRaise},
		// Another release, even at a lower class, is a raise.
		{g("lamp:dangerous@a"), g("lamp:read@b"), policy.DeviceCapabilitiesRaise},
	} {
		if got := ChangeOf(tt.old, tt.next); got.Action != tt.want {
			t.Errorf("ChangeOf(%v, %v) = %+v, want %s", tt.old, tt.next, got, tt.want)
		}
	}
}

func TestSetCapabilityPlugins(t *testing.T) {
	var c Ceiling
	if err := SetCapability(&c, "plugins", "go-lamp:safe, load"); err != nil {
		t.Fatal(err)
	}
	if len(c.Plugins) != 2 || c.Plugins[0] != (PluginGrant{"go-lamp", policy.Safe, ""}) || c.Plugins[1] != (PluginGrant{"load", policy.Read, ""}) {
		t.Fatalf("plugins = %+v", c.Plugins)
	}
	// A grant keeps its release unless @latest moves it.
	d := strings.Repeat("d", 64)
	c.Plugins[0].Digest, c.Plugins[1].Digest = d, d
	if err := SetCapability(&c, "plugins", "go-lamp:read,load@latest"); err != nil {
		t.Fatal(err)
	}
	if c.Plugins[0] != (PluginGrant{"go-lamp", policy.Read, d}) || c.Plugins[1] != (PluginGrant{"load", policy.Read, LatestRelease}) {
		t.Fatalf("plugins = %+v", c.Plugins)
	}
	c.Plugins[1].Digest = d
	if _, err := NormalizeCeiling(c); err != nil {
		t.Fatal(err)
	}
	// The hub never sets a grant without a release.
	c.Plugins[1].Digest = ""
	if _, err := NormalizeCeiling(c); err == nil {
		t.Error("a grant without a release was taken")
	}
	if err := SetCapability(&c, "plugins", "on"); err == nil {
		t.Error("plugins=on was taken")
	}
	if err := SetCapability(&c, "plugins", "off"); err != nil || len(c.Plugins) != 0 {
		t.Errorf("off = %+v, %v", c.Plugins, err)
	}
	c.Plugins = []PluginGrant{{"x", "root", d}}
	if _, err := NormalizeCeiling(c); err == nil {
		t.Error("a bad class was taken")
	}
}

// TestDevicePluginsOfOldAgent: the device's plugins say an agent too old for
// them must be upgraded, and a command is refused before it is sent.
func TestDevicePluginsOfOldAgent(t *testing.T) {
	f := newWebAdminFixture(t, policy.Config{})
	f.api.agents = NewAgents(f.st.Devices())
	reportHello(t, f, "pi", agentHello(13, false, &agentv1.Ceiling{Plugins: []*agentv1.PluginGrant{{Name: "go-lamp", MaxClass: "safe"}}}))
	runner := DevicePluginRunner{Agents: f.api.agents, Store: f.st, Policy: f.api.policy}
	got, err := runner.Device(t.Context(), "pi")
	if err != nil {
		t.Fatal(err)
	}
	if got.Supported || got.Connected || len(got.Plugins) != 1 || got.Plugins[0].Installed {
		t.Fatalf("device plugins = %+v", got)
	}
	s := &agentSession{minor: 13, ceiling: &agentv1.Ceiling{Plugins: []*agentv1.PluginGrant{{Name: "go-lamp", MaxClass: "safe"}}}}
	if err := f.api.agents.checkPlugin(t.Context(), s, "pi", "go-lamp", strings.Repeat("a", 64), policy.Read); err == nil || !strings.Contains(err.Error(), "upgrade") {
		t.Fatalf("old agent check = %v", err)
	}
}

// TestCheckPlugin: the hub sends a plugin command only for a release the
// device's grants pin, up to their class, and takes a grant the agent
// reports only when the hub set it or the agent's own flags hold it.
func TestCheckPlugin(t *testing.T) {
	f := newWebAdminFixture(t, policy.Config{})
	a := NewAgents(f.st.Devices())
	a.SetPlugins(f.st, nil)
	dA, dB := strings.Repeat("a", 64), strings.Repeat("b", 64)
	set := &agentv1.Ceiling{Plugins: []*agentv1.PluginGrant{{Name: "go-lamp", MaxClass: "safe", Digest: dA}}}
	b, err := protojson.Marshal(set)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.st.DeviceCeilings().Set(t.Context(), "pi", b, "test", time.Now()); err != nil {
		t.Fatal(err)
	}
	local := &agentv1.Ceiling{Plugins: []*agentv1.PluginGrant{{Name: "own", MaxClass: "read"}}}
	reportHello(t, f, "pi", piHello(14, false, local))
	reported := proto.CloneOf(set)
	reported.Plugins = append(reported.Plugins,
		&agentv1.PluginGrant{Name: "own", MaxClass: "read"},
		// Claimed by the device, set by no one.
		&agentv1.PluginGrant{Name: "stolen", MaxClass: "dangerous", Digest: dB},
		&agentv1.PluginGrant{Name: "own", MaxClass: "dangerous", Digest: dB})
	s := &agentSession{minor: 14, ceiling: reported}
	for _, tt := range []struct {
		name, plugin, digest string
		class                policy.Class
		ok                   bool
	}{
		{"pinned release", "go-lamp", dA, policy.Safe, true},
		{"above the class", "go-lamp", dA, policy.Dangerous, false},
		{"another release", "go-lamp", dB, policy.Read, false},
		{"own flag, pinned by the agent", "own", dB, policy.Read, true},
		{"own flag, above its class", "own", dB, policy.Dangerous, false},
		{"claimed by the device", "stolen", dB, policy.Read, false},
		{"off the ceiling", "other", dA, policy.Read, false},
	} {
		err := a.checkPlugin(t.Context(), s, "pi", tt.plugin, tt.digest, tt.class)
		if (err == nil) != tt.ok || (err != nil && !errors.Is(err, policy.ErrBeyondCeiling)) {
			t.Errorf("%s: %v, want ok %v", tt.name, err, tt.ok)
		}
	}
	// On --local-ceiling, the hub's grants count for nothing.
	reportHello(t, f, "pi", piHello(14, true, local))
	if err := a.checkPlugin(t.Context(), s, "pi", "go-lamp", dA, policy.Read); !errors.Is(err, policy.ErrBeyondCeiling) {
		t.Errorf("locked device: %v", err)
	}
}

// TestPluginBlobsFetch: a hub lacking a program fetches it from the hub that
// holds it, and refuses one whose SHA-256 is not the one asked for.
func TestPluginBlobsFetch(t *testing.T) {
	holder := NewPluginBlobs(t.TempDir())
	sum, _, err := holder.Save(strings.NewReader("program"))
	if err != nil {
		t.Fatal(err)
	}
	evil := NewPluginBlobs(t.TempDir())
	evilSum, _, err := evil.Save(strings.NewReader("other"))
	if err != nil {
		t.Fatal(err)
	}
	// The holder serves sum's name with evil's bytes.
	if err := os.Rename(filepath.Join(evil.dir, evilSum), filepath.Join(evil.dir, sum)); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name  string
		serve *PluginBlobs
		ok    bool
	}{{"good", holder, true}, {"wrong bytes", evil, false}} {
		t.Run(tt.name, func(t *testing.T) {
			mux := http.NewServeMux()
			mux.HandleFunc("GET /agents/plugin-blobs/{sum}", tt.serve.serveLocal)
			b := NewPluginBlobs(t.TempDir())
			b.masters = &linkMasters{self: "hub-b", handler: mux}
			f, err := b.Open(t.Context(), sum, "hub-a")
			if tt.ok != (err == nil) {
				t.Fatalf("Open = %v, want ok %v", err, tt.ok)
			}
			if err == nil {
				got, _ := io.ReadAll(f)
				_ = f.Close()
				if string(got) != "program" {
					t.Fatalf("fetched %q", got)
				}
				return
			}
			if !strings.Contains(err.Error(), "SHA-256") {
				t.Errorf("err = %v", err)
			}
			if _, err := os.Stat(filepath.Join(b.dir, sum)); !os.IsNotExist(err) {
				t.Errorf("kept a program of the wrong SHA-256: %v", err)
			}
		})
	}
	if _, err := NewPluginBlobs(t.TempDir()).Open(t.Context(), sum, "hub-a"); err == nil {
		t.Error("a single hub opened a program it does not hold")
	}
	// A holder that is not a live master is never dialled.
	dialled := false
	b := NewPluginBlobs(t.TempDir())
	b.masters = &linkMasters{self: "hub-b", live: []string{"hub-a"}, handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		dialled = true
		http.NotFound(w, nil)
	})}
	if _, err := b.Open(t.Context(), sum, "storage-c"); err == nil || dialled {
		t.Errorf("fetched from a storage member: %v, dialled %v", err, dialled)
	}
}

// linkMasters is a Masters whose link serves handler; live, when set, are
// the live masters.
type linkMasters struct {
	self    string
	live    []string
	handler http.Handler
}

func (m *linkMasters) Self() string { return m.self }
func (m *linkMasters) Live(id string) bool {
	return m.live == nil || slices.Contains(m.live, id)
}
func (m *linkMasters) AgentURLOf(context.Context, string) string { return "" }
func (m *linkMasters) OwnerOf(string) string                     { return m.self }
func (m *linkMasters) Client() *http.Client {
	return &http.Client{Transport: handlerTransport{m.handler}}
}

type handlerTransport struct{ h http.Handler }

func (t handlerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	rec := httptest.NewRecorder()
	t.h.ServeHTTP(rec, r)
	return rec.Result(), nil
}

// TestPluginBlobHandler: a device downloads only the program of a release
// its grants allow (the hub's record, not only what it reports), over its
// own stream's identity.
func TestPluginBlobHandler(t *testing.T) {
	st := newTestStore(t)
	a := NewAgents(st.Devices())
	blobs := NewPluginBlobs(t.TempDir())
	a.SetPlugins(st, blobs)
	sum, size, err := blobs.Save(strings.NewReader("program"))
	if err != nil {
		t.Fatal(err)
	}
	other, _, err := blobs.Save(strings.NewReader("stray"))
	if err != nil {
		t.Fatal(err)
	}
	m, err := plugins.ParseManifest([]byte(lampManifest))
	if err != nil {
		t.Fatal(err)
	}
	u := DevicePluginUpload{Manifest: m, OS: "linux", Arch: "arm64", SHA256: sum, Size: size}
	if err := u.Save(t.Context(), st, "", "test", time.Now()); err != nil {
		t.Fatal(err)
	}
	grantOf := func(digest string) *agentv1.Ceiling {
		return &agentv1.Ceiling{Plugins: []*agentv1.PluginGrant{{Name: "go-lamp", MaxClass: "read", Digest: digest}}}
	}
	digest := u.Release().Digest()
	for id, c := range map[string]*agentv1.Ceiling{"pi": grantOf(digest), "nas": {}, "liar": {}, "old": grantOf(strings.Repeat("e", 64))} {
		enrollDevice(t, st, id)
		b, err := protojson.Marshal(c)
		if err != nil {
			t.Fatal(err)
		}
		if err := st.DeviceCeilings().Set(t.Context(), id, b, "test", time.Now()); err != nil {
			t.Fatal(err)
		}
		a.sessions[id] = &agentSession{minor: minPluginMinor, ceiling: c}
	}
	// liar reports a grant the hub never set for it.
	a.sessions["liar"].ceiling = grantOf(digest)
	h := a.pluginBlobHandler()
	for _, tt := range []struct {
		name, device, sum string
		status            int
	}{
		{"allowed", "pi", sum, http.StatusOK},
		{"no client certificate", "", sum, http.StatusNotFound},
		{"not in the ceiling", "nas", sum, http.StatusNotFound},
		{"claimed, not set", "liar", sum, http.StatusNotFound},
		{"another release pinned", "old", sum, http.StatusNotFound},
		{"no stream here", "tv", sum, http.StatusForbidden},
		{"not in the registry", "pi", other, http.StatusNotFound},
		{"not a SHA-256", "pi", "..%2Fca.key", http.StatusNotFound},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, plugins.BlobPath+tt.sum, nil)
			if tt.device != "" {
				r = r.WithContext(withDeviceID(r.Context(), tt.device))
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != tt.status {
				t.Fatalf("= %d %s, want %d", w.Code, w.Body, tt.status)
			}
			if tt.status == http.StatusOK && w.Body.String() != "program" {
				t.Fatalf("body = %q", w.Body)
			}
		})
	}
}
