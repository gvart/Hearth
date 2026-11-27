// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"bytes"
	"context"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/plugins"
	"github.com/gvart/hearth/internal/policy"
	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
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
	reportHello(t, f, "pi", agentHello(13, false, &agentv1.Ceiling{}))
	stale := staleSession(t, f)
	if got := decode[CapabilitiesJSON](t, f.do(t, http.MethodGet, capsPath, "", stale)); got.PluginsManageable || got.Hub.Plugins == nil {
		t.Fatalf("minor 13 = %+v, want plugins not manageable", got)
	}
	reportHello(t, f, "pi", agentHello(14, false, &agentv1.Ceiling{}))

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
		`{"hub":{"plugins":[{"name":"lamp","class":"read"},{"name":"lamp","class":"safe"}]}}`,
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
	if !got.PluginsManageable || len(got.Hub.Plugins) != 2 || got.Hub.Plugins[0].Name != "go-lamp" {
		t.Fatalf("after allow = %+v, want sorted grants", got.Hub.Plugins)
	}
	// Lowering a class, or removing one, never asks.
	other := staleSession(t, f)
	if resp := f.do(t, http.MethodPut, capsPath, `{"hub":{"plugins":[{"name":"go-lamp","class":"read"}]}}`, other); resp.StatusCode != http.StatusOK {
		t.Fatalf("lower = %d %s", resp.StatusCode, resp.body)
	}
	if e := auditOf(t, f, policy.DeviceCapabilitiesSet); len(e) == 0 || !strings.Contains(string(e[0].Detail), "plugin:zeta") {
		t.Fatalf("lower audit = %+v", e)
	}

	// A device on --local-ceiling refuses them too.
	reportHello(t, f, "pi", agentHello(14, true, &agentv1.Ceiling{}))
	if resp := f.do(t, http.MethodPut, capsPath, `{"hub":{}}`, other); resp.StatusCode != http.StatusConflict {
		t.Fatalf("locked = %d", resp.StatusCode)
	}
}

func TestChangeOfPlugins(t *testing.T) {
	g := func(gs ...string) *agentv1.Ceiling {
		c := &agentv1.Ceiling{}
		for _, s := range gs {
			name, class, _ := strings.Cut(s, ":")
			c.Plugins = append(c.Plugins, &agentv1.PluginGrant{Name: name, MaxClass: class})
		}
		return c
	}
	for _, tt := range []struct {
		old, next *agentv1.Ceiling
		want      policy.Action
	}{
		{g(), g("lamp:read"), policy.DeviceCapabilitiesRaise},
		{g("lamp:read"), g("lamp:safe"), policy.DeviceCapabilitiesRaise},
		{g("lamp:safe"), g("lamp:read"), policy.DeviceCapabilitiesSet},
		{g("lamp:safe"), g(), policy.DeviceCapabilitiesSet},
		{g("lamp:safe"), g("lamp:safe"), policy.DeviceCapabilitiesSet},
		{g("lamp:dangerous"), g("lamp:read", "load:read"), policy.DeviceCapabilitiesRaise},
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
	if len(c.Plugins) != 2 || c.Plugins[0] != (PluginGrant{"go-lamp", policy.Safe}) || c.Plugins[1] != (PluginGrant{"load", policy.Read}) {
		t.Fatalf("plugins = %+v", c.Plugins)
	}
	if _, err := NormalizeCeiling(c); err != nil {
		t.Fatal(err)
	}
	if err := SetCapability(&c, "plugins", "on"); err == nil {
		t.Error("plugins=on was taken")
	}
	if err := SetCapability(&c, "plugins", "off"); err != nil || len(c.Plugins) != 0 {
		t.Errorf("off = %+v, %v", c.Plugins, err)
	}
	c.Plugins = []PluginGrant{{"x", "root"}}
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
	if err := s.checkPlugin("pi", "go-lamp", policy.Read); err == nil || !strings.Contains(err.Error(), "upgrade") {
		t.Fatalf("old agent check = %v", err)
	}
	s.minor = 14
	if err := s.checkPlugin("pi", "go-lamp", policy.Safe); err != nil {
		t.Fatal(err)
	}
	if err := s.checkPlugin("pi", "go-lamp", policy.Dangerous); err == nil {
		t.Fatal("a dangerous command passed a safe grant")
	}
	if err := s.checkPlugin("pi", "other", policy.Read); err == nil {
		t.Fatal("a plugin off the ceiling passed")
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
}

// linkMasters is a Masters whose link serves handler.
type linkMasters struct {
	self    string
	handler http.Handler
}

func (m *linkMasters) Self() string                              { return m.self }
func (m *linkMasters) Live(string) bool                          { return true }
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

// TestPluginBlobHandler: a device downloads only the program of a plugin
// its reported ceiling allows, over its own stream's identity.
func TestPluginBlobHandler(t *testing.T) {
	st := newTestStore(t)
	a := NewAgents(st.Devices())
	blobs := NewPluginBlobs(t.TempDir())
	a.SetPlugins(st.DevicePlugins(), blobs)
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
	grant := &agentv1.Ceiling{Plugins: []*agentv1.PluginGrant{{Name: "go-lamp", MaxClass: "read"}}}
	a.sessions["pi"] = &agentSession{minor: minPluginMinor, ceiling: grant}
	a.sessions["nas"] = &agentSession{minor: minPluginMinor, ceiling: &agentv1.Ceiling{}}
	h := a.pluginBlobHandler()
	for _, tt := range []struct {
		name, device, sum string
		status            int
	}{
		{"allowed", "pi", sum, http.StatusOK},
		{"no client certificate", "", sum, http.StatusNotFound},
		{"not in the ceiling", "nas", sum, http.StatusNotFound},
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
