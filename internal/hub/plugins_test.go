// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"net/http"
	"path/filepath"
	"testing"

	"github.com/gvart/hearth/internal/plugins"
	"github.com/gvart/hearth/internal/policy"
)

func TestAPIPluginsNotConfigured(t *testing.T) {
	f := newAPIFixture(t, true)
	cookie := sessionCookie(t, f.login(t, testPassword))
	if resp := f.do(t, http.MethodGet, "/api/v1/plugins", "", cookie); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status %d, want 404", resp.StatusCode)
	}
}

// The API serves the manager's plugins behind the admin session, and every
// command goes through policy: an undeclared one is denied and audited.
// (internal/plugins tests running plugins; this one only the wiring, with a
// plugin whose program does not exist, so it never runs.)
func TestAPIPlugins(t *testing.T) {
	var mgr *plugins.Manager
	f := newAPIFixture(t, true, func(c *Config) {
		var err error
		mgr, err = plugins.New(plugins.Config{Policy: c.Policy, Manifests: []plugins.Manifest{{
			Protocol: 1, Name: "lamp", Version: "1", Command: filepath.Join(t.TempDir(), "missing"),
			Capabilities: []string{plugins.CapCommand},
			Commands:     []plugins.CommandSpec{{Name: "turn_on", Class: policy.Safe}},
		}}})
		if err != nil {
			t.Fatal(err)
		}
		c.Plugins = mgr
	})
	if resp := f.do(t, http.MethodGet, "/api/v1/plugins", "", nil); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("without a session: %d, want 401", resp.StatusCode)
	}
	if resp := f.do(t, http.MethodPost, "/api/v1/plugins/lamp/commands", `{"command":"turn_on"}`, nil); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("command without a session: %d, want 401", resp.StatusCode)
	}
	cookie := sessionCookie(t, f.login(t, testPassword))
	resp := f.do(t, http.MethodGet, "/api/v1/plugins", "", cookie)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	got := decode[struct{ Plugins []plugins.Status }](t, resp)
	if len(got.Plugins) != 1 || got.Plugins[0].Name != "lamp" || len(got.Plugins[0].Commands) != 1 {
		t.Fatalf("body = %+v", got)
	}

	for _, tt := range []struct {
		name, path, body string
		want             int
	}{
		{"undeclared command", "/api/v1/plugins/lamp/commands", `{"command":"format_disk"}`, http.StatusForbidden},
		{"plugin not running", "/api/v1/plugins/lamp/commands", `{"command":"turn_on"}`, http.StatusServiceUnavailable},
		{"unknown plugin", "/api/v1/plugins/nope/commands", `{"command":"turn_on"}`, http.StatusNotFound},
		{"bad body", "/api/v1/plugins/lamp/commands", `[]`, http.StatusBadRequest},
		{"bad command", "/api/v1/plugins/lamp/commands", `{"command":"a b"}`, http.StatusBadRequest},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if resp := f.do(t, http.MethodPost, tt.path, tt.body, cookie); resp.StatusCode != tt.want {
				t.Fatalf("status %d, want %d", resp.StatusCode, tt.want)
			}
		})
	}

	entries, err := f.st.Audit().List(t.Context(), 100)
	if err != nil {
		t.Fatal(err)
	}
	var denied, ran bool
	for _, e := range entries {
		switch {
		case e.Action == string(policy.PluginCommandDangerous) && e.Decision == policy.Deny && e.Target == "lamp/format_disk":
			denied = true
		case e.Action == string(policy.PluginCommandSafe) && e.Decision == policy.Allow && e.Target == "lamp/turn_on":
			ran = true
		}
	}
	if !denied || !ran {
		t.Errorf("audit log: denied undeclared %v, allowed declared %v; entries %+v", denied, ran, entries)
	}
}
