// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"net/http"
	"path/filepath"
	"testing"

	"github.com/gvart/hearth/internal/plugins"
	"github.com/gvart/hearth/internal/policy"
)

// The plugin list says, by class, what policy decides now for the caller's
// commands, so the UI can show a command as held or refused before a run.
func TestAPIPluginDecisions(t *testing.T) {
	for _, tt := range []struct {
		name string
		cfg  policy.Config
		want map[policy.Class]string
	}{
		{"no policy file", policy.Config{}, map[policy.Class]string{
			policy.Read: policy.Allow, policy.Safe: policy.Allow, policy.Dangerous: policy.Allow,
		}},
		{
			"dangerous held, safe denied",
			policy.Config{Actors: map[string]map[policy.Class]policy.Mode{
				policy.ActorWeb: {policy.Dangerous: policy.ModeConfirm, policy.Safe: policy.ModeDeny},
			}},
			map[policy.Class]string{policy.Read: policy.Allow, policy.Safe: policy.Deny, policy.Dangerous: policy.Confirm},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := newAPIFixture(t, true, func(c *Config) {
				c.Policy = policy.NewWithConfig(c.Store.Audit(), c.Store.Approvals(), tt.cfg)
				mgr, err := plugins.New(plugins.Config{Policy: c.Policy, Manifests: []plugins.Manifest{{
					Protocol: 1, Name: "lamp", Version: "1", Command: filepath.Join(t.TempDir(), "missing"),
					Capabilities: []string{plugins.CapCommand},
					Commands:     []plugins.CommandSpec{{Name: "turn_on", Class: policy.Safe}},
				}}})
				if err != nil {
					t.Fatal(err)
				}
				c.Plugins = mgr
			})
			cookie := sessionCookie(t, f.login(t, testPassword))
			resp := f.do(t, http.MethodGet, "/api/v1/plugins", "", cookie)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status %d", resp.StatusCode)
			}
			got := decode[struct {
				Decisions map[policy.Class]string `json:"decisions"`
			}](t, resp)
			for class, want := range tt.want {
				if got.Decisions[class] != want {
					t.Errorf("decisions = %v, want %v", got.Decisions, tt.want)
					break
				}
			}
			// Checking decides nothing: no command entry is written.
			entries, err := f.st.Audit().List(t.Context(), 100)
			if err != nil {
				t.Fatal(err)
			}
			for _, e := range entries {
				if e.Action == string(policy.PluginCommandSafe) || e.Action == string(policy.PluginCommandDangerous) ||
					e.Action == string(policy.PluginCommandRead) {
					t.Errorf("listing wrote an audit entry: %+v", e)
				}
			}
		})
	}
}
