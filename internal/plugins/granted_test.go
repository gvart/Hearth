// SPDX-License-Identifier: AGPL-3.0-only

package plugins

import (
	"context"
	"errors"
	"testing"

	"github.com/gvart/hearth/internal/policy"
)

func TestCommandPolicyFollowsTheManifest(t *testing.T) {
	m, err := New(Config{Manifests: []Manifest{helperManifest(t, "p", "good")}})
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		plugin, command string
		want            policy.Action
		declared        bool
	}{
		{"p", "fail", policy.PluginCommandRead, true},
		{"p", "toggle", policy.PluginCommandSafe, true},
		{"p", "wipe", policy.PluginCommandDangerous, true},
		{"p", "format-disk", policy.PluginCommandDangerous, false},
		{"nope", "toggle", policy.PluginCommandDangerous, false},
	} {
		got, declared := m.CommandPolicy(tt.plugin, tt.command)
		if got != tt.want || declared != tt.declared {
			t.Errorf("CommandPolicy(%s, %s) = %s, %v; want %s, %v", tt.plugin, tt.command, got, declared, tt.want, tt.declared)
		}
	}
	var none *Manager
	if got, declared := none.CommandPolicy("p", "toggle"); got != policy.PluginCommandDangerous || declared {
		t.Errorf("nil manager: CommandPolicy = %s, %v", got, declared)
	}
}

func TestRunGrantedRunsOnlyInsideTheManifestsGrant(t *testing.T) {
	m, audit := startManager(t, policy.Config{}, helperManifest(t, "p", "good"))
	waitFor(t, "the plugin's devices", func() bool { return commandsRun(m, "p") == "0" })
	pol := policy.NewWithConfig(audit, nil, policy.Config{})

	// Outside any decision, or under the grant of another class, nothing runs.
	for _, tt := range []struct {
		name  string
		grant policy.Action
		req   CommandRequest
	}{
		{"no grant", "", CommandRequest{Command: "toggle"}},
		{"grant of a lower class", policy.PluginCommandRead, CommandRequest{Command: "toggle"}},
		{"grant of a higher class", policy.PluginCommandDangerous, CommandRequest{Command: "toggle"}},
		{"undeclared command", policy.PluginCommandDangerous, CommandRequest{Command: "format-disk"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			run := func(ctx context.Context) error {
				_, err := m.RunGranted(ctx, "p", tt.req)
				return err
			}
			var err error
			if tt.grant == "" {
				err = run(t.Context())
			} else {
				err = pol.Do(t.Context(), policy.Request{ActorKind: policy.ActorAutomation, ActorID: "a", Action: tt.grant}, run)
			}
			if !errors.Is(err, policy.ErrDenied) {
				t.Fatalf("err = %v, want ErrDenied", err)
			}
		})
	}
	if got := commandsRun(m, "p"); got != "0" {
		t.Fatalf("the plugin got a command run without its grant: commands run = %s", got)
	}

	var res CommandResult
	err := pol.Do(t.Context(), policy.Request{ActorKind: policy.ActorAutomation, ActorID: "a", Action: policy.PluginCommandSafe},
		func(ctx context.Context) error {
			var err error
			res, err = m.RunGranted(ctx, "p", CommandRequest{Command: "toggle", Device: "lamp"})
			return err
		})
	if err != nil || res.Output != "toggle lamp" {
		t.Fatalf("granted run: %q, %v", res.Output, err)
	}
	if _, err := m.RunGranted(t.Context(), "nope", CommandRequest{Command: "toggle"}); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown plugin: err = %v", err)
	}
}
