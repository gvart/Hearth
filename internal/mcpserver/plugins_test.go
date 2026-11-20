// SPDX-License-Identifier: AGPL-3.0-only

package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/gvart/hearth/internal/plugins"
	"github.com/gvart/hearth/internal/policy"
)

// fakePlugins is plugin "lamp", whose commands are of the classes in its
// manifest. Like the manager, it decides each command through policy with
// the manifest's class, and records the ones that ran.
type fakePlugins struct {
	pol *policy.Engine
	mu  sync.Mutex
	ran []string
}

var lampCommands = []plugins.CommandSpec{
	{Name: "status", Class: policy.Read}, {Name: "turn_on", Class: policy.Safe}, {Name: "reflash", Class: policy.Dangerous},
}

func (p *fakePlugins) Plugins() []plugins.Status {
	return []plugins.Status{{
		Name: "lamp", Version: "1.0", State: plugins.StateRunning, Commands: lampCommands,
		Devices: []plugins.Device{{ID: "desk", Name: "Desk lamp", Entities: []plugins.Entity{{ID: "on", State: json.RawMessage("true")}}}},
		Stderr:  []string{"secret-in-stderr"},
	}}
}

func (p *fakePlugins) Command(ctx context.Context, kind, actor, name string, req plugins.CommandRequest) (plugins.CommandResult, error) {
	if name != "lamp" {
		return plugins.CommandResult{}, plugins.ErrNotFound
	}
	action, declared := policy.PluginCommandDangerous, false
	for _, c := range lampCommands {
		if c.Name == req.Command {
			action, declared = policy.Action("plugin.command."+string(c.Class)), true
		}
	}
	preq := policy.Request{ActorKind: kind, ActorID: actor, Action: action, Target: name + "/" + req.Command}
	if !declared {
		preq.Precheck = func(context.Context) error { return fmt.Errorf("undeclared: %w", policy.ErrDenied) }
	}
	err := p.pol.Do(ctx, preq, func(context.Context) error {
		p.mu.Lock()
		defer p.mu.Unlock()
		p.ran = append(p.ran, req.Command+" "+req.Device+" "+string(req.Args))
		return nil
	})
	return plugins.CommandResult{Output: "done " + req.Command}, err
}

func (p *fakePlugins) calls() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.ran...)
}

func pluginFixture(t *testing.T, cfg policy.Config) (*fixture, *fakePlugins) {
	t.Helper()
	pl := &fakePlugins{}
	f := newFixture(t, cfg, func(c *Config) { c.Plugins = pl })
	pl.pol = f.pol
	return f, pl
}

func TestPluginToolsOnlyWithPlugins(t *testing.T) {
	f := newFixture(t, policy.Config{})
	for _, name := range toolNames(t, f.mustConnect(t, "admin-token")) {
		if strings.Contains(name, "plugin") {
			t.Errorf("a hub without plugins offers %s", name)
		}
	}
	f, _ = pluginFixture(t, policy.Config{})
	got := toolNames(t, f.mustConnect(t, "reader-token"))
	for _, want := range []string{"list_plugins", "plugin_command"} {
		if !strings.Contains(strings.Join(got, " "), want) {
			t.Errorf("a read token is not offered %s: %v", want, got)
		}
	}
}

func TestListPlugins(t *testing.T) {
	f, _ := pluginFixture(t, policy.Config{})
	text, isErr := call(t, f.mustConnect(t, "reader-token"), "list_plugins", nil)
	if isErr || !strings.Contains(text, `"Desk lamp"`) || !strings.Contains(text, `"class": "dangerous"`) {
		t.Fatalf("list_plugins = %q (error %v)", text, isErr)
	}
	if strings.Contains(text, "secret-in-stderr") {
		t.Errorf("list_plugins shows the plugin's stderr: %s", text)
	}
	if e := f.lastAudit(t); e.Action != string(policy.DeviceRead) || e.Target != "plugins" || e.ActorID != "reader" || e.Decision != policy.Allow {
		t.Errorf("audit = %+v", e)
	}
}

// Each command runs with its manifest's class, capped by the token's scope;
// denials are audited and never reach the plugin.
func TestPluginCommandFollowsClassAndScope(t *testing.T) {
	tests := []struct {
		token, command string
		cfg            policy.Config
		ok             bool
		action         policy.Action
		decision       string
	}{
		{"reader-token", "status", policy.Config{}, true, policy.PluginCommandRead, policy.Allow},
		{"reader-token", "turn_on", policy.Config{}, false, policy.PluginCommandSafe, policy.Deny},
		{"safe-token", "turn_on", policy.Config{}, true, policy.PluginCommandSafe, policy.Allow},
		{"safe-token", "reflash", policy.Config{}, false, policy.PluginCommandDangerous, policy.Deny},
		{"admin-token", "self_destruct", policy.Config{}, false, policy.PluginCommandDangerous, policy.Deny},
		{
			"admin-token", "turn_on",
			policy.Config{Actors: map[string]map[policy.Class]policy.Mode{policy.ActorMCP: {policy.Safe: policy.ModeDeny}}},
			false, policy.PluginCommandSafe, policy.Deny,
		},
	}
	for _, tt := range tests {
		t.Run(tt.token+" "+tt.command, func(t *testing.T) {
			f, pl := pluginFixture(t, tt.cfg)
			text, isErr := call(t, f.mustConnect(t, tt.token), "plugin_command",
				map[string]any{"plugin": "lamp", "command": tt.command, "device": "desk", "args": map[string]any{"level": 2}})
			if isErr == tt.ok {
				t.Fatalf("plugin_command = %q (error %v), want ok %v", text, isErr, tt.ok)
			}
			if want := map[bool]int{true: 1, false: 0}[tt.ok]; len(pl.calls()) != want {
				t.Errorf("ran %q, want %d", pl.calls(), want)
			}
			if tt.ok && pl.calls()[0] != tt.command+` desk {"level":2}` {
				t.Errorf("ran %q", pl.calls())
			}
			e := f.lastAudit(t)
			if e.ActorKind != policy.ActorMCP || e.Action != string(tt.action) || e.Decision != tt.decision || e.Target != "lamp/"+tt.command {
				t.Errorf("audit = %+v", e)
			}
		})
	}
}
