// SPDX-License-Identifier: AGPL-3.0-only

package mcpserver

import (
	"context"
	"strings"
	"testing"

	"github.com/gvart/hearth/internal/plugins"
	"github.com/gvart/hearth/internal/policy"
)

// fakeDevicePlugins is plugin "lamp" on device "pi", deciding each command
// through policy with its manifest's class, as hub.DevicePluginRunner does.
type fakeDevicePlugins struct {
	pol *policy.Engine
	ran []string
}

func (p *fakeDevicePlugins) DevicePluginsOf(_ context.Context, device string) (any, error) {
	return map[string]any{"device": device, "plugins": []string{"lamp"}}, nil
}

func (p *fakeDevicePlugins) Run(ctx context.Context, kind, actor, device, name string, req plugins.CommandRequest) (plugins.CommandResult, error) {
	action := policy.DevicePluginCommandDangerous
	for _, c := range lampCommands {
		if c.Name == req.Command {
			action = policy.Action("device.plugin.command." + string(c.Class))
		}
	}
	err := p.pol.Do(ctx, policy.Request{ActorKind: kind, ActorID: actor, Action: action, Target: device},
		func(context.Context) error {
			p.ran = append(p.ran, device+" "+name+" "+req.Command+" "+req.Device)
			return nil
		})
	return plugins.CommandResult{Output: "done"}, err
}

func TestDevicePluginTools(t *testing.T) {
	f := newFixture(t, policy.Config{})
	for _, name := range toolNames(t, f.mustConnect(t, "admin-token")) {
		if strings.Contains(name, "device_plugin") {
			t.Errorf("a hub without device plugins offers %s", name)
		}
	}
	dp := &fakeDevicePlugins{}
	f = newFixture(t, policy.Config{}, func(c *Config) { c.DevicePlugins = dp })
	dp.pol = f.pol
	text, isErr := call(t, f.mustConnect(t, "reader-token"), "list_device_plugins", map[string]any{"device": "pi"})
	if isErr || !strings.Contains(text, "lamp") {
		t.Fatalf("list_device_plugins = %q (error %v)", text, isErr)
	}
	if e := f.lastAudit(t); e.Action != string(policy.DeviceRead) || e.Target != "pi" {
		t.Errorf("audit = %+v", e)
	}
	// The manifest's class, capped by the token's scope.
	if _, isErr := call(t, f.mustConnect(t, "reader-token"), "device_plugin_command",
		map[string]any{"device": "pi", "plugin": "lamp", "command": "turn_on"}); !isErr || len(dp.ran) != 0 {
		t.Fatalf("a read token ran a safe command: %v", dp.ran)
	}
	if e := f.lastAudit(t); e.Action != string(policy.DevicePluginCommandSafe) || e.Decision != policy.Deny {
		t.Errorf("audit = %+v", e)
	}
	text, isErr = call(t, f.mustConnect(t, "safe-token"), "device_plugin_command",
		map[string]any{"device": "pi", "plugin": "lamp", "command": "turn_on", "target": "desk"})
	if isErr || text != "done" || len(dp.ran) != 1 || dp.ran[0] != "pi lamp turn_on desk" {
		t.Fatalf("device_plugin_command = %q (error %v), ran %v", text, isErr, dp.ran)
	}
}
