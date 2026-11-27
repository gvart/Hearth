// SPDX-License-Identifier: AGPL-3.0-only

package mcpserver

import (
	"context"
	"encoding/json"

	"github.com/gvart/hearth/internal/plugins"
	"github.com/gvart/hearth/internal/policy"
)

// DevicePlugins are the exec plugins on devices (#223): hub.DevicePluginRunner.
type DevicePlugins interface {
	// DevicePluginsOf is the plugins of device: those its ceiling allows,
	// whether its agent installed each, and their commands.
	DevicePluginsOf(ctx context.Context, device string) (any, error)
	// Run decides and audits a command of plugin name on device, with the
	// class the plugin's manifest declares, and runs it through the agent.
	Run(ctx context.Context, actorKind, actorID, device, name string, req plugins.CommandRequest) (plugins.CommandResult, error)
}

// devicePluginTools are the tools of the plugins on devices; none without
// them.
func (s *session) devicePluginTools() []tool {
	if s.cfg.DevicePlugins == nil {
		return nil
	}
	return []tool{
		newTool(policy.Read, "list_device_plugins",
			"List the exec plugins on a device: those its capabilities allow, with the highest class of command each may run, "+
				"whether its agent installed it, and the commands it declares with their policy class.",
			s.listDevicePlugins),
		// Read: the lowest class a command may have. The class of each
		// command is its manifest's, and the token's scope caps it.
		newTool(policy.Read, "device_plugin_command",
			"Run a command of an exec plugin on a device, through its agent. The command's policy class is the one its "+
				"manifest declares (list_device_plugins shows it): a dangerous one is usually held until an operator approves it.",
			s.devicePluginCommand),
	}
}

type devicePluginsIn struct {
	Device string `json:"device" jsonschema:"the device's id, name or hostname"`
}

func (s *session) listDevicePlugins(ctx context.Context, in devicePluginsIn) (any, error) {
	var out any
	err := s.do(ctx, policy.Request{Action: policy.DeviceRead, Target: in.Device}, func(ctx context.Context) error {
		var err error
		out, err = s.cfg.DevicePlugins.DevicePluginsOf(ctx, in.Device)
		return err
	})
	return out, err
}

type devicePluginCommandIn struct {
	Device  string         `json:"device" jsonschema:"the device's id, name or hostname"`
	Plugin  string         `json:"plugin" jsonschema:"the plugin's name, as list_device_plugins shows it"`
	Command string         `json:"command" jsonschema:"a command the plugin declares"`
	Target  string         `json:"target,omitempty" jsonschema:"the plugin's own device id the command is for, if any"`
	Args    map[string]any `json:"args,omitempty" jsonschema:"the command's arguments: a JSON object"`
}

func (s *session) devicePluginCommand(ctx context.Context, in devicePluginCommandIn) (any, error) {
	var args json.RawMessage
	if len(in.Args) > 0 {
		var err error
		if args, err = json.Marshal(in.Args); err != nil {
			return nil, err
		}
	}
	// The runner decides and audits it, as this token, with the class the
	// manifest declares; the token's scope caps it.
	res, err := s.cfg.DevicePlugins.Run(s.scoped(ctx), policy.ActorMCP, s.tok.Name, in.Device, in.Plugin, plugins.CommandRequest{
		Command: in.Command, Device: in.Target, Args: args,
	})
	if err != nil {
		return nil, err
	}
	if res.Output == "" {
		return "(the command printed nothing)", nil
	}
	return res.Output, nil
}
