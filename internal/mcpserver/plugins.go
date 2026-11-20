// SPDX-License-Identifier: AGPL-3.0-only

package mcpserver

import (
	"context"
	"encoding/json"

	"github.com/gvart/hearth/internal/plugins"
	"github.com/gvart/hearth/internal/policy"
)

// Plugins are the hub's exec plugins: *plugins.Manager.
type Plugins interface {
	Plugins() []plugins.Status
	Command(ctx context.Context, actorKind, actorID, name string, req plugins.CommandRequest) (plugins.CommandResult, error)
}

// pluginTools are the tools of the hub's exec plugins; none without them.
func (s *session) pluginTools() []tool {
	if s.cfg.Plugins == nil {
		return nil
	}
	return []tool{
		newTool(policy.Read, "list_plugins",
			"List the hub's exec plugins: their state, the devices and entities (with their last state) each reports, "+
				"and the commands each declares with its policy class.",
			s.listPlugins),
		// Read: the lowest class a command may have. The class of each
		// command is its manifest's, and the token's scope caps it.
		newTool(policy.Read, "plugin_command",
			"Run a command an exec plugin declares, optionally for one of its devices. The command's policy class is "+
				"the one its manifest declares (list_plugins shows it): a dangerous one is usually held until an operator approves it.",
			s.pluginCommand),
	}
}

// pluginView is a plugin as list_plugins shows it: its status without the
// tail of its stderr, which only signed-in admins see.
type pluginView struct {
	Name     string                `json:"name"`
	Version  string                `json:"version"`
	State    string                `json:"state"`
	Error    string                `json:"error,omitempty"`
	Commands []plugins.CommandSpec `json:"commands"`
	Devices  []plugins.Device      `json:"devices"`
}

func (s *session) listPlugins(ctx context.Context, _ struct{}) (any, error) {
	out := []pluginView{}
	err := s.do(ctx, policy.Request{Action: policy.DeviceRead, Target: "plugins"}, func(context.Context) error {
		for _, p := range s.cfg.Plugins.Plugins() {
			out = append(out, pluginView{
				Name: p.Name, Version: p.Version, State: p.State, Error: p.Error, Commands: p.Commands, Devices: p.Devices,
			})
		}
		return nil
	})
	return out, err
}

type pluginCommandIn struct {
	Plugin  string         `json:"plugin" jsonschema:"the plugin's name, as list_plugins shows it"`
	Command string         `json:"command" jsonschema:"a command the plugin declares"`
	Device  string         `json:"device,omitempty" jsonschema:"the plugin's device id the command is for, if any"`
	Args    map[string]any `json:"args,omitempty" jsonschema:"the command's arguments: a JSON object"`
}

func (s *session) pluginCommand(ctx context.Context, in pluginCommandIn) (any, error) {
	var args json.RawMessage
	if len(in.Args) > 0 {
		var err error
		if args, err = json.Marshal(in.Args); err != nil {
			return nil, err
		}
	}
	// The manager decides and audits it, as this token, with the class the
	// manifest declares; the token's scope caps it.
	res, err := s.cfg.Plugins.Command(s.scoped(ctx), policy.ActorMCP, s.tok.Name, in.Plugin, plugins.CommandRequest{
		Command: in.Command, Device: in.Device, Args: args,
	})
	if err != nil {
		return nil, err
	}
	if res.Output == "" {
		return "(the command printed nothing)", nil
	}
	return res.Output, nil
}
