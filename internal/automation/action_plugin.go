// SPDX-License-Identifier: AGPL-3.0-only

package automation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/gvart/hearth/internal/plugins"
	"github.com/gvart/hearth/internal/policy"
)

// Plugins runs the commands of the hub's exec plugins: *plugins.Manager.
// RunGranted must not audit: the runtime runs it inside its own policy
// decision, and it refuses to run outside one.
type Plugins interface {
	// CommandPolicy is the policy action of a plugin's command, of the class
	// its manifest declares; declared is false for a plugin or command the
	// hub does not have.
	CommandPolicy(plugin, command string) (action policy.Action, declared bool)
	RunGranted(ctx context.Context, plugin string, req plugins.CommandRequest) (plugins.CommandResult, error)
}

// pluginAction runs a command an exec plugin's manifest declares. Its
// policy action is plugin.command.<class>, of the class the manifest
// declares: the automation never chooses it. A command the hub's plugins do
// not declare is plugin.command.dangerous, and denied.
type pluginAction struct {
	plugins         Plugins
	plugin, command string
	device          Text
	args            json.RawMessage
	policy          policy.Action
	declared        bool
}

func buildPluginCommand(p Params, pl Plugins) (Action, error) {
	var cfg struct {
		Plugin  string         `yaml:"plugin"`
		Command string         `yaml:"command"`
		Device  string         `yaml:"device"`
		Args    map[string]any `yaml:"args"`
	}
	if err := p.Decode(&cfg); err != nil {
		return nil, err
	}
	if cfg.Plugin == "" {
		return nil, errors.New("plugin is required")
	}
	if cfg.Command == "" {
		return nil, errors.New("command is required")
	}
	a := &pluginAction{plugins: pl, plugin: cfg.Plugin, command: cfg.Command, policy: policy.PluginCommandDangerous}
	if pl != nil {
		a.policy, a.declared = pl.CommandPolicy(cfg.Plugin, cfg.Command)
	}
	var err error
	if a.device, err = p.Text(cfg.Device, "device"); err != nil {
		return nil, err
	}
	if len(cfg.Args) > 0 {
		if a.args, err = json.Marshal(cfg.Args); err != nil {
			return nil, fmt.Errorf("args: %w", err)
		}
	}
	return a, nil
}

func (a *pluginAction) Describe() string {
	d := fmt.Sprintf("run command %s of plugin %s", a.command, a.plugin)
	if a.device.raw != "" {
		d += fmt.Sprintf(" on its device %s", a.device)
	}
	switch {
	case a.plugins == nil:
		return d + "; its class is the one the plugin's manifest declares on the hub"
	case !a.declared:
		return d + "; this hub's plugins declare no such command, so it is denied"
	}
	return d
}

func (a *pluginAction) Policy() policy.Action { return a.policy }

// Target is the one the web UI's commands audit: plugin/command.
func (a *pluginAction) Target() Text  { return Literal(a.plugin + "/" + a.command) }
func (a *pluginAction) texts() []Text { return []Text{a.device} }

// Precheck refuses, before policy decides, a command the hub's plugins do
// not declare: it is audited as a denied dangerous command, as the web UI's.
func (a *pluginAction) Precheck(context.Context, Event) error {
	if a.plugins == nil {
		return fmt.Errorf("this hub runs no plugin %s: %w", a.plugin, policy.ErrDenied)
	}
	if !a.declared {
		return fmt.Errorf("plugin %s declares no command %q on this hub: %w", a.plugin, a.command, policy.ErrDenied)
	}
	return nil
}

// Run sends the command. The runtime calls it inside the policy decision on
// it, which RunGranted checks.
func (a *pluginAction) Run(ctx context.Context, ev Event) error {
	if a.plugins == nil {
		return definiteFailure{fmt.Errorf("this hub runs no plugin %s", a.plugin)}
	}
	device, err := a.device.Render(ctx, ev)
	if err != nil {
		return err
	}
	_, err = a.plugins.RunGranted(ctx, a.plugin, plugins.CommandRequest{Command: a.command, Device: device, Args: a.args})
	switch {
	case err == nil, errors.Is(err, policy.ErrDenied):
		return err
	case errors.Is(err, plugins.ErrNotFound), errors.Is(err, plugins.ErrBadRequest), errors.Is(err, plugins.ErrBusy),
		errors.Is(err, plugins.ErrCommandFailed):
		// The plugin never got it, or answered that it failed.
		return definiteFailure{err}
	}
	// Sent and not answered: the plugin stopped or did not answer in time,
	// maybe after it acted.
	return fmt.Errorf("%w: %w", ErrOutcomeUnknown, err)
}
