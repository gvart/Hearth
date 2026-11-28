// SPDX-License-Identifier: AGPL-3.0-only

package plugins

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"time"

	"github.com/gvart/hearth/internal/policy"
)

// Errors of Manager.Command.
var (
	// ErrNotFound is a plugin that is not configured.
	ErrNotFound = errors.New("no such plugin")
	// ErrBadRequest is a malformed command request.
	ErrBadRequest = errors.New("bad plugin command")
	// ErrUnavailable is a plugin that is not running, or stopped while the
	// hub waited for it.
	ErrUnavailable = errors.New("plugin not running")
	// ErrBusy is a plugin with as many commands in flight as it is sent.
	// It matches ErrUnavailable.
	ErrBusy = fmt.Errorf("plugin busy: %w", ErrUnavailable)
	// ErrCommandFailed is a command the plugin ran and reported as failed.
	ErrCommandFailed = errors.New("plugin command failed")
)

// Policy decides and audits plugin starts and commands: *policy.Engine.
type Policy interface {
	Do(ctx context.Context, req policy.Request, fn func(context.Context) error) error
}

// Config holds a Manager's plugins and dependencies.
type Config struct {
	// Manifests are the plugins to run; none means none run.
	Manifests []Manifest
	Policy    Policy
	Log       *slog.Logger
	Options   Options
}

// Manager runs the configured plugins.
type Manager struct {
	plugins []*plugin
}

// New returns a manager of cfg's plugins, which must be valid and named
// uniquely. Call Run to start them.
func New(cfg Config) (*Manager, error) {
	log := cfg.Log
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	o := cfg.Options.withDefaults()
	m := &Manager{}
	seen := map[string]bool{}
	for _, man := range cfg.Manifests {
		if err := man.Validate(); err != nil {
			return nil, fmt.Errorf("plugin %s: %w", man.Name, err)
		}
		if seen[man.Name] {
			return nil, fmt.Errorf("plugin %s configured twice", man.Name)
		}
		seen[man.Name] = true
		m.plugins = append(m.plugins, &plugin{
			m: man, o: o, pol: cfg.Policy, log: log, now: time.Now, state: StateStopped,
		})
	}
	return m, nil
}

// Run runs every plugin until ctx is done. A plugin that fails is restarted
// with backoff; nothing a plugin does ends Run, which returns nil.
func (m *Manager) Run(ctx context.Context) error {
	var wg sync.WaitGroup
	for _, p := range m.plugins {
		wg.Go(func() { p.run(ctx) })
	}
	wg.Wait()
	return nil
}

// Status is what the hub knows of a plugin.
type Status struct {
	Name         string        `json:"name"`
	Version      string        `json:"version"`
	State        string        `json:"state"`
	Error        string        `json:"error,omitempty"`
	Restarts     int           `json:"restarts"`
	StartedAt    *time.Time    `json:"started_at"`
	Capabilities []string      `json:"capabilities"`
	Commands     []CommandSpec `json:"commands"`
	Devices      []Device      `json:"devices"`
	// Stderr is the tail of what the plugin printed on stderr, each line
	// cut short.
	Stderr []string `json:"stderr"`
}

// Plugins returns the status of every plugin, in configuration order.
func (m *Manager) Plugins() []Status {
	out := make([]Status, 0, len(m.plugins))
	for _, p := range m.plugins {
		out = append(out, p.status())
	}
	return out
}

func (p *plugin) status() Status {
	p.mu.Lock()
	defer p.mu.Unlock()
	s := Status{
		Name: p.m.Name, Version: p.m.Version, State: p.state, Error: p.lastErr, Restarts: p.restarts,
		Capabilities: slices.Clone(p.m.Capabilities), Commands: slices.Clone(p.m.Commands),
		Devices: make([]Device, 0, len(p.devices)), Stderr: slices.Clone(p.stderr),
	}
	if s.Capabilities == nil {
		s.Capabilities = []string{}
	}
	if s.Commands == nil {
		s.Commands = []CommandSpec{}
	}
	if s.Stderr == nil {
		s.Stderr = []string{}
	}
	if p.state == StateRunning {
		t := p.startedAt
		s.StartedAt = &t
	}
	for _, d := range p.devices {
		d.Entities = slices.Clone(d.Entities)
		if d.Entities == nil {
			d.Entities = []Entity{}
		}
		s.Devices = append(s.Devices, d)
	}
	return s
}

// CommandRequest is a command for a plugin.
type CommandRequest struct {
	// Command is a command the plugin's manifest declares.
	Command string `json:"command"`
	// Device is the device the command is for, if any.
	Device string `json:"device,omitempty"`
	// Args are the command's arguments: a JSON object, or empty.
	Args json.RawMessage `json:"args,omitempty"`
}

// CommandResult is what a plugin answered to a command.
type CommandResult struct {
	Output string `json:"output"`
}

// Command runs a command of plugin name for actorKind/actorID, through
// policy: the action is plugin.command.<class>, of the class the plugin's
// manifest declares for the command. A command the manifest does not
// declare is denied, and audited as a denied dangerous command. Policy
// errors match policy.ErrDenied. The arguments are not audited: they may
// hold secrets.
func (m *Manager) Command(ctx context.Context, actorKind, actorID, name string, req CommandRequest) (CommandResult, error) {
	p, err := m.lookup(name, req)
	if err != nil {
		return CommandResult{}, err
	}
	action, declared := p.m.commandPolicy(req.Command)
	preq := policy.Request{
		ActorKind: actorKind, ActorID: actorID, Action: action,
		Target: name + "/" + req.Command,
		Detail: map[string]any{"plugin": name, "version": p.m.Version, "command": req.Command, "device": req.Device},
	}
	if !declared {
		preq.Precheck = func(context.Context) error {
			return fmt.Errorf("plugin %s declares no command %q: %w", name, req.Command, policy.ErrDenied)
		}
	}
	var res CommandResult
	err = p.pol.Do(ctx, preq, func(ctx context.Context) error {
		var err error
		res, err = p.command(ctx, req)
		return err
	})
	return res, err
}

// CommandPolicy returns the policy action of plugin name's command:
// plugin.command.<class>, of the class its manifest declares. A plugin that
// is not configured, or a command its manifest does not declare, is
// plugin.command.dangerous, and declared is false: such a command is
// denied. The caller never chooses the class. A nil Manager has no plugins.
func (m *Manager) CommandPolicy(name, command string) (action policy.Action, declared bool) {
	p := m.find(name)
	if p == nil {
		return policy.PluginCommandDangerous, false
	}
	return p.m.commandPolicy(command)
}

// RunGranted runs a command of plugin name as Command does, but neither
// decides nor audits it: it is for a caller that runs it inside a policy
// decision of its own, such as an automation's. It refuses unless ctx carries
// policy's grant of the action CommandPolicy returns for the command
// (policy.Granted), and it refuses a command the manifest does not declare.
func (m *Manager) RunGranted(ctx context.Context, name string, req CommandRequest) (CommandResult, error) {
	p, err := m.lookup(name, req)
	if err != nil {
		return CommandResult{}, err
	}
	action, declared := p.m.commandPolicy(req.Command)
	if !declared {
		return CommandResult{}, fmt.Errorf("plugin %s declares no command %q: %w", name, req.Command, policy.ErrDenied)
	}
	if !policy.Granted(ctx, action) {
		return CommandResult{}, fmt.Errorf("plugin %s command %s: %s was not granted by policy: %w",
			name, req.Command, action, policy.ErrDenied)
	}
	return p.command(ctx, req)
}

// find returns the configured plugin named name, or nil.
func (m *Manager) find(name string) *plugin {
	if m == nil {
		return nil
	}
	i := slices.IndexFunc(m.plugins, func(p *plugin) bool { return p.m.Name == name })
	if i < 0 {
		return nil
	}
	return m.plugins[i]
}

// lookup returns plugin name, once req is well formed.
func (m *Manager) lookup(name string, req CommandRequest) (*plugin, error) {
	p := m.find(name)
	if p == nil {
		return nil, ErrNotFound
	}
	if err := checkRequest(req); err != nil {
		return nil, err
	}
	return p, nil
}

// checkRequest checks that req is well formed: a command name, a device id
// if any, and args that are a JSON object of at most 16 KiB.
func checkRequest(req CommandRequest) error {
	if !idRE().MatchString(req.Command) {
		return fmt.Errorf("%w: invalid command name", ErrBadRequest)
	}
	if req.Device != "" && !idRE().MatchString(req.Device) {
		return fmt.Errorf("%w: invalid device id", ErrBadRequest)
	}
	if len(req.Args) > maxArgs {
		return fmt.Errorf("%w: args larger than %d bytes", ErrBadRequest, maxArgs)
	}
	if len(req.Args) > 0 {
		var obj map[string]any
		if err := json.Unmarshal(req.Args, &obj); err != nil || obj == nil {
			return fmt.Errorf("%w: args must be a JSON object", ErrBadRequest)
		}
	}
	return nil
}

// CheckRequest checks that req is well formed, as Command does before it
// decides on it: errors match ErrBadRequest.
func CheckRequest(req CommandRequest) error { return checkRequest(req) }

// command sends req to the running plugin and waits for its result.
func (p *plugin) command(ctx context.Context, req CommandRequest) (CommandResult, error) {
	p.mu.Lock()
	pr := p.proc
	p.mu.Unlock()
	if pr == nil {
		return CommandResult{}, ErrUnavailable
	}
	select {
	case pr.slots <- struct{}{}:
		defer func() { <-pr.slots }()
	default:
		return CommandResult{}, fmt.Errorf("%w: %d commands in flight", ErrBusy, maxInFlight)
	}
	r, err := pr.request(ctx, message{Type: typeCommand, Command: req.Command, Device: req.Device, Args: req.Args},
		typeResult, p.o.CommandTimeout)
	if err != nil {
		if errors.Is(err, errNoReply) && p.m.IsWasm() {
			// A WASM plugin runs one thing at a time: one that does not
			// answer in time is spinning or stuck, and is stopped.
			pr.cancel(fmt.Errorf("command %s: no reply within %s", req.Command, p.o.CommandTimeout))
		}
		return CommandResult{}, fmt.Errorf("plugin %s command %s: %w", p.m.Name, req.Command, err)
	}
	if !r.OK {
		return CommandResult{}, fmt.Errorf("%w: %s", ErrCommandFailed, truncate(r.Error, 1024))
	}
	return CommandResult{Output: truncate(r.Output, maxOutput)}, nil
}
