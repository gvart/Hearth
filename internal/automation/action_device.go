// SPDX-License-Identifier: AGPL-3.0-only

package automation

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/gvart/hearth/internal/policy"
	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
)

// Agents runs requests on devices through their agents: *hub.Agents. device
// is a device id, name or hostname.
type Agents interface {
	Exec(ctx context.Context, device string, req *agentv1.ExecRequest) (*agentv1.ExecResult, error)
}

// ActionDeps are what the exec, restart, webhook and notify actions use when they
// run. Zero values are enough to load and plan automations.
type ActionDeps struct {
	Agents Agents
	// HTTP sends webhooks; nil means a default client.
	HTTP *http.Client
	// Notifier sends notify actions; nil (as in a dry run) skips checking
	// that their channels exist.
	Notifier Notifier
	// Kube carries out the kube_* actions; nil fails them when they run.
	Kube Kube
	// Plugins runs plugin_command actions; nil (as in a dry run) leaves each
	// one dangerous, and denies it when it runs.
	Plugins Plugins
	// Probers run check actions that name a device in from; nil fails them
	// when they run.
	Probers Probers
}

// Actions returns the exec, restart, check, vip_claim, vip_release, webhook, notify, plugin_command and
// kube_* action kinds,
// to add to Builtin's.
func Actions(d ActionDeps) map[string]Builder[Action] {
	if d.HTTP == nil {
		d.HTTP = &http.Client{}
	}
	out := map[string]Builder[Action]{
		"exec":      func(p Params) (Action, error) { return buildExec(p, d.Agents) },
		"restart":   func(p Params) (Action, error) { return buildRestart(p, d.Agents) },
		"check":     func(p Params) (Action, error) { return buildCheckAction(p, d.Probers) },
		"vip_claim": func(p Params) (Action, error) { return buildVIP(p, d.Agents, false) },
		"vip_release": func(p Params) (Action, error) {
			return buildVIP(p, d.Agents, true)
		},
		"webhook": func(p Params) (Action, error) { return buildWebhook(p, d.HTTP) },
		"notify":  func(p Params) (Action, error) { return buildNotify(p, d.Notifier) },
		"plugin_command": func(p Params) (Action, error) {
			return buildPluginCommand(p, d.Plugins)
		},
	}
	maps.Copy(out, kubeActions(d.Kube))
	return out
}

const (
	// defaultAgentTimeout bounds an exec or restart that sets no timeout.
	defaultAgentTimeout = time.Minute
	// maxAgentTimeout is the longest timeout an action may set; agents cap
	// it the same way.
	maxAgentTimeout = 10 * time.Minute
	// answerGrace is how long the hub waits past the timeout for the
	// agent's answer before giving up on it.
	answerGrace = 15 * time.Second
)

// agentAction is an action a device's agent executes: exec or restart.
type agentAction struct {
	agents  Agents
	device  Text
	timeout time.Duration
	policy  policy.Action
	desc    string
	// what names the action in errors, never with its arguments.
	what string
	req  func() *agentv1.ExecRequest
}

func (a *agentAction) Describe() string      { return a.desc }
func (a *agentAction) Policy() policy.Action { return a.policy }
func (a *agentAction) Target() Text          { return a.device }
func (a *agentAction) texts() []Text         { return []Text{a.device} }

// Precheck refuses an action beyond the capability ceiling the device's
// agent reported, when agents can tell (*hub.Agents can), so policy denies
// it instead of holding it for approval or running it.
func (a *agentAction) Precheck(ctx context.Context, ev Event) error {
	c, ok := a.agents.(interface {
		Check(ctx context.Context, device string, req *agentv1.ExecRequest) error
	})
	if !ok {
		return nil
	}
	device, err := renderDevice(ctx, a.device, ev)
	if err != nil {
		return nil // Run reports it
	}
	return c.Check(ctx, device, a.req())
}

func (a *agentAction) Run(ctx context.Context, ev Event) error {
	if a.agents == nil {
		return errors.New("this hub does not run actions on devices")
	}
	device, err := renderDevice(ctx, a.device, ev)
	if err != nil {
		return err
	}
	req := a.req()
	req.Timeout = durationpb.New(a.timeout)
	ctx, cancel := context.WithTimeout(ctx, a.timeout+answerGrace)
	defer cancel()
	res, err := a.agents.Exec(ctx, device, req)
	if err != nil {
		return fmt.Errorf("%s: %w", a.what, err)
	}
	if res.GetDenied() {
		return fmt.Errorf("%s on device %s: %w", a.what, device, policy.ErrBeyondCeiling)
	}
	if msg := res.GetError(); agentStoppedCommand(msg) {
		return fmt.Errorf("%s on device %s: %s: %w", a.what, device, msg, ErrOutcomeUnknown)
	} else if msg != "" {
		return fmt.Errorf("%s on device %s: %s", a.what, device, msg)
	}
	return nil
}

// agentStoppedCommand reports whether msg, an agent's report of a command, says
// the agent stopped the command before it ended: it may have done part of its
// work. Agents report this only as text.
func agentStoppedCommand(msg string) bool {
	return strings.HasPrefix(msg, context.DeadlineExceeded.Error()+" after ") ||
		strings.HasPrefix(msg, context.Canceled.Error()+" after ")
}

// renderDevice renders a device field, which must not come out empty.
func renderDevice(ctx context.Context, device Text, ev Event) (string, error) {
	d, err := device.Render(ctx, ev)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(d) == "" {
		return "", fmt.Errorf("device %q is empty for this event", device)
	}
	return d, nil
}

// deviceText parses a device field: required, and may be a template.
func deviceText(p Params, raw string) (Text, error) {
	if raw == "" {
		return Text{}, errors.New("device is required")
	}
	return p.Text(raw, "device")
}

// agentTimeout checks a timeout field: 0 means the default.
func agentTimeout(d time.Duration) (time.Duration, error) {
	switch {
	case d == 0:
		return defaultAgentTimeout, nil
	case d < 0 || d > maxAgentTimeout:
		return 0, fmt.Errorf("timeout must be between 0 and %s", maxAgentTimeout)
	}
	return d, nil
}

func buildExec(p Params, agents Agents) (Action, error) {
	var cfg struct {
		Device  string        `yaml:"device"`
		Command []string      `yaml:"command"`
		Timeout time.Duration `yaml:"timeout"`
	}
	if err := p.Decode(&cfg); err != nil {
		return nil, err
	}
	device, err := deviceText(p, cfg.Device)
	if err != nil {
		return nil, err
	}
	if len(cfg.Command) == 0 || cfg.Command[0] == "" {
		return nil, errors.New("command is required: a list, program first, e.g. [/usr/bin/df, -h]")
	}
	timeout, err := agentTimeout(cfg.Timeout)
	if err != nil {
		return nil, err
	}
	argv := cfg.Command
	return &agentAction{
		agents: agents, device: device, timeout: timeout, policy: policy.AutomationExec,
		desc: fmt.Sprintf("run %q", argv), what: "exec " + argv[0],
		req: func() *agentv1.ExecRequest {
			return &agentv1.ExecRequest{Action: &agentv1.ExecRequest_Command{Command: &agentv1.Command{Argv: argv}}}
		},
	}, nil
}

// serviceManagers are the managers a restart may name, as the agent's
// --allow-restart does.
var serviceManagers = []string{"systemd", "systemd-user", "docker"}

func buildRestart(p Params, agents Agents) (Action, error) {
	var cfg struct {
		Device  string        `yaml:"device"`
		Service string        `yaml:"service"`
		Timeout time.Duration `yaml:"timeout"`
	}
	if err := p.Decode(&cfg); err != nil {
		return nil, err
	}
	device, err := deviceText(p, cfg.Device)
	if err != nil {
		return nil, err
	}
	manager, name, ok := strings.Cut(cfg.Service, ":")
	if !ok || name == "" || !slices.Contains(serviceManagers, manager) {
		return nil, fmt.Errorf("service must be manager:name with manager one of %s, e.g. systemd:pihole-FTL.service",
			strings.Join(serviceManagers, ", "))
	}
	timeout, err := agentTimeout(cfg.Timeout)
	if err != nil {
		return nil, err
	}
	return &agentAction{
		agents: agents, device: device, timeout: timeout, policy: policy.AutomationRestart,
		desc: "restart " + cfg.Service, what: "restart " + cfg.Service,
		req: func() *agentv1.ExecRequest {
			return &agentv1.ExecRequest{Action: &agentv1.ExecRequest_Restart{
				Restart: &agentv1.RestartService{Manager: manager, Name: name},
			}}
		},
	}, nil
}
