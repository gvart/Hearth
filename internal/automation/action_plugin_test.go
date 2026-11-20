// SPDX-License-Identifier: AGPL-3.0-only

package automation

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/gvart/hearth/internal/plugins"
	"github.com/gvart/hearth/internal/policy"
)

// fakePlugins declares the commands in classes, of plugin "lamp", and runs
// them only inside their grant, as *plugins.Manager does.
type fakePlugins struct {
	classes map[string]policy.Action
	err     error
	mu      sync.Mutex
	runs    []string
}

func (f *fakePlugins) CommandPolicy(plugin, command string) (policy.Action, bool) {
	a, ok := f.classes[command]
	if plugin != "lamp" || !ok {
		return policy.PluginCommandDangerous, false
	}
	return a, true
}

func (f *fakePlugins) RunGranted(ctx context.Context, plugin string, req plugins.CommandRequest) (plugins.CommandResult, error) {
	a, ok := f.CommandPolicy(plugin, req.Command)
	if !ok || !policy.Granted(ctx, a) {
		return plugins.CommandResult{}, policy.ErrDenied
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.runs = append(f.runs, plugin+" "+req.Command+" "+req.Device+" "+string(req.Args))
	return plugins.CommandResult{Output: "done"}, f.err
}

func (f *fakePlugins) calls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.runs...)
}

func lampPlugins() *fakePlugins {
	return &fakePlugins{classes: map[string]policy.Action{
		"status": policy.PluginCommandRead, "turn_on": policy.PluginCommandSafe, "reflash": policy.PluginCommandDangerous,
	}}
}

func pluginAutomation(command string) string {
	return kubeAutomation("lamp-auto", `  - id: cmd
    type: plugin_command
    plugin: lamp
    command: `+command+`
    device: '{{ "desk" }}'
    args: {level: 3}
`)
}

func TestPluginCommandAutomation(t *testing.T) {
	pl := lampPlugins()
	rec, audit := runOnce(t, pluginAutomation("turn_on"), ActionDeps{Plugins: pl})
	if run := rec.all()[0]; run.Status != StatusSucceeded {
		t.Fatalf("run = %+v", run)
	}
	if runs := pl.calls(); len(runs) != 1 || runs[0] != `lamp turn_on desk {"level":3}` {
		t.Errorf("runs = %q", runs)
	}
	es := audit.all()
	if len(es) != 1 {
		t.Fatalf("audit = %+v, want one entry", es)
	}
	if e := es[0]; e.ActorKind != policy.ActorAutomation || e.ActorID != "lamp-auto" || e.Action != string(policy.PluginCommandSafe) ||
		e.Target != "lamp/turn_on@desk" || e.Decision != policy.Allow || e.Result != "ok" {
		t.Errorf("audit = %+v", e)
	}
	if strings.Contains(string(es[0].Detail), "level") {
		t.Errorf("the audit entry holds the args: %s", es[0].Detail)
	}
}

// The class is the manifest's, never the automation's: a file cannot set
// one, and a dangerous command needs the automation's grant.
func TestPluginCommandClassIsTheManifests(t *testing.T) {
	kinds := actionKinds(ActionDeps{Plugins: lampPlugins()})
	if _, err := Parse("a.yaml", []byte(pluginAutomation("turn_on")+"    class: read\n"), kinds); err == nil ||
		!strings.Contains(err.Error(), "class") {
		t.Errorf("a class field was accepted: %v", err)
	}
	for cmd, want := range map[string]policy.Action{
		"status": policy.PluginCommandRead, "turn_on": policy.PluginCommandSafe, "reflash": policy.PluginCommandDangerous,
		"self_destruct": policy.PluginCommandDangerous,
	} {
		a, err := Parse("a.yaml", []byte(pluginAutomation(cmd)), kinds)
		if err != nil {
			t.Fatal(err)
		}
		if got := a.Actions[0].Impl.Policy(); got != want {
			t.Errorf("%s: policy = %s, want %s", cmd, got, want)
		}
	}
	// Without the hub's plugins (a plan from the CLI), it is the worst.
	a, err := Parse("a.yaml", []byte(pluginAutomation("status")), actionKinds(ActionDeps{}))
	if err != nil {
		t.Fatal(err)
	}
	if got := a.Actions[0].Impl.Policy(); got != policy.PluginCommandDangerous {
		t.Errorf("without plugins: policy = %s", got)
	}
}

func TestPluginCommandDeniedAndAudited(t *testing.T) {
	tests := []struct {
		name    string
		command string
		deps    func(*fakePlugins) ActionDeps
		granted []string
		action  policy.Action
	}{
		{"dangerous without a grant", "reflash", func(p *fakePlugins) ActionDeps { return ActionDeps{Plugins: p} }, nil, policy.PluginCommandDangerous},
		{"undeclared, even when granted", "self_destruct", func(p *fakePlugins) ActionDeps { return ActionDeps{Plugins: p} }, []string{"lamp-auto"}, policy.PluginCommandDangerous},
		{"no plugins on this hub", "turn_on", func(*fakePlugins) ActionDeps { return ActionDeps{} }, []string{"lamp-auto"}, policy.PluginCommandDangerous},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pl := lampPlugins()
			rec, audit := runOnce(t, pluginAutomation(tt.command), tt.deps(pl), tt.granted...)
			if run := rec.all()[0]; run.Status != StatusDenied {
				t.Errorf("run = %+v, want denied", run)
			}
			if runs := pl.calls(); len(runs) != 0 {
				t.Errorf("a denied command reached the plugin: %q", runs)
			}
			es := audit.all()
			if len(es) != 1 || es[0].Decision != policy.Deny || es[0].Action != string(tt.action) ||
				es[0].Target != "lamp/"+tt.command+"@desk" || es[0].ActorKind != policy.ActorAutomation {
				t.Errorf("audit = %+v", es)
			}
		})
	}

	// Granted, the dangerous command runs.
	pl := lampPlugins()
	rec, audit := runOnce(t, pluginAutomation("reflash"), ActionDeps{Plugins: pl}, "lamp-auto")
	if run := rec.all()[0]; run.Status != StatusSucceeded || len(pl.calls()) != 1 {
		t.Errorf("granted run = %+v, runs %q", run, pl.calls())
	}
	if e := audit.all()[0]; e.Decision != policy.Allow || e.Action != string(policy.PluginCommandDangerous) {
		t.Errorf("audit = %+v", e)
	}
}

// Outside a policy decision, the action never runs.
func TestPluginCommandOutsidePolicy(t *testing.T) {
	pl := lampPlugins()
	a, err := Parse("test.yaml", []byte(pluginAutomation("turn_on")), actionKinds(ActionDeps{Plugins: pl}))
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Actions[0].Impl.Run(t.Context(), Event{}); !errors.Is(err, policy.ErrDenied) {
		t.Fatalf("err = %v, want ErrDenied", err)
	}
	if runs := pl.calls(); len(runs) != 0 {
		t.Errorf("runs = %q", runs)
	}
}

func TestPluginCommandOutcome(t *testing.T) {
	for _, tt := range []struct {
		err       error
		uncertain bool
	}{
		{plugins.ErrBusy, false},
		{plugins.ErrCommandFailed, false},
		{plugins.ErrUnavailable, true},
		{context.DeadlineExceeded, true},
	} {
		pl := lampPlugins()
		pl.err = tt.err
		a, err := Parse("test.yaml", []byte(pluginAutomation("turn_on")), actionKinds(ActionDeps{Plugins: pl}))
		if err != nil {
			t.Fatal(err)
		}
		err = policy.NewWithConfig(&auditLog{}, nil, policy.Config{}).Do(t.Context(), policy.Request{
			ActorKind: policy.ActorAutomation, ActorID: "a", Action: a.Actions[0].Impl.Policy(),
		}, func(ctx context.Context) error { return a.Actions[0].Impl.Run(ctx, Event{}) })
		if !errors.Is(err, tt.err) || outcomeUncertain(err) != tt.uncertain {
			t.Errorf("%v: err = %v, uncertain = %v, want %v", tt.err, err, outcomeUncertain(err), tt.uncertain)
		}
	}
}

func TestPluginCommandNeedsPluginAndCommand(t *testing.T) {
	kinds := actionKinds(ActionDeps{Plugins: lampPlugins()})
	for _, y := range []string{
		"  - type: plugin_command\n    command: turn_on\n",
		"  - type: plugin_command\n    plugin: lamp\n",
	} {
		if _, err := Parse("a.yaml", []byte(kubeAutomation("x", y)), kinds); err == nil || !strings.Contains(err.Error(), "required") {
			t.Errorf("%q: err = %v", y, err)
		}
	}
}

// A runbook step runs a plugin command as its runbook, through policy with
// the manifest's class: a dangerous one is denied unless granted.
func TestRunbookPluginCommand(t *testing.T) {
	grant := policy.Config{DangerousAutomations: []string{RunbookActor("rb")}}
	for _, tt := range []struct {
		name, command, status, step string
		cfg                         policy.Config
		decision                    string
		action                      policy.Action
	}{
		{"safe", "turn_on", RunbookSucceeded, stepOK, policy.Config{}, policy.Allow, policy.PluginCommandSafe},
		{"dangerous without a grant", "reflash", RunbookFailed, stepDenied, policy.Config{}, policy.Deny, policy.PluginCommandDangerous},
		{"dangerous granted", "reflash", RunbookSucceeded, stepOK, grant, policy.Allow, policy.PluginCommandDangerous},
		{"undeclared, even when granted", "self_destruct", RunbookFailed, stepDenied, grant, policy.Deny, policy.PluginCommandDangerous},
	} {
		t.Run(tt.name, func(t *testing.T) {
			pl := lampPlugins()
			h := newRBHarness(t, `id: rb
steps:
  - id: lamp
    type: action
    action: {type: plugin_command, plugin: lamp, command: `+tt.command+`, device: desk}
`, tt.cfg)
			h.kinds.Actions["plugin_command"] = Actions(ActionDeps{Plugins: pl})["plugin_command"]
			h.rb = h.engine()
			h.run(h.rb)
			run := h.await(h.start("rb"), tt.status)
			if s := run.Steps[0]; s.Status != tt.step {
				t.Errorf("step = %s %q, want %s", s.Status, s.Error, tt.step)
			}
			if want := map[bool]int{true: 1, false: 0}[tt.decision == policy.Allow]; len(pl.calls()) != want {
				t.Errorf("runs = %q, want %d", pl.calls(), want)
			}
			got := h.audited(tt.action)
			if len(got) != 1 || got[0].Decision != tt.decision || got[0].ActorID != RunbookActor("rb") || got[0].Target != "lamp/"+tt.command+"@desk" {
				t.Errorf("audit = %+v", got)
			}
		})
	}
}
