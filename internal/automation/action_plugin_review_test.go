// SPDX-License-Identifier: AGPL-3.0-only

package automation

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

// A held command's approval, like its audit entry, names the device it is
// for, rendered.
func TestRunbookHeldPluginCommandNamesTheDevice(t *testing.T) {
	cfg := policy.Config{Actors: map[string]map[policy.Class]policy.Mode{
		policy.ActorAutomation: {policy.Safe: policy.ModeConfirm},
	}}
	// Prompt answers cannot name the device (they are data, never a target):
	// the template renders a constant here.
	h := newRBHarness(t, `id: rb
steps:
  - id: open
    type: action
    action: {type: plugin_command, plugin: lamp, command: turn_on, device: '{{ "front" }}-door'}
`, cfg)
	pl := lampPlugins()
	h.kinds.Actions["plugin_command"] = Actions(ActionDeps{Plugins: pl})["plugin_command"]
	pol := policy.NewWithConfig(h.audit, h.st.Approvals(), cfg)
	h.rb = NewRunbooks(RunbooksConfig{
		Dir: h.dir, Kinds: h.kinds, Policy: pol, Runs: h.st.RunbookRuns(), Sealer: xorSealer{}, Poll: 5 * time.Millisecond,
	})
	defer h.run(h.rb)()
	id := h.start("rb")

	var held []store.Approval
	eventually(t, "the command held for approval", func() bool {
		var err error
		held, err = h.st.Approvals().List(t.Context(), store.ApprovalPending, 10)
		return err == nil && len(held) == 1
	})
	if held[0].Target != "lamp/turn_on@front-door" {
		t.Errorf("approval target = %q", held[0].Target)
	}
	if err := pol.Decide(context.Background(), policy.ActorWeb, "10.0.0.1", held[0].ID, true,
		func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	h.await(id, RunbookSucceeded)
	if runs := pl.calls(); len(runs) != 1 || runs[0] != "lamp turn_on front-door " {
		t.Errorf("runs = %q", runs)
	}
	got := h.audited(policy.PluginCommandSafe)
	if len(got) == 0 {
		t.Fatal("no plugin.command.safe entry")
	}
	for _, e := range got {
		if e.Target != "lamp/turn_on@front-door" {
			t.Errorf("audit target = %q", e.Target)
		}
	}
}

// A device template that renders empty sends nothing: without a device the
// command could act on more than the action names.
func TestPluginCommandEmptyDeviceIsNotSent(t *testing.T) {
	pl := lampPlugins()
	y := kubeAutomation("lamp-auto", "  - type: plugin_command\n    plugin: lamp\n    command: turn_on\n    device: '{{ \"\" }}'\n")
	rec, _ := runOnce(t, y, ActionDeps{Plugins: pl})
	if run := rec.all()[0]; run.Status != StatusFailed || !strings.Contains(run.Error, "rendered empty") {
		t.Errorf("run = %+v, want failed", run)
	}
	if runs := pl.calls(); len(runs) != 0 {
		t.Errorf("runs = %q", runs)
	}
}

// Plugin and command fix the class when the file loads: no templates.
func TestPluginCommandNamesAreNotTemplates(t *testing.T) {
	kinds := actionKinds(ActionDeps{Plugins: lampPlugins()})
	y := kubeAutomation("x", "  - type: plugin_command\n    plugin: lamp\n    command: '{{ \"turn_on\" }}'\n")
	if _, err := Parse("a.yaml", []byte(y), kinds); err == nil || !strings.Contains(err.Error(), "template") {
		t.Errorf("err = %v", err)
	}
}

// Saving an automation with a plugin command that may run unasked needs a
// person, even when this hub's manifest calls the command safe: another hub
// of the cluster may call it dangerous.
func TestSaveOfPluginCommandIsJudgedDangerous(t *testing.T) {
	a, err := Parse("a.yaml", []byte(pluginAutomation("turn_on")), actionKinds(ActionDeps{Plugins: lampPlugins()}))
	if err != nil {
		t.Fatal(err)
	}
	granted := policy.NewWithConfig(&auditLog{}, nil, policy.Config{DangerousAutomations: []string{"lamp-auto"}})
	if SaveEngine(granted, policy.ActorWeb, a) == granted {
		t.Error("a save of a granted automation with a plugin command is not held for a person")
	}
	if e := policy.NewWithConfig(&auditLog{}, nil, policy.Config{}); SaveEngine(e, policy.ActorWeb, a) != e {
		t.Error("a save of an ungranted plugin command is held, though it could not run unasked")
	}
}
