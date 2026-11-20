// SPDX-License-Identifier: AGPL-3.0-only

package automation

import (
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/policy"
)

// talosUpgradeHarness runs the upgrade-talos-node recipe as shipped, with the
// cluster renamed to the fake's "lab", the Talos API check pointed at a local
// listener and the reboot wait cut to 10ms: nothing else of the file changes. talosctl never runs: a
// recording agent stands in for the device.
func talosUpgradeHarness(t *testing.T) (*rbHarness, *recordingAgents) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(recipesDir, "upgrade-talos-node.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	for old, repl := range map[string]string{
		"  cluster: homelab\n":                 "  cluster: lab\n",
		"    duration: 3m\n":                   "    duration: 10ms\n",
		`address: "${{ vars.node-ip }}:50000"`: `address: "` + tcpListener(t) + `"`,
	} {
		if !strings.Contains(src, old) {
			t.Fatalf("recipe has no %q", old)
		}
		src = strings.Replace(src, old, repl, 1)
	}
	agents := &recordingAgents{}
	h := newRBHarness(t, src, policy.Config{DangerousAutomations: []string{"runbook/upgrade-talos-node"}})
	maps.Copy(h.kinds.Actions, Actions(ActionDeps{Agents: agents}))
	h.kubeNodes = &fakeNodes{nodes: map[string]error{"talos-worker-1": nil}}
	h.rb = h.engine()
	h.run(h.rb)
	return h, agents
}

// answerAt waits for the run to ask step, and answers it.
func answerAt(h *rbHarness, id, step, value string) {
	h.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for h.get(id).Awaiting != step {
		if time.Now().After(deadline) {
			h.t.Fatalf("no prompt %s: %+v", step, h.get(id).Steps)
		}
		time.Sleep(2 * time.Millisecond)
	}
	h.answer(id, step, value)
}

func (a *recordingAgents) all() [][]string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return slices.Clone(a.argv)
}

var (
	talosctl      = []string{"/usr/local/bin/talosctl", "--talosconfig", "/etc/talos/talosconfig", "--nodes"}
	talosHealth   = append(slices.Clone(talosctl), "192.0.2.10", "health", "--wait-timeout", "5m")
	talosUpgrade  = append(slices.Clone(talosctl), "192.0.2.50", "upgrade", "--image", "ghcr.io/siderolabs/installer:v1.12.8", "--preserve", "--wait=false")
	talosRollback = append(slices.Clone(talosctl), "192.0.2.50", "rollback")
)

// The upgrade runs its steps in order: health, the quorum and go-ahead
// prompts, the upgrade, the wait for the node, the version prompt, health
// again.
func TestTalosUpgradeRecipeRunsInOrder(t *testing.T) {
	h, agents := talosUpgradeHarness(t)
	id := h.start("upgrade-talos-node")
	answerAt(h, id, "ready", ConfirmYes)
	answerAt(h, id, "quorum", ConfirmYes)
	answerAt(h, id, "approve", ConfirmYes)
	answerAt(h, id, "version-after", ConfirmYes)
	run := h.await(id, RunbookSucceeded)
	if got := agents.all(); !reflect.DeepEqual(got, [][]string{talosHealth, talosUpgrade, talosHealth}) {
		t.Errorf("ran %q; want health, upgrade, health", got)
	}
	var order []string
	for _, s := range run.Steps {
		order = append(order, s.ID)
	}
	want := []string{
		"ready", "quorum", "health-before", "node-ready-before", "approve", "upgrade",
		"reboot-settle", "api-back", "node-ready-after", "version-after", "health-after", "done",
	}
	if !slices.Equal(order, want) {
		t.Errorf("steps %v; want %v", order, want)
	}
	// Every talosctl run was decided as automation.exec, which is dangerous.
	if c, _ := policy.ClassOf(policy.AutomationExec); c != policy.Dangerous {
		t.Errorf("automation.exec is %s; want dangerous", c)
	}
	if n := len(h.audited(policy.AutomationExec)); n < 3 {
		t.Errorf("%d automation.exec audit entries; want one per talosctl run", n)
	}
}

// Answering no on the quorum prompt, as for the only control-plane node,
// stops the run before anything runs on a device.
func TestTalosUpgradeRecipeRefusesWithoutQuorumConfirmation(t *testing.T) {
	h, agents := talosUpgradeHarness(t)
	id := h.start("upgrade-talos-node")
	answerAt(h, id, "ready", ConfirmYes)
	answerAt(h, id, "quorum", ConfirmNo)
	h.await(id, RunbookFailed)
	if got := agents.all(); len(got) != 0 {
		t.Errorf("ran %q; want nothing", got)
	}
}

// A version that does not match stops the run, and rolling back runs
// talosctl rollback on the node, after nothing else.
func TestTalosUpgradeRecipeRollsBack(t *testing.T) {
	h, agents := talosUpgradeHarness(t)
	id := h.start("upgrade-talos-node")
	answerAt(h, id, "ready", ConfirmYes)
	answerAt(h, id, "quorum", ConfirmYes)
	answerAt(h, id, "approve", ConfirmYes)
	answerAt(h, id, "version-after", ConfirmNo)
	h.await(id, RunbookFailed)
	h.rollback(id)
	h.await(id, RunbookRolledBack)
	if got := agents.all(); !reflect.DeepEqual(got, [][]string{talosHealth, talosUpgrade, talosRollback}) {
		t.Errorf("ran %q; want health, upgrade, rollback", got)
	}
}
