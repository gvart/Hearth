// SPDX-License-Identifier: AGPL-3.0-only

package automation

import (
	"io/fs"
	"maps"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/integrations/talos"
	"github.com/gvart/hearth/internal/policy"
)

// talosUpgradeHarness runs the upgrade-talos-node recipe as shipped, with the
// cluster renamed to the fake's "lab", plus the changes in edits: nothing else
// of the file changes. The Talos API answers that the node runs version, with
// every service healthy. talosctl never runs: a recording agent stands in for
// the device.
func talosUpgradeHarness(t *testing.T, version string, edits map[string]string) (*rbHarness, *recordingAgents) {
	t.Helper()
	b, err := fs.ReadFile(os.DirFS(recipesDir), "upgrade-talos-node.yaml")
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	edits["  cluster: homelab\n"] = "  cluster: lab\n"
	for old, repl := range edits {
		if !strings.Contains(src, old) {
			t.Fatalf("recipe has no %q", old)
		}
		src = strings.Replace(src, old, repl, 1)
	}
	agents := &recordingAgents{}
	h := newRBHarness(t, src, policy.Config{DangerousAutomations: []string{"runbook/upgrade-talos-node"}})
	maps.Copy(h.kinds.Actions, Actions(ActionDeps{Agents: agents}))
	h.kubeNodes = &fakeNodes{nodes: map[string]error{"talos-worker-1": nil}}
	h.talosNodes = &fakeTalos{nodes: []talos.Node{{
		Address: "192.0.2.50", Hostname: "talos-worker-1", Version: version, Healthy: true,
		Services: []talos.Service{{ID: "kubelet", State: "Running", Health: talos.HealthHealthy}},
	}}}
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
	talosUpgrade  = append(slices.Clone(talosctl), "192.0.2.50", "upgrade", "--image", "ghcr.io/siderolabs/installer:v1.12.8", "--preserve", "--wait", "--timeout", "9m")
	talosRollback = append(slices.Clone(talosctl), "192.0.2.50", "rollback")
)

// The upgrade runs its steps in order: the quorum prompt, health, the node's
// own checks, the go-ahead prompt, the upgrade, the checks that the node runs
// the new version and is Ready, health again. Nobody is asked to confirm the
// version.
func TestTalosUpgradeRecipeRunsInOrder(t *testing.T) {
	h, agents := talosUpgradeHarness(t, "v1.12.8", map[string]string{})
	id := h.start("upgrade-talos-node")
	answerAt(h, id, "ready", ConfirmYes)
	answerAt(h, id, "quorum", ConfirmYes)
	answerAt(h, id, "approve", ConfirmYes)
	run := h.await(id, RunbookSucceeded)
	if got := agents.all(); !reflect.DeepEqual(got, [][]string{talosHealth, talosUpgrade, talosHealth}) {
		t.Errorf("ran %q; want health, upgrade, health", got)
	}
	var order []string
	for _, s := range run.Steps {
		order = append(order, s.ID)
	}
	want := []string{
		"ready", "quorum", "health-before", "node-healthy-before", "node-ready-before", "approve", "upgrade",
		"version-after", "node-ready-after", "health-after", "done",
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
	// Each talos_node check was one talos.read decision, as the runbook, on
	// the node.
	reads := h.audited(policy.TalosRead)
	if len(reads) != 2 {
		t.Fatalf("talos.read entries = %+v; want one per talos_node check", reads)
	}
	for _, e := range reads {
		if e.ActorKind != policy.ActorAutomation || e.ActorID != RunbookActor("upgrade-talos-node") || e.Target != "192.0.2.50" {
			t.Errorf("talos.read entry = %+v", e)
		}
	}
}

// Answering no on the quorum prompt, as for the only control-plane node,
// stops the run before anything runs on a device.
func TestTalosUpgradeRecipeRefusesWithoutQuorumConfirmation(t *testing.T) {
	h, agents := talosUpgradeHarness(t, "v1.12.8", map[string]string{})
	id := h.start("upgrade-talos-node")
	answerAt(h, id, "ready", ConfirmYes)
	answerAt(h, id, "quorum", ConfirmNo)
	h.await(id, RunbookFailed)
	if got := agents.all(); len(got) != 0 {
		t.Errorf("ran %q; want nothing", got)
	}
}

// A version that does not match stops the run at the version check, which
// says what the node runs; rolling back runs talosctl rollback on the node,
// after nothing else. The check's 20 minutes are cut to 2 seconds.
func TestTalosUpgradeRecipeRollsBack(t *testing.T) {
	h, agents := talosUpgradeHarness(t, "v1.12.7", map[string]string{
		"      healthy: true\n    within: 20m\n": "      healthy: true\n    within: 2s\n",
	})
	id := h.start("upgrade-talos-node")
	answerAt(h, id, "ready", ConfirmYes)
	answerAt(h, id, "quorum", ConfirmYes)
	answerAt(h, id, "approve", ConfirmYes)
	run := h.await(id, RunbookFailed)
	var failed []string
	for _, s := range run.Steps {
		if s.Status == stepFailed {
			failed = append(failed, s.ID)
			if !strings.Contains(s.Error, "runs v1.12.7, not v1.12.8") {
				t.Errorf("step %s failed with %q; want the version the node runs", s.ID, s.Error)
			}
		}
	}
	if !slices.Equal(failed, []string{"version-after"}) {
		t.Errorf("failed steps %v; want version-after", failed)
	}
	h.rollback(id)
	h.await(id, RunbookRolledBack)
	if got := agents.all(); !reflect.DeepEqual(got, [][]string{talosHealth, talosUpgrade, talosRollback}) {
		t.Errorf("ran %q; want health, upgrade, rollback", got)
	}
}

// The upgrade step waits for talosctl, so the checks after it cannot pass on
// a node that has not rebooted yet; the approval names the node's address and
// warns against rolling back a node that never rebooted, as does the version
// check; the version is checked through the Talos API, not asked for; the
// quorum prompt is still there.
func TestTalosUpgradeRecipeWaitsAndWarns(t *testing.T) {
	rb, err := LoadRunbookFile(recipesDir+"/upgrade-talos-node.yaml", recipeKinds())
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, s := range rb.Steps {
		seen[s.ID] = true
		switch s.ID {
		case "approve":
			if s.Type != RunbookStepPrompt {
				t.Fatalf("approve is a %s step; want a prompt", s.Type)
			}
			if !strings.Contains(s.Prompt.Message, "192.0.2.50") || !strings.Contains(s.Prompt.Message, "talos-worker-1") {
				t.Errorf("approve prompt %q does not name the node and its address", s.Prompt.Message)
			}
			if !strings.Contains(s.Prompt.Message, "do NOT roll back") {
				t.Errorf("approve prompt %q does not warn against a rollback", s.Prompt.Message)
			}
		case "quorum":
			if s.Type != RunbookStepPrompt || !strings.Contains(s.Prompt.Message, "control-plane") {
				t.Errorf("quorum step is not the control-plane prompt: %+v", s)
			}
		case "version-after":
			c := s.Check
			if s.Type != RunbookStepCheck || c == nil || c.talosNode == nil ||
				*c.talosNode != (talosNodeCheck{node: "192.0.2.50", version: "v1.12.8", healthy: true}) {
				t.Errorf("version-after is not a talos_node check of the version and health: %+v", s)
			} else if !strings.Contains(s.Description, "do NOT roll back") {
				t.Errorf("version check %q does not warn against a rollback", s.Description)
			}
		}
		if s.Type == RunbookStepPrompt && s.ID != "approve" && strings.Contains(strings.ReplaceAll(s.Prompt.Message, "installer:v1.12.8", ""), "v1.12.8") {
			t.Errorf("step %s asks a person about the version: %q", s.ID, s.Prompt.Message)
		}
		if s.Type == RunbookStepWait {
			t.Errorf("step %s: a fixed wait could end before the node reboots", s.ID)
		}
	}
	for _, id := range []string{"quorum", "approve", "version-after"} {
		if !seen[id] {
			t.Errorf("no step %s", id)
		}
	}
}
