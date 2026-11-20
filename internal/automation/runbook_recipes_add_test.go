// SPDX-License-Identifier: AGPL-3.0-only

package automation

import (
	"encoding/json"
	"io/fs"
	"maps"
	"net"
	"os"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/gvart/hearth/internal/integrations/talos"
	"github.com/gvart/hearth/internal/policy"
)

// mutating reports whether s is an action step that changes something: any
// action but a log, unless the recipe's step only reads.
func mutating(rbID string, s RunbookStep) bool {
	return s.Type == RunbookStepAction && s.Action.Impl.Policy() != policy.AutomationLog &&
		!readOnlySteps[rbID+"/"+s.ID]
}

// Every step that changes something is approved by a person first: a confirm
// prompt comes after the previous change, so one answer never covers two.
func TestRecipesAskBeforeEveryChange(t *testing.T) {
	kinds := recipeKinds()
	for _, f := range recipeFiles(t) {
		rb, err := LoadRunbookFile(f, kinds)
		if err != nil {
			t.Fatal(err)
		}
		approved := false
		for _, s := range rb.Steps {
			switch {
			case s.Type == RunbookStepPrompt && s.Prompt.Kind == PromptConfirm:
				approved = true
			case mutating(rb.ID, s):
				if !approved {
					t.Errorf("%s step %s changes something with no confirm prompt since the last change", rb.ID, s.ID)
				}
				approved = false
			}
		}
	}
}

// A recipe waits for a machine with a check that polls, never for a fixed
// time that may end too soon or too late.
func TestRecipesHaveNoFixedWaits(t *testing.T) {
	kinds := recipeKinds()
	for _, f := range recipeFiles(t) {
		rb, err := LoadRunbookFile(f, kinds)
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range rb.Steps {
			if s.Type == RunbookStepWait {
				t.Errorf("%s step %s is a fixed wait; use a check with within and every", rb.ID, s.ID)
			}
		}
	}
}

// recipeHarness runs the recipe file as shipped, with the cluster renamed to
// the fakes' "lab", plus the changes in edits: nothing else of the file
// changes. A recording agent stands in for every device, so nothing runs.
func recipeHarness(t *testing.T, file string, edits map[string]string, kube KubeNodes, tal TalosNodes) (*rbHarness, *recordingAgents) {
	t.Helper()
	b, err := fs.ReadFile(os.DirFS(recipesDir), file)
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	if strings.Contains(src, "  cluster: homelab\n") {
		edits["  cluster: homelab\n"] = "  cluster: lab\n"
	}
	for old, repl := range edits {
		if !strings.Contains(src, old) {
			t.Fatalf("recipe has no %q", old)
		}
		src = strings.Replace(src, old, repl, 1)
	}
	id := strings.TrimSuffix(file, ".yaml")
	agents := &recordingAgents{}
	h := newRBHarness(t, src, policy.Config{DangerousAutomations: []string{"runbook/" + id}})
	maps.Copy(h.kinds.Actions, Actions(ActionDeps{Agents: agents}))
	h.kubeNodes, h.talosNodes = kube, tal
	h.rb = h.engine()
	h.run(h.rb)
	return h, agents
}

func stepOrder(run RunbookRunJSON) []string {
	var order []string
	for _, s := range run.Steps {
		order = append(order, s.ID)
	}
	return order
}

// programs are the program and first argument of each command run: enough to
// tell sh -c scripts apart from the rest by their position.
func programs(argv [][]string) []string {
	var out []string
	for _, a := range argv {
		out = append(out, strings.Join(a[:min(2, len(a))], " "))
	}
	return out
}

var (
	talosAddHealth = append(slices.Clone(talosctl), "192.0.2.10", "health", "--wait-timeout", "5m")
	talosAddApply  = []string{
		"/usr/local/bin/talosctl", "apply-config", "--insecure", "--nodes", "192.0.2.50", "--file", "/etc/talos/worker.yaml",
	}
)

func talosAddHarness(t *testing.T, newNodeHealthy bool, edits map[string]string) (*rbHarness, *recordingAgents) {
	t.Helper()
	edits[`"${{ vars.node-ip }}:50000"`] = `"` + tcpListener(t) + `"`
	running := talos.Service{ID: "apid", State: "Running", Health: talos.HealthHealthy}
	tal := &fakeTalos{nodes: []talos.Node{
		{Address: "192.0.2.10", Hostname: "talos-cp-1", Version: "v1.12.8", Healthy: true, Services: []talos.Service{running}},
		{Address: "192.0.2.50", Hostname: "talos-worker-1", Version: "v1.12.8", Healthy: newNodeHealthy, Services: []talos.Service{running}},
	}}
	return recipeHarness(t, "add-talos-node.yaml", edits, &fakeNodes{nodes: map[string]error{"talos-worker-1": nil}}, tal)
}

// The Talos recipe checks the cluster, asks about quorum and for the
// go-ahead, applies the config once, waits for the node through the Talos API
// and Kubernetes, and checks the cluster again.
func TestTalosAddRecipeRunsInOrder(t *testing.T) {
	h, agents := talosAddHarness(t, true, map[string]string{})
	id := h.start("add-talos-node")
	answerAt(h, id, "ready", ConfirmYes)
	answerAt(h, id, "quorum", ConfirmYes)
	answerAt(h, id, "approve", ConfirmYes)
	run := h.await(id, RunbookSucceeded)
	want := []string{
		"ready", "hub-talos-access", "health-before", "maintenance-api", "quorum", "approve", "apply-config",
		"node-healthy", "node-ready", "health-after", "done",
	}
	if got := stepOrder(run); !slices.Equal(got, want) {
		t.Errorf("steps %v; want %v", got, want)
	}
	if got := agents.all(); !reflect.DeepEqual(got, [][]string{talosAddHealth, talosAddApply, talosAddHealth}) {
		t.Errorf("ran %q; want health, apply-config, health", got)
	}
	var targets []string
	for _, e := range h.audited(policy.TalosRead) {
		targets = append(targets, e.Target)
	}
	if !slices.Equal(targets, []string{"192.0.2.10", "192.0.2.50"}) {
		t.Errorf("talos.read targets %v; want the control plane, then the new node", targets)
	}
}

// Answering no to the go-ahead stops the run before apply-config.
func TestTalosAddRecipeStopsWithoutApproval(t *testing.T) {
	h, agents := talosAddHarness(t, true, map[string]string{})
	id := h.start("add-talos-node")
	answerAt(h, id, "ready", ConfirmYes)
	answerAt(h, id, "quorum", ConfirmYes)
	answerAt(h, id, "approve", ConfirmNo)
	h.await(id, RunbookFailed)
	if got := agents.all(); !reflect.DeepEqual(got, [][]string{talosAddHealth}) {
		t.Errorf("ran %q; want only the health check", got)
	}
}

// A node that never gets healthy stops the run; rolling back runs nothing on
// a device and logs how to remove the node by hand. The check's 20 minutes
// are cut to 2 seconds.
func TestTalosAddRecipeRollsBackNothingOnADevice(t *testing.T) {
	h, agents := talosAddHarness(t, false, map[string]string{
		"      healthy: true\n    within: 20m\n": "      healthy: true\n    within: 2s\n",
	})
	id := h.start("add-talos-node")
	answerAt(h, id, "ready", ConfirmYes)
	answerAt(h, id, "quorum", ConfirmYes)
	answerAt(h, id, "approve", ConfirmYes)
	run := h.await(id, RunbookFailed)
	if !slices.ContainsFunc(run.Steps, func(s RunbookStepState) bool {
		return s.ID == "node-healthy" && s.Status == stepFailed
	}) {
		t.Fatalf("node-healthy did not fail: %+v", run.Steps)
	}
	h.rollback(id)
	h.await(id, RunbookRolledBack)
	if got := agents.all(); !reflect.DeepEqual(got, [][]string{talosAddHealth, talosAddApply}) {
		t.Errorf("ran %q; want health and apply-config, and no reset", got)
	}
}

// The Talos recipe's rollbacks only log guidance; its prompts name the
// quorum risk and the trust-on-first-use risk of --insecure.
func TestTalosAddRecipeWarns(t *testing.T) {
	rb, err := LoadRunbookFile(recipesDir+"/add-talos-node.yaml", recipeKinds())
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, s := range rb.Steps {
		seen[s.ID] = true
		if s.Rollback != nil && s.Rollback.Impl.Policy() != policy.AutomationLog {
			t.Errorf("step %s rolls back with %s; want guidance only", s.ID, s.Rollback.Impl.Policy())
		}
		switch s.ID {
		case "quorum":
			if s.Type != RunbookStepPrompt || !strings.Contains(s.Prompt.Message, "etcd") {
				t.Errorf("quorum is not the etcd prompt: %+v", s)
			}
		case "approve":
			if s.Type != RunbookStepPrompt || !strings.Contains(s.Prompt.Message, "--insecure") ||
				!strings.Contains(s.Prompt.Message, "trust on first use") {
				t.Errorf("approve does not explain --insecure: %+v", s)
			}
		case "node-healthy":
			if s.Check == nil || s.Check.talosNode == nil || *s.Check.talosNode != (talosNodeCheck{node: "192.0.2.50", healthy: true}) {
				t.Errorf("node-healthy is not a talos_node check of the new node: %+v", s)
			}
		}
	}
	for _, id := range []string{"quorum", "approve", "node-healthy", "apply-config"} {
		if !seen[id] {
			t.Errorf("no step %s", id)
		}
	}
}

// installerSHA is the sha256 of k3s's install.sh at the recipe's version.
const installerSHA = "ed01f89fd977bf20ac1516bbebf8370bf3ddbaa55dac8aba610956a4c78cc00b"

// pipedIntoShell matches a download piped straight into a shell.
var pipedIntoShell = regexp.MustCompile(`\|\s*(ba)?sh(\s|$)`)

// The k3s recipe downloads and checks the installer, asks again, then
// installs with the token read from its file on the device: the token is in
// no command, prompt, plan or audit entry.
func TestK3sAddRecipeRunsInOrderWithTheTokenInAFile(t *testing.T) {
	h, agents := recipeHarness(t, "add-k3s-node.yaml", map[string]string{
		`"${{ vars.server-ip }}:6443"`: `"` + tcpListener(t) + `"`,
	}, &fakeNodes{nodes: map[string]error{"k3s-new": nil}}, nil)
	id := h.start("add-k3s-node")
	answerAt(h, id, "ready", ConfirmYes)
	answerAt(h, id, "approve-download", ConfirmYes)
	answerAt(h, id, "approve-install", ConfirmYes)
	run := h.await(id, RunbookSucceeded)
	want := []string{
		"ready", "server-up", "approve-download", "fetch-installer", "forget-node", "approve-install", "install",
		"node-ready", "done",
	}
	if got := stepOrder(run); !slices.Equal(got, want) {
		t.Errorf("steps %v; want %v", got, want)
	}
	got := agents.all()
	if len(got) != 2 || !slices.Equal(programs(got), []string{"/bin/sh -c", "/bin/sh -c"}) {
		t.Fatalf("ran %q; want the fetch, then the install", got)
	}
	fetch, install := got[0], got[1]
	if !slices.Equal(fetch[3:], []string{"sh", "v1.37.2+k3s1", installerSHA}) ||
		!strings.Contains(fetch[2], "sha256sum -c") || pipedIntoShell.MatchString(fetch[2]) {
		t.Errorf("fetch = %q; want a download checked against the pinned sha256, not piped into a shell", fetch)
	}
	if !slices.Equal(install[3:], []string{"sh", "v1.37.2+k3s1", installerSHA, "https://192.0.2.10:6443", "/etc/hearth/k3s-token"}) ||
		!strings.Contains(install[2], "sha256sum -c") || !strings.Contains(install[2], `--token-file "$4"`) {
		t.Errorf("install = %q; want the sha256 checked again and the token read from its file", install)
	}
	// The token never passes through the hub: no prompt asks for it, and
	// nothing the run records names more than its file.
	secretish := regexp.MustCompile(`(?i)(--token[ =]|K3S_TOKEN=|K10[0-9a-f]{20})`)
	audit, err := json.Marshal(h.audit.all())
	if err != nil {
		t.Fatal(err)
	}
	runJSON, err := json.Marshal(h.get(id))
	if err != nil {
		t.Fatal(err)
	}
	for what, b := range map[string][]byte{"audit": audit, "run": runJSON, "argv": []byte(strings.Join(slices.Concat(got...), " "))} {
		if m := secretish.Find(b); m != nil {
			t.Errorf("%s holds something like a token: %q", what, m)
		}
	}
}

// The Docker recipe asks before each change, and a run stopped at the group
// prompt rolls back the install and the repository, last first.
func TestDockerAddRecipeRunsInOrderAndRollsBack(t *testing.T) {
	edits := func() map[string]string {
		host, port, err := net.SplitHostPort(tcpListener(t))
		if err != nil {
			t.Fatal(err)
		}
		return map[string]string{"  address: 192.0.2.70\n": "  address: " + host + "\n", `}}:22"`: `}}:` + port + `"`}
	}
	t.Run("all the way", func(t *testing.T) {
		h, agents := recipeHarness(t, "add-docker-host.yaml", edits(), nil, nil)
		id := h.start("add-docker-host")
		for _, p := range []string{"ready", "approve-repo", "approve-install", "approve-group", "approve-hello"} {
			answerAt(h, id, p, ConfirmYes)
		}
		h.await(id, RunbookSucceeded)
		got := agents.all()
		want := []string{"/bin/sh -c", "/bin/sh -c", "/usr/bin/docker version", "/usr/sbin/usermod -aG", "/usr/bin/docker run"}
		if !slices.Equal(programs(got), want) {
			t.Fatalf("ran %q; want %v", got, want)
		}
		if repo := got[0]; !slices.Equal(repo[3:], []string{"sh", "debian", "9DC858229FC7DD38854AE2D88D81803C0EBFCD88"}) ||
			!strings.Contains(repo[2], "gpg --batch --show-keys") {
			t.Errorf("add-repo = %q; want the key checked against the pinned fingerprint", repo)
		}
		if !slices.Equal(got[3], []string{"/usr/sbin/usermod", "-aG", "docker", "pi"}) {
			t.Errorf("group = %q", got[3])
		}
	})
	t.Run("stopped at the group", func(t *testing.T) {
		h, agents := recipeHarness(t, "add-docker-host.yaml", edits(), nil, nil)
		id := h.start("add-docker-host")
		for _, p := range []string{"ready", "approve-repo", "approve-install"} {
			answerAt(h, id, p, ConfirmYes)
		}
		answerAt(h, id, "approve-group", ConfirmNo)
		h.await(id, RunbookFailed)
		h.rollback(id)
		h.await(id, RunbookRolledBack)
		want := []string{"/bin/sh -c", "/bin/sh -c", "/usr/bin/docker version", "/usr/bin/apt-get purge", "/bin/rm -f"}
		if got := agents.all(); !slices.Equal(programs(got), want) {
			t.Errorf("ran %q; want %v", got, want)
		}
	})
}
