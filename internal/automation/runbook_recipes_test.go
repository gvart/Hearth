// SPDX-License-Identifier: AGPL-3.0-only

package automation

import (
	"context"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/gvart/hearth/internal/policy"
)

// recipesDir holds the runbook recipes shipped for users to copy.
const recipesDir = "../../docs/recipes/runbooks"

// recipesPage is the docs page that shows every recipe.
const recipesPage = "../../docs/runbook-recipes.md"

var wantRecipes = []string{"add-talos-node", "add-k3s-node", "add-docker-host"}

// readOnlySteps are action steps that only read, so they need no rollback.
var readOnlySteps = map[string]bool{"add-docker-host/verify": true}

func recipeKinds() Kinds {
	k := builtinKinds()
	maps.Copy(k.Actions, Actions(ActionDeps{Agents: &recordingAgents{}}))
	return k
}

func recipeFiles(t *testing.T) []string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(recipesDir, "*.yaml"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no recipes in %s: %v", recipesDir, err)
	}
	return files
}

func TestRecipesLoadWithTheRunbookParser(t *testing.T) {
	kinds := recipeKinds()
	files := recipeFiles(t)
	for _, f := range files {
		t.Run(filepath.Base(f), func(t *testing.T) {
			b, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			rb, err := ParseRunbook(f, b, kinds)
			if err != nil {
				t.Fatalf("recipe does not load: %v", err)
			}
			if rb.Description == "" {
				t.Error("a recipe needs a description")
			}
			if !strings.Contains(string(b), "Prerequisites") {
				t.Error("a recipe must state its prerequisites in a comment")
			}
			if want := strings.TrimSuffix(filepath.Base(f), ".yaml"); rb.ID != want {
				t.Errorf("id %q does not match the file name %q", rb.ID, want)
			}
		})
	}
	// The directory as a whole loads: every id unique, nothing left out.
	all, errs := LoadRunbooks(recipesDir, kinds)
	if len(errs) > 0 {
		t.Fatalf("LoadRunbooks: %v", errs)
	}
	got := map[string]bool{}
	for _, rb := range all {
		got[rb.ID] = true
	}
	for _, id := range wantRecipes {
		if !got[id] {
			t.Errorf("recipe %s is missing", id)
		}
	}
}

func TestRecipeChecksAndRollbacksAreWellFormed(t *testing.T) {
	kinds := recipeKinds()
	for _, f := range recipeFiles(t) {
		rb, err := LoadRunbookFile(f, kinds)
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		var checks, rollbacks, prompts int
		for _, s := range rb.Steps {
			switch s.Type {
			case RunbookStepCheck:
				checks++
				if s.Check == nil || s.Check.from != "" {
					t.Errorf("%s step %s: check missing or not from the hub", rb.ID, s.ID)
				}
				// A check that is tried once would fail while a node is still booting.
				if s.Within <= 0 || s.Every < minEvery || s.Every > s.Within {
					t.Errorf("%s step %s: within %s every %s", rb.ID, s.ID, s.Within, s.Every)
				}
			case RunbookStepAction:
				if s.Rollback == nil {
					continue
				}
				rollbacks++
				if s.Rollback.Impl == nil {
					t.Errorf("%s step %s: rollback has no action", rb.ID, s.ID)
					continue
				}
				if _, ok := policy.ClassOf(s.Rollback.Impl.Policy()); !ok {
					t.Errorf("%s step %s: rollback has no policy class", rb.ID, s.ID)
				}
			case RunbookStepPrompt:
				prompts++
				if s.Prompt.Secret {
					t.Errorf("%s step %s: no recipe needs a secret answer; reference a file on the device", rb.ID, s.ID)
				}
			}
		}
		if checks == 0 {
			t.Errorf("%s has no check step", rb.ID)
		}
		if prompts == 0 {
			t.Errorf("%s has no prompt for its manual steps", rb.ID)
		}
		// Every step that changes a device has a rollback, unless it only reads.
		for _, s := range rb.Steps {
			if readOnlySteps[rb.ID+"/"+s.ID] {
				continue
			}
			if s.Type == RunbookStepAction && s.Rollback == nil && s.Action.Impl.Policy() != policy.AutomationLog {
				t.Errorf("%s step %s changes something and has no rollback", rb.ID, s.ID)
			}
		}
		if rollbacks == 0 {
			t.Errorf("%s declares no rollback", rb.ID)
		}
	}
}

func TestRecipesHoldInlineNoSecrets(t *testing.T) {
	secretish := regexp.MustCompile(`(?i)(--token[ =]|--password|K3S_TOKEN=|\bpassword:|\btoken:\s*\S|bearer )`)
	for _, f := range recipeFiles(t) {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(b), "\n") {
			if secretish.MatchString(line) {
				t.Errorf("%s:%d looks like an inline secret: %s", filepath.Base(f), i+1, line)
			}
		}
	}
}

func TestRecipesPlanInADryRun(t *testing.T) {
	// A hub that grants nothing: dangerous steps must be held, never allowed.
	e := NewRunbooks(RunbooksConfig{
		Dir: recipesDir, Kinds: recipeKinds(),
		Policy: policy.NewWithConfig(&auditLog{}, nil, policy.Config{}),
	})
	all, errs := e.List()
	if len(errs) > 0 || len(all) < len(wantRecipes) {
		t.Fatalf("recipes: %d loaded, errors %v", len(all), errs)
	}
	for _, rb := range all {
		plan, err := e.Plan(context.Background(), rb.ID)
		if err != nil {
			t.Fatalf("plan %s: %v", rb.ID, err)
		}
		if len(plan.Steps) != len(rb.Steps) || len(plan.Steps) == 0 {
			t.Fatalf("%s: plan has %d steps, runbook %d", rb.ID, len(plan.Steps), len(rb.Steps))
		}
		var dangerous int
		for _, s := range plan.Steps {
			if s.What == "" {
				t.Errorf("%s step %s: empty plan line", rb.ID, s.ID)
			}
			for _, p := range []*RunbookPlanStep{&s, s.Rollback} {
				if p == nil || p.Action == "" {
					continue
				}
				if p.Class == string(policy.Dangerous) {
					dangerous++
					if p.Decision == policy.Allow {
						t.Errorf("%s step %s: a dangerous step is allowed with no grant", rb.ID, s.ID)
					}
				} else if p.Decision == policy.Deny {
					t.Errorf("%s step %s: denied by default policy: %s", rb.ID, s.ID, p.Reason)
				}
			}
			if s.Type == RunbookStepCheck && s.Decision != policy.Allow {
				t.Errorf("%s step %s: check decision %q", rb.ID, s.ID, s.Decision)
			}
		}
		if dangerous == 0 {
			t.Errorf("%s: the plan shows no dangerous step to hold", rb.ID)
		}
	}
}

// The node recipes wait for the node with a kube_node check and delete its
// Node object on a rollback, after the step that resets or uninstalls it; every
// recipe names its targets once, in vars.
func TestRecipesUseVarsAndTheKubernetesSteps(t *testing.T) {
	kinds := recipeKinds()
	for _, f := range recipeFiles(t) {
		rb, err := LoadRunbookFile(f, kinds)
		if err != nil {
			t.Fatal(err)
		}
		if len(rb.Vars) == 0 {
			t.Errorf("%s has no vars", rb.ID)
		}
		if rb.ID == "add-docker-host" {
			continue
		}
		deleteAt, lastExecRollback, kubeCheck := -1, -1, false
		for i, s := range rb.Steps {
			if s.Check != nil && s.Check.kubeNode != nil {
				kubeCheck = true
			}
			if s.Rollback == nil {
				continue
			}
			switch s.Rollback.Impl.Policy() {
			case policy.KubeNodeDelete:
				deleteAt = i
			case policy.AutomationExec:
				lastExecRollback = i
			}
		}
		if !kubeCheck {
			t.Errorf("%s has no kube_node check", rb.ID)
		}
		// Rollback runs last step first: the Node is deleted after the node
		// is reset or uninstalled, so its kubelet cannot register it again.
		if deleteAt < 0 || deleteAt > lastExecRollback {
			t.Errorf("%s: kube_node_delete rollback at step %d, want before the reset at %d", rb.ID, deleteAt, lastExecRollback)
		}
	}
}

// The docs page shows each recipe exactly as the file is: the page is what
// users read, the file what they copy.
func TestRecipesPageShowsEveryRecipeVerbatim(t *testing.T) {
	page, err := os.ReadFile(recipesPage)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range recipeFiles(t) {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(page), "```yaml\n"+strings.TrimRight(string(b), "\n")+"\n```") {
			t.Errorf("%s differs from its copy in %s", filepath.Base(f), recipesPage)
		}
	}
}
