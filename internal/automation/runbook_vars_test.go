// SPDX-License-Identifier: AGPL-3.0-only

package automation

import (
	"context"
	"log/slog"
	"maps"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/policy"
)

func varsKinds() Kinds {
	k := Builtin(slog.New(slog.DiscardHandler))
	maps.Copy(k.Actions, Actions(ActionDeps{Agents: &recordingAgents{}}))
	return k
}

func TestRunbookVarsAreFilledInAtLoad(t *testing.T) {
	const file = `id: rb
vars:
  node: pi-3
  addr: 192.0.2.50
  wait: 2m
steps:
  - id: up
    type: check
    check: {type: tcp, address: "${{ vars.addr }}:50000"}
    within: ${{ vars.wait }}
    every: 10s
  - id: apply
    type: action
    action:
      type: exec
      device: ${{vars.node}}
      command: [/usr/bin/talosctl, --nodes, "${{ vars.addr }}"]
    rollback:
      type: kube_uncordon
      cluster: lab
      node: ${{ vars.node }}
  - id: done
    type: action
    action: {type: log, message: "node ${{ vars.node }} at ${{ vars.addr }} joined"}
`
	rb, err := ParseRunbook("rb.yaml", []byte(file), varsKinds())
	if err != nil {
		t.Fatal(err)
	}
	if want := map[string]string{"node": "pi-3", "addr": "192.0.2.50", "wait": "2m"}; !reflect.DeepEqual(rb.Vars, want) {
		t.Errorf("Vars = %v, want %v", rb.Vars, want)
	}
	up, apply, done := rb.Steps[0], rb.Steps[1], rb.Steps[2]
	if up.Check.target != "192.0.2.50:50000" || up.Within != 2*time.Minute {
		t.Errorf("check = %s within %s", up.Check.target, up.Within)
	}
	if got := apply.Action.Impl.Target().String(); got != "pi-3" {
		t.Errorf("exec target = %q", got)
	}
	if got := apply.What(); !strings.Contains(got, "192.0.2.50") {
		t.Errorf("exec What = %q, want the address filled in", got)
	}
	if got := apply.Rollback.Impl.Target().String(); got != "lab/pi-3" {
		t.Errorf("rollback target = %q", got)
	}
	msg, err := done.Action.Impl.(texted).texts()[0].Render(context.Background(), runbookEvent("rb", time.Time{}, nil))
	if err != nil || msg != "node pi-3 at 192.0.2.50 joined" {
		t.Errorf("log message = %q, %v", msg, err)
	}

	// The plan shows the steps with the values filled in.
	h := newRBHarness(t, file, policy.Config{})
	plan, err := h.rb.Plan(context.Background(), "rb")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(plan.Steps[0].What, "192.0.2.50:50000") || plan.Steps[1].Target != "pi-3" ||
		plan.Steps[1].Rollback.Target != "lab/pi-3" {
		t.Errorf("plan = check %q, apply target %q, rollback target %q", plan.Steps[0].What, plan.Steps[1].Target, plan.Steps[1].Rollback.Target)
	}
}

func TestRunbookVarsRejects(t *testing.T) {
	step := func(field string) string {
		return "steps:\n  - id: a\n    type: prompt\n    message: hi\n" +
			"  - {type: action, action: {type: exec, device: " + field + ", command: [/bin/true]}}\n"
	}
	for _, tc := range []struct{ name, yaml, want string }{
		{"undefined var", "id: rb\n" + step(`"${{ vars.nope }}"`), `var "nope" is not declared`},
		{"unused var", "id: rb\nvars: {node: pi, extra: x}\n" + step(`"${{ vars.node }}"`), "var extra is not used"},
		{"other expression", "id: rb\n" + step(`"${{ inputs.a }}"`), "only ${{ vars.<name> }}"},
		{"vars not a mapping", "id: rb\nvars: [a]\n" + step("pi"), "vars must be a mapping"},
		{"list value", "id: rb\nvars: {node: [a]}\n" + step(`"${{ vars.node }}"`), "single value"},
		{"bad name", "id: rb\nvars: {Node: pi}\n" + step(`"${{ vars.Node }}"`), "var name \"Node\""},
		{"var refers to a var", "id: rb\nvars: {a: pi, b: '${{ vars.a }}'}\n" + step(`"${{ vars.b }}"`), "literal value"},
		// A prompt answer never chooses a target, through a var or not.
		{
			"var holds a prompt answer",
			"id: rb\nvars: {node: '{{ .Input.a }}'}\n" + step(`"${{ vars.node }}"`), "literal value",
		},
		{"prompt answer in the target", "id: rb\n" + step(`"{{ .Input.a }}"`), "cannot use them"},
		{
			"prompt answer next to a var in the target",
			"id: rb\nvars: {node: pi}\n" + step(`"${{ vars.node }}{{ .Input.a }}"`), "cannot use them",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseRunbook("rb.yaml", []byte(tc.yaml), varsKinds())
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

// A prompt whose id is a var's name sets nothing: the answer is .Input data,
// and the action acts on the var's value from the file.
func TestRunbookPromptAnswerCannotSetAVar(t *testing.T) {
	allowAll := policy.Config{Classes: map[policy.Class]policy.Mode{
		policy.Read: policy.ModeAllow, policy.Safe: policy.ModeAllow, policy.Dangerous: policy.ModeAllow,
	}}
	h := newRBHarness(t, `id: rb
vars:
  node: pi-1
steps:
  - id: node
    type: prompt
    message: Which node?
  - id: go
    type: action
    action: {type: exec, device: "${{ vars.node }}", command: [/bin/true]}
`, allowAll)
	h.run(h.rb)
	id := h.start("rb")
	h.await(id, RunbookWaiting)
	h.answer(id, "node", "evil-host")
	h.await(id, RunbookSucceeded)
	got := h.audited(policy.AutomationExec)
	if len(got) == 0 {
		t.Fatal("no exec was audited")
	}
	for _, e := range got {
		if e.Target != "pi-1" {
			t.Errorf("exec ran on %q, want pi-1 from the file", e.Target)
		}
	}
}
