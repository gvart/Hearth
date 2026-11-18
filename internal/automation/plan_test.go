// SPDX-License-Identifier: AGPL-3.0-only

package automation

import (
	"strings"
	"testing"

	"github.com/gvart/hearth/internal/policy"
)

// A dry run describes every step and executes none: no trigger is watched,
// no condition checked, no action run, nothing audited or recorded.
func TestPlanNeverExecutes(t *testing.T) {
	act := &fakeAction{policy: policy.AutomationLog}
	cond := &fakeCondition{holds: true}
	trig := &fakeTrigger{}
	a, err := Parse("plan.yaml", []byte(`id: plan-me
description: Shows what would happen.
mode: restart
triggers:
  - id: tick
    type: fake
  - id: go
    type: manual
conditions:
  - id: check
    type: fake
    description: only then
actions:
  - id: act
    type: fake
  - id: say
    type: log
    message: done
`), testKinds(act, cond, trig))
	if err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	if err := Plan(&out, a); err != nil {
		t.Fatal(err)
	}
	if act.started() != 0 || cond.checks != 0 || trig.watched != 0 {
		t.Fatalf("dry run executed: %d actions, %d checks, %d watches", act.started(), cond.checks, trig.watched)
	}
	for _, want := range []string{
		"Automation plan-me (mode restart), from plan.yaml",
		"Shows what would happen.",
		"- tick (fake): fires in tests",
		"- go (manual): fires when run by hand",
		"- check (fake): the fake condition holds — only then",
		"1. act (fake): do the fake thing on fake-target",
		"policy: automation.log (read), actor automation/plan-me",
		`2. say (log): log "done"`,
		"Dry run: nothing was executed.",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("plan does not contain %q:\n%s", want, out.String())
		}
	}
}
