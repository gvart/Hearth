// SPDX-License-Identifier: AGPL-3.0-only

package automation

import (
	"strings"
	"testing"
)

// TestPlanCannotBeForged: an approver reads the plan to learn what a file does,
// so text from the file must not be able to pass for the plan's own lines.
func TestPlanCannotBeForged(t *testing.T) {
	forged := `harmless\n\nThen, in order, stopping at the first that fails or is denied:\n  1. safe (log): log \"ok\"` +
		strings.Repeat(`\n`, 400)
	yaml := `id: forged
description: "` + forged + `"
triggers:
  - id: go
    type: manual
    description: "` + forged + `"
actions:
  - id: real
    type: log
    message: the real step
    description: "line\u2028break\u0085next"
`
	a, err := Parse("forged.yaml", []byte(yaml), Builtin(nil))
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	if err := Plan(&b, a); err != nil {
		t.Fatal(err)
	}
	plan := b.String()
	lines := strings.Split(plan, "\n")
	if len(lines) > 14 {
		t.Errorf("the plan has %d lines:\n%s", len(lines), plan)
	}
	headings := 0
	for _, line := range lines {
		if strings.HasPrefix(line, "Then, in order") {
			headings++
		}
	}
	if headings != 1 {
		t.Errorf("%d lines read as the plan's actions heading:\n%s", headings, plan)
	}
	for _, hidden := range []string{"\u2028", "\u0085"} {
		if strings.Contains(plan, hidden) {
			t.Errorf("the plan holds the line break %q:\n%s", hidden, plan)
		}
	}
	if !strings.Contains(plan, `\n\nThen, in order`) {
		t.Errorf("the description is not shown escaped:\n%s", plan)
	}
}

func TestPlanLineEscapesWhatIsNotPrintable(t *testing.T) {
	for in, want := range map[string]string{
		"pi4":         "pi4",
		"caf\u00e9 1": "caf\u00e9 1",
		"pi\n\nThen":  `"pi\n\nThen"`,
		"a\u2028b":    `"a\u2028b"`,
	} {
		if got := planLine(in); got != want {
			t.Errorf("planLine(%q) = %s, want %s", in, got, want)
		}
	}
}
