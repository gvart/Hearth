// SPDX-License-Identifier: AGPL-3.0-only

package automation

import (
	"fmt"
	"io"
	"maps"
	"slices"
	"strconv"
	"strings"

	"github.com/gvart/hearth/internal/policy"
)

// Plan writes what a would do when triggered, without running anything: it
// only describes its steps, and never checks a condition or executes an
// action.
func Plan(w io.Writer, a *Automation) error {
	var b strings.Builder
	fmt.Fprintf(&b, "Automation %s (mode %s), from %s\n", a.ID, a.Mode, a.File)
	if a.Description != "" {
		fmt.Fprintf(&b, "  %s\n", strconv.Quote(a.Description))
	}
	b.WriteString("\nRuns when any of these fire:\n")
	for _, t := range a.Triggers {
		fmt.Fprintf(&b, "  - %s (%s): %s%s\n", t.ID, t.Type, planLine(t.Impl.Describe()), suffix(t.Description))
		fmt.Fprintf(&b, "    templates see: %s\n", strings.Join(fieldNames(t.Impl.Sample()), ", "))
	}
	if len(a.Conditions) > 0 {
		b.WriteString("\nIf all of these hold:\n")
		for _, c := range a.Conditions {
			fmt.Fprintf(&b, "  - %s (%s): %s%s\n", c.ID, c.Type, planLine(c.Impl.Describe()), suffix(c.Description))
		}
	}
	b.WriteString("\nThen, in order, stopping at the first that fails or is denied:\n")
	for i, s := range a.Actions {
		class, _ := policy.ClassOf(s.Impl.Policy())
		target := ""
		if t := s.Impl.Target().String(); t != "" {
			target = " on " + planLine(t)
		}
		fmt.Fprintf(&b, "  %d. %s (%s): %s%s%s\n     policy: %s (%s), actor automation/%s\n",
			i+1, s.ID, s.Type, planLine(s.Impl.Describe()), target, suffix(s.Description), s.Impl.Policy(), class, a.ID)
	}
	b.WriteString("\nDry run: nothing was executed.\n")
	if _, err := io.WriteString(w, b.String()); err != nil {
		return fmt.Errorf("write plan: %w", err)
	}
	return nil
}

// fieldNames lists the template fields a firing with this data provides.
func fieldNames(data map[string]any) []string {
	names := []string{".Trigger.ID", ".Trigger.Type", ".Trigger.At"}
	for _, k := range slices.Sorted(maps.Keys(data)) {
		names = append(names, ".Trigger."+k)
	}
	return names
}

// planLine keeps text from a file on its line of the plan: someone approving
// the file reads the plan, and a line break could fake the plan's own lines.
func planLine(s string) string {
	for _, r := range s {
		if !strconv.IsPrint(r) {
			return strconv.Quote(s)
		}
	}
	return s
}

func suffix(description string) string {
	if description == "" {
		return ""
	}
	return " — " + strconv.Quote(description)
}
