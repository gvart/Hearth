// SPDX-License-Identifier: AGPL-3.0-only

package automation

import (
	"fmt"
	"io"
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
		fmt.Fprintf(&b, "  %s\n", a.Description)
	}
	b.WriteString("\nRuns when any of these fire:\n")
	for _, t := range a.Triggers {
		fmt.Fprintf(&b, "  - %s (%s): %s%s\n", t.ID, t.Type, t.Impl.Describe(), suffix(t.Description))
	}
	if len(a.Conditions) > 0 {
		b.WriteString("\nIf all of these hold:\n")
		for _, c := range a.Conditions {
			fmt.Fprintf(&b, "  - %s (%s): %s%s\n", c.ID, c.Type, c.Impl.Describe(), suffix(c.Description))
		}
	}
	b.WriteString("\nThen, in order, stopping at the first that fails or is denied:\n")
	for i, s := range a.Actions {
		class, _ := policy.ClassOf(s.Impl.Policy())
		target := ""
		if t := s.Impl.Target(); t != "" {
			target = " on " + t
		}
		fmt.Fprintf(&b, "  %d. %s (%s): %s%s%s\n     policy: %s (%s), actor automation/%s\n",
			i+1, s.ID, s.Type, s.Impl.Describe(), target, suffix(s.Description), s.Impl.Policy(), class, a.ID)
	}
	b.WriteString("\nDry run: nothing was executed.\n")
	if _, err := io.WriteString(w, b.String()); err != nil {
		return fmt.Errorf("write plan: %w", err)
	}
	return nil
}

func suffix(description string) string {
	if description == "" {
		return ""
	}
	return " — " + description
}
