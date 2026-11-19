// SPDX-License-Identifier: AGPL-3.0-only

package automation

import (
	"errors"
	"fmt"
	"strings"
	"text/template"
	"time"
)

// Text is an action's string field, which may hold Go templates over the
// event that started the run: "{{ .Trigger.Device }}". Templates get no
// functions beyond text/template's built-in ones, and a key the event does
// not have is an error, never an empty string.
type Text struct {
	raw string
	// t is nil when raw holds no template.
	t *template.Template
	// line is where the field is in its file, for load errors.
	line int
}

// Literal is a Text that is never rendered as a template.
func Literal(s string) Text { return Text{raw: s} }

// String returns the field as written, templates unrendered.
func (x Text) String() string { return x.raw }

// Render executes the field's templates for ev.
func (x Text) Render(ev Event) (string, error) {
	if x.t == nil {
		return x.raw, nil
	}
	var b strings.Builder
	if err := x.t.Execute(&b, ev.templateData()); err != nil {
		return "", templateErr(err)
	}
	return b.String(), nil
}

// templateData is what templates see: the trigger's fields under .Trigger
// and, in a runbook step allowed them, prompt answers under .Input.
func (ev Event) templateData() map[string]any {
	trig := make(map[string]any, len(ev.Data)+3)
	for k, v := range ev.Data {
		trig[k] = v
	}
	trig["ID"] = ev.TriggerID
	trig["Type"] = ev.TriggerType
	trig["At"] = ev.At.UTC().Format(time.RFC3339)
	data := map[string]any{"Trigger": trig}
	if ev.Input != nil {
		data["Input"] = ev.Input
	}
	return data
}

// texted is an action with template fields, which the loader checks against
// every trigger of its automation.
type texted interface {
	texts() []Text
}

// Text parses the string field at path (a key, or keys into nested
// mappings) as a template. A parse error is reported at the field's line.
func (p Params) Text(raw string, path ...string) (Text, error) {
	line := p.line(path...)
	if !strings.Contains(raw, "{{") {
		return Text{raw: raw, line: line}, nil
	}
	t, err := template.New(strings.Join(path, ".")).Option("missingkey=error").Parse(raw)
	if err != nil {
		return Text{}, lineError(line, "%s: %v", strings.Join(path, "."), err)
	}
	return Text{raw: raw, t: t, line: line}, nil
}

// line returns the line of the value at path, or of the step if it is not
// there.
func (p Params) line(path ...string) int {
	n := p.node
	line := n.Line
	for _, key := range path {
		next := n
		for i := 0; i+1 < len(n.Content); i += 2 {
			if n.Content[i].Value == key {
				next = n.Content[i+1]
				break
			}
		}
		if next == n {
			return line
		}
		n, line = next, next.Line
	}
	return line
}

// checkTemplates renders every template of a's actions for a sample firing
// of each of its triggers, so a template that names a field some trigger
// does not provide fails the load, at its line, rather than a run.
func checkTemplates(a *Automation, errs *[]error) {
	for _, s := range a.Actions {
		tx, ok := s.Impl.(texted)
		if !ok {
			continue
		}
		for _, x := range tx.texts() {
			for _, tr := range a.Triggers {
				ev := Event{TriggerID: tr.ID, TriggerType: tr.Type, Data: tr.Impl.Sample()}
				if _, err := x.Render(ev); err != nil {
					*errs = append(*errs, lineError(x.line, "action %s: %v (when trigger %s fires)", s.ID, err, tr.ID))
					break
				}
			}
		}
	}
}

// templateErr shortens text/template's execution errors to what the user
// needs: `executing "device" at <.Trigger.Foo>: map has no entry for key
// "Foo"` becomes `device: .Trigger.Foo: no such field`.
func templateErr(err error) error {
	var ee template.ExecError
	if !errors.As(err, &ee) {
		return err
	}
	msg := ee.Err.Error()
	if _, rest, ok := strings.Cut(msg, " at <"); ok {
		if node, why, ok := strings.Cut(rest, ">: "); ok {
			if strings.HasPrefix(why, "map has no entry for key") {
				why = "no such field"
			}
			return fmt.Errorf("%s: %s: %s", ee.Name, node, why)
		}
	}
	return err
}
