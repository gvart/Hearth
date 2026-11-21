// SPDX-License-Identifier: AGPL-3.0-only

package automation

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"text/template"
	"text/template/parse"
	"time"
)

const (
	// maxRenderBytes bounds what one field renders to.
	maxRenderBytes = 1 << 20
	// maxRenderBudget bounds the text one render builds along the way.
	maxRenderBudget = 8 * maxRenderBytes
	// maxRenderSteps bounds the writes and loop iterations of one render.
	maxRenderSteps = 100_000
	// maxRenderTime bounds one render.
	maxRenderTime = 2 * time.Second
	// maxCheckTime bounds rendering all of a file's templates at load.
	maxCheckTime = 5 * time.Second
)

// errRenderLimit is a template that renders too much.
var errRenderLimit = errors.New("template exceeds the render limit (1 MiB of output, 8 MiB of text built, 100000 steps or 2 seconds)")

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
	// named says the field uses define, template or block.
	named bool
}

// Literal is a Text that is never rendered as a template.
func Literal(s string) Text { return Text{raw: s} }

// String returns the field as written, templates unrendered.
func (x Text) String() string { return x.raw }

// Render executes the field's templates for ev. It stops when ctx ends, and
// when the template renders more than the limits allow.
func (x Text) Render(ctx context.Context, ev Event) (string, error) {
	return x.renderWithin(ctx, ev, maxRenderTime)
}

// renderWithin is Render with limit as its time limit.
func (x Text) renderWithin(ctx context.Context, ev Event, limit time.Duration) (string, error) {
	if x.t == nil {
		return x.raw, nil
	}
	limited, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	// A clone, for this render's own budget: renders may run side by side.
	t, err := x.t.Clone()
	if err != nil {
		return "", fmt.Errorf("render template: %w", err)
	}
	budget := renderBudget{left: maxRenderBudget}
	t.Funcs(budget.funcs())
	w := renderWriter{stopped: limited.Err}
	if err := t.Execute(&w, ev.templateData()); err != nil {
		if errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil {
			return "", errRenderLimit // the limit ran out, not the caller's time
		}
		return "", templateErr(err)
	}
	return w.b.String(), nil
}

// renderWriter collects a template's output. text/template cannot be
// interrupted, but it stops at the first failed write: boundNode makes every
// loop iteration write, so even a loop with no output comes through here.
type renderWriter struct {
	stopped func() error
	b       strings.Builder
	steps   int
}

func (w *renderWriter) Write(p []byte) (int, error) {
	w.steps++
	if w.steps > maxRenderSteps || w.b.Len()+len(p) > maxRenderBytes {
		return 0, errRenderLimit
	}
	if err := w.stopped(); err != nil {
		return 0, err
	}
	return w.b.Write(p)
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
	return Text{raw: raw, t: t, line: line, named: boundTemplate(t)}, nil
}

// boundTemplate makes every loop iteration and every call of a named template
// count as a step, and reports whether t uses named templates.
func boundTemplate(t *template.Template) (named bool) {
	for _, each := range t.Templates() {
		if each.Tree == nil || each.Root == nil {
			continue
		}
		named = boundList(each.Root) || named || each.Name() != t.Name()
		countStep(each.Root)
	}
	return named
}

// countStep makes running list call the writer: an empty text node writes
// nothing, but it does get written.
func countStep(list *parse.ListNode) {
	list.Nodes = append([]parse.Node{&parse.TextNode{NodeType: parse.NodeText}}, list.Nodes...)
}

// boundList bounds the loops in list, and reports whether it calls a named
// template.
func boundList(list *parse.ListNode) (named bool) {
	if list == nil {
		return false
	}
	for _, n := range list.Nodes {
		named = boundNode(n) || named
	}
	return named
}

func boundNode(n parse.Node) (named bool) {
	switch n := n.(type) {
	case *parse.IfNode:
		return boundBranch(&n.BranchNode)
	case *parse.WithNode:
		return boundBranch(&n.BranchNode)
	case *parse.RangeNode:
		named = boundBranch(&n.BranchNode)
		countStep(n.List)
		return named
	case *parse.TemplateNode:
		return true
	}
	return false
}

func boundBranch(b *parse.BranchNode) (named bool) {
	named = boundList(b.List)
	return boundList(b.ElseList) || named
}

// printfSize finds a width or precision too large for a message, one computed
// when the template runs, or an argument index, which uses one argument over
// and over: one call could build gigabytes.
var printfSize = sync.OnceValue(func() *regexp.Regexp {
	return regexp.MustCompile(`%[-+# 0-9.*]*\[|%[-+# 0]*(\*|\d{4,}|\d*\.(\*|\d{4,}))`)
})

// renderBudget limits the text one render builds, which a value doubled at
// every step could otherwise grow without writing anything.
type renderBudget struct{ left int }

func (b *renderBudget) spend(n int) error {
	if n > b.left {
		return errRenderLimit
	}
	b.left -= n
	return nil
}

// build runs fn, which makes a string out of args, within the budget.
func (b *renderBudget) build(args []any, fn func() string) (string, error) {
	size := 0
	for _, a := range args {
		if s, ok := a.(string); ok {
			size += len(s)
		}
	}
	if err := b.spend(size); err != nil {
		return "", err
	}
	out := fn()
	if err := b.spend(len(out)); err != nil {
		return "", err
	}
	return out, nil
}

// funcs are text/template's functions that build strings, within the budget.
func (b *renderBudget) funcs() template.FuncMap {
	wrap := func(fn func(...any) string) func(...any) (string, error) {
		return func(args ...any) (string, error) {
			return b.build(args, func() string { return fn(args...) })
		}
	}
	return template.FuncMap{
		"print":    wrap(fmt.Sprint),
		"println":  wrap(fmt.Sprintln),
		"html":     wrap(template.HTMLEscaper),
		"js":       wrap(template.JSEscaper),
		"urlquery": wrap(template.URLQueryEscaper),
		"printf": func(format string, args ...any) (string, error) {
			// Every percent sign is checked, %% included: fmt reads %5% as one
			// verb, so dropping %% first would hide the verb after it.
			if printfSize().MatchString(format) {
				return "", errRenderLimit
			}
			return b.build(args, func() string { return fmt.Sprintf(format, args...) })
		},
	}
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
// does not provide fails the load, at its line, rather than a run. A template
// over the render limits is a warning, not a failure: one invalid file stops
// the whole directory loading, and only that template's runs need to fail.
func checkTemplates(a *Automation, errs *[]error) {
	ctx, cancel := context.WithTimeout(context.Background(), maxCheckTime)
	defer cancel()
	for _, s := range a.Actions {
		tx, ok := s.Impl.(texted)
		if !ok {
			continue
		}
		for _, x := range tx.texts() {
			if x.named {
				a.named = append(a.named, Problem{Line: x.line, Message: fmt.Sprintf(
					"action %s: define, template and block are not available here: edit this file on the hub", s.ID)})
			}
			for _, tr := range a.Triggers {
				ev := Event{TriggerID: tr.ID, TriggerType: tr.Type, Data: tr.Impl.Sample()}
				_, err := x.Render(ctx, ev)
				if err == nil {
					continue
				}
				if errors.Is(err, errRenderLimit) || errors.Is(err, context.DeadlineExceeded) {
					a.Warnings = append(a.Warnings, Problem{Line: x.line, Message: fmt.Sprintf(
						"action %s: %v (when trigger %s fires)", s.ID, errRenderLimit, tr.ID)})
				} else {
					*errs = append(*errs, lineError(x.line, "action %s: %v (when trigger %s fires)", s.ID, err, tr.ID))
				}
				break
			}
			if ctx.Err() != nil {
				return // out of time: what is left is judged when it runs
			}
		}
	}
}

// templateErr shortens text/template's execution errors to what the user
// needs: `executing "device" at <.Trigger.Foo>: map has no entry for key
// "Foo"` becomes `device: .Trigger.Foo: no such field`.
func templateErr(err error) error {
	if errors.Is(err, errRenderLimit) {
		return errRenderLimit
	}
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
