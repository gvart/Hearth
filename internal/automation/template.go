// SPDX-License-Identifier: AGPL-3.0-only

package automation

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"text/template"
	"text/template/parse"
	"time"
)

const (
	// maxRenderBytes bounds what one field renders to.
	maxRenderBytes = 1 << 20
	// maxRenderSteps bounds the writes and loop iterations of one render.
	maxRenderSteps = 100_000
	// maxRenderTime bounds one render.
	maxRenderTime = 2 * time.Second
	// maxCheckTime bounds rendering all of a file's templates at load.
	maxCheckTime = 5 * time.Second
)

// errRenderLimit is a template that renders too much.
var errRenderLimit = errors.New("template exceeds the render limit")

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

// Render executes the field's templates for ev. It stops when ctx ends, and
// when the template renders more than the limits allow.
func (x Text) Render(ctx context.Context, ev Event) (string, error) {
	if x.t == nil {
		return x.raw, nil
	}
	ctx, cancel := context.WithTimeout(ctx, maxRenderTime)
	defer cancel()
	w := renderWriter{stopped: ctx.Err}
	if err := x.t.Execute(&w, ev.templateData()); err != nil {
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
	if err := boundTemplate(t); err != nil {
		return Text{}, lineError(line, "%s: %v", strings.Join(path, "."), err)
	}
	return Text{raw: raw, t: t, line: line}, nil
}

// boundTemplate refuses what could use unbounded memory or time before the
// render limits are reached, and makes every loop iteration count as a step.
func boundTemplate(t *template.Template) error {
	if len(t.Templates()) > 1 {
		return errors.New("define and block are not allowed")
	}
	if t.Tree == nil {
		return nil
	}
	return boundList(t.Root)
}

func boundList(list *parse.ListNode) error {
	if list == nil {
		return nil
	}
	for _, n := range list.Nodes {
		if err := boundNode(n); err != nil {
			return err
		}
	}
	return nil
}

func boundNode(n parse.Node) error {
	switch n := n.(type) {
	case *parse.ActionNode:
		return boundPipe(n.Pipe, false)
	case *parse.IfNode:
		return boundBranch(&n.BranchNode, false)
	case *parse.WithNode:
		return boundBranch(&n.BranchNode, false)
	case *parse.RangeNode:
		if err := boundRangeOver(n.Pipe); err != nil {
			return err
		}
		if err := boundBranch(&n.BranchNode, true); err != nil {
			return err
		}
		// An empty text node writes nothing, but it does call the writer.
		n.List.Nodes = append([]parse.Node{&parse.TextNode{NodeType: parse.NodeText}}, n.List.Nodes...)
	case *parse.TemplateNode:
		return errors.New("template is not allowed")
	}
	return nil
}

func boundBranch(b *parse.BranchNode, declares bool) error {
	if err := boundPipe(b.Pipe, declares); err != nil {
		return err
	}
	if err := boundList(b.List); err != nil {
		return err
	}
	return boundList(b.ElseList)
}

// boundRangeOver allows ranging over the event's data only: over a number, a
// file could loop as many times as it likes.
func boundRangeOver(p *parse.PipeNode) error {
	if len(p.Cmds) == 1 && len(p.Cmds[0].Args) == 1 {
		switch p.Cmds[0].Args[0].(type) {
		case *parse.FieldNode, *parse.DotNode, *parse.VariableNode, *parse.ChainNode:
			return nil
		}
	}
	return errors.New("range may only go over a field of the event")
}

// printfSize finds a width or precision too large for a message, or one
// computed when the template runs.
var printfSize = regexp.MustCompile(`%[-+# 0]*(\[|\*|\d{4,}|\d*\.(\[|\*|\d{4,}))`)

func boundPipe(p *parse.PipeNode, declares bool) error {
	if p == nil {
		return nil
	}
	if p.IsAssign || (len(p.Decl) > 0 && !declares) {
		return errors.New("variables are only allowed in range")
	}
	for _, c := range p.Cmds {
		if id, ok := c.Args[0].(*parse.IdentifierNode); ok && id.Ident == "printf" {
			if err := boundPrintf(c); err != nil {
				return err
			}
		}
		for _, arg := range c.Args {
			if err := boundArg(arg); err != nil {
				return err
			}
		}
	}
	return nil
}

func boundPrintf(c *parse.CommandNode) error {
	if len(c.Args) < 2 {
		return errors.New("printf needs its format written in the template")
	}
	format, ok := c.Args[1].(*parse.StringNode)
	if !ok {
		return errors.New("printf needs its format written in the template")
	}
	if printfSize.MatchString(format.Text) {
		return errors.New("printf width and precision may be at most 3 digits")
	}
	return nil
}

func boundArg(n parse.Node) error {
	switch n := n.(type) {
	case *parse.PipeNode:
		return boundPipe(n, false)
	case *parse.ChainNode:
		return boundArg(n.Node)
	}
	return nil
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
	ctx, cancel := context.WithTimeout(context.Background(), maxCheckTime)
	defer cancel()
	for _, s := range a.Actions {
		tx, ok := s.Impl.(texted)
		if !ok {
			continue
		}
		for _, x := range tx.texts() {
			for _, tr := range a.Triggers {
				ev := Event{TriggerID: tr.ID, TriggerType: tr.Type, Data: tr.Impl.Sample()}
				if _, err := x.Render(ctx, ev); err != nil {
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
