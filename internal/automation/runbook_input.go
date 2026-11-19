// SPDX-License-Identifier: AGPL-3.0-only

package automation

import (
	"slices"
	"text/template/parse"
)

// inputUse is what a template does with prompt answers, read from its parse
// tree. Rendering cannot tell: index gives "" for an absent answer without an
// error, and a comparison or a branch not taken shows nothing of what it read.
type inputUse struct {
	// reads is set when the template may read .Input in any form. Handing the
	// whole data on counts, since .Input can be reached from it.
	reads bool
	// ids are the answers it names literally.
	ids []string
}

// inputUse walks the field's templates, those it defines included.
func (x Text) inputUse() inputUse {
	var u inputUse
	if x.t == nil {
		return u
	}
	for _, t := range x.t.Templates() {
		if t.Tree != nil {
			u.walk(t.Root)
		}
	}
	return u
}

func (u *inputUse) walk(node parse.Node) {
	switch n := node.(type) {
	case *parse.ListNode:
		if n != nil {
			for _, c := range n.Nodes {
				u.walk(c)
			}
		}
	case *parse.ActionNode:
		u.walk(n.Pipe)
	case *parse.IfNode:
		u.walkBranch(&n.BranchNode)
	case *parse.RangeNode:
		u.walkBranch(&n.BranchNode)
	case *parse.WithNode:
		u.walkBranch(&n.BranchNode)
	case *parse.TemplateNode:
		u.walk(n.Pipe)
	case *parse.PipeNode:
		if n != nil {
			u.walkPipe(n)
		}
	case *parse.CommandNode:
		for _, a := range n.Args {
			u.walk(a)
		}
	case *parse.ChainNode:
		u.walk(n.Node)
		u.reads = u.reads || slices.Contains(n.Field, "Input")
	case *parse.DotNode:
		u.reads = true
	case *parse.FieldNode:
		u.walkIdent(n.Ident)
	case *parse.VariableNode:
		// A bare variable may hold the whole data: {{ $d := . }} or $.
		u.reads = u.reads || len(n.Ident) == 1
		u.walkIdent(n.Ident[1:])
	}
}

func (u *inputUse) walkBranch(b *parse.BranchNode) {
	u.walk(b.Pipe)
	u.walk(b.List)
	u.walk(b.ElseList)
}

// walkPipe also notes the ids named by index .Input "id" and "id" | index .Input.
func (u *inputUse) walkPipe(p *parse.PipeNode) {
	for i, cmd := range p.Cmds {
		u.walk(cmd)
		if len(cmd.Args) < 2 || !isIndex(cmd.Args[0]) || !isInput(cmd.Args[1]) {
			continue
		}
		switch {
		case len(cmd.Args) > 2:
			if s, ok := cmd.Args[2].(*parse.StringNode); ok {
				u.ids = append(u.ids, s.Text)
			}
		case i > 0 && len(p.Cmds[i-1].Args) == 1:
			if s, ok := p.Cmds[i-1].Args[0].(*parse.StringNode); ok {
				u.ids = append(u.ids, s.Text)
			}
		}
	}
}

// walkIdent notes a chain of field names, as in .Input.id.
func (u *inputUse) walkIdent(ident []string) {
	if i := slices.Index(ident, "Input"); i >= 0 {
		u.reads = true
		if i == 0 && len(ident) > 1 {
			u.ids = append(u.ids, ident[1])
		}
	}
}

func isIndex(n parse.Node) bool {
	id, ok := n.(*parse.IdentifierNode)
	return ok && id.Ident == "index"
}

// isInput reports whether n is .Input, $.Input or either in parentheses.
func isInput(n parse.Node) bool {
	switch n := n.(type) {
	case *parse.FieldNode:
		return slices.Equal(n.Ident, []string{"Input"})
	case *parse.VariableNode:
		return slices.Equal(n.Ident, []string{"$", "Input"})
	case *parse.PipeNode:
		return len(n.Decl) == 0 && len(n.Cmds) == 1 && len(n.Cmds[0].Args) == 1 && isInput(n.Cmds[0].Args[0])
	}
	return false
}
