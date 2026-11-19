// SPDX-License-Identifier: AGPL-3.0-only

package automation

import (
	"errors"
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/gvart/hearth/internal/policy"
)

// The step types of a runbook.
const (
	RunbookStepAction = "action"
	RunbookStepCheck  = "check"
	RunbookStepPrompt = "prompt"
	RunbookStepWait   = "wait"
)

// The kinds of prompt.
const (
	PromptInput   = "input"
	PromptConfirm = "confirm"
)

// The answers a confirm prompt takes.
const (
	ConfirmYes = "yes"
	ConfirmNo  = "no"
)

const (
	// maxRunbookFile bounds a runbook file: a copy of it is replicated with
	// every run.
	maxRunbookFile = 64 << 10
	// maxRunbookSteps bounds a runbook, whose state is rewritten at every step.
	maxRunbookSteps = 100
	// defaultPromptTimeout is how long a prompt waits for its answer unless
	// it says otherwise.
	defaultPromptTimeout = time.Hour
	// maxPromptTimeout is the longest a prompt may wait.
	maxPromptTimeout = 7 * 24 * time.Hour
	// maxRunbookWait is the longest a wait step may last.
	maxRunbookWait = 24 * time.Hour
	// defaultCheckRetry is how often a check that has not passed is repeated.
	defaultCheckRetry = 5 * time.Second
	// maxCheckWithin is the longest a check step may keep trying.
	maxCheckWithin = time.Hour
)

// Runbook is a loaded, valid runbook.
type Runbook struct {
	ID          string
	Description string
	Steps       []RunbookStep
	// File is the file it was loaded from.
	File string
	// source is the file's content: a run keeps it, sealed, and goes on with
	// the definition it started from whatever happens to the file.
	source []byte
}

// RunbookStep is one step of a runbook.
type RunbookStep struct {
	ID          string
	Type        string
	Description string
	Line        int
	// Action is what an action step does.
	Action *Step[Action]
	// Rollback undoes an action step.
	Rollback *Step[Action]
	// Check is what a check step checks, from the hub. Within is how long it
	// keeps trying, Every how often.
	Check  *checkTrigger
	Within time.Duration
	Every  time.Duration
	// Prompt is what a prompt step asks.
	Prompt *RunbookPrompt
	// Wait is how long a wait step lasts.
	Wait time.Duration
	// needs and rollbackNeeds are the secret prompts the action and its
	// rollback use: answers that only this hub's memory holds.
	needs, rollbackNeeds []string
}

// RunbookPrompt is what a prompt step asks an operator.
type RunbookPrompt struct {
	Kind    string
	Message string
	// Secret answers are never stored, logged or shown.
	Secret  bool
	Timeout time.Duration
}

// What says what the step does, for plans and run logs.
func (s *RunbookStep) What() string {
	switch s.Type {
	case RunbookStepAction:
		return s.Action.Impl.Describe()
	case RunbookStepCheck:
		if s.Within > 0 {
			return fmt.Sprintf("check %s, for up to %s", s.Check.what, s.Within)
		}
		return "check " + s.Check.what
	case RunbookStepPrompt:
		return s.Prompt.Message
	default:
		return "wait " + s.Wait.String()
	}
}

// inputScope says which prompt answers an action may use in its templates.
// Answers are data: they may fill in the text an action sends, and never what
// it acts on (a device, a cluster, an object) or which command it runs. A
// secret may only go where it is sent on, in a webhook's body or headers: a
// log line would store it, and so would a notification.
func inputScope(a Action) (data, secret bool) {
	switch a.(type) {
	case *webhookAction:
		return true, true
	case *logAction, *notifyAction:
		return true, false
	}
	return false, false
}

// inputFor is what the action a may see of the answers: nil, so that a
// template naming .Input fails, if it may see none.
func inputFor(a Action, plain, secrets map[string]string) map[string]string {
	data, secret := inputScope(a)
	if !data {
		return nil
	}
	out := make(map[string]string, len(plain)+len(secrets))
	for k, v := range plain {
		out[k] = v
	}
	if secret {
		for k, v := range secrets {
			out[k] = v
		}
	}
	return out
}

// LoadRunbookFile reads and validates one runbook file.
func LoadRunbookFile(path string, kinds Kinds) (*Runbook, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("load runbook: %w", err)
	}
	return ParseRunbook(path, b, kinds)
}

// LoadRunbooks loads every *.yaml and *.yml file in dir, not its
// subdirectories. A missing dir has no runbooks. A file that is invalid, or
// reuses another's id, is left out and its problem returned: the others stay
// usable.
func LoadRunbooks(dir string, kinds Kinds) ([]*Runbook, []error) {
	files, err := automationFiles(dir)
	if err != nil {
		return nil, []error{err}
	}
	var (
		out  []*Runbook
		errs []error
		ids  = map[string]string{}
	)
	for _, f := range files {
		rb, err := LoadRunbookFile(f, kinds)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if prev, ok := ids[rb.ID]; ok {
			errs = append(errs, fmt.Errorf("%s: runbook id %q is already used by %s", f, rb.ID, prev))
			continue
		}
		ids[rb.ID] = f
		out = append(out, rb)
	}
	return out, errs
}

// ParseRunbook validates the runbook in b, read from file name.
func ParseRunbook(name string, b []byte, kinds Kinds) (*Runbook, error) {
	fail := func(err error) (*Runbook, error) { return nil, &LoadError{File: name, Errs: []error{err}} }
	if len(b) > maxRunbookFile {
		return fail(fmt.Errorf("a runbook file may be at most %d bytes", maxRunbookFile))
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return fail(err)
	}
	if len(doc.Content) == 0 {
		return fail(errors.New("empty file"))
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return fail(lineError(root.Line, "a runbook must be a mapping"))
	}
	rb := &Runbook{File: name, source: b}
	var errs []error
	checkDuplicateKeys(root, &errs)
	idLine := root.Line
	for i := 0; i+1 < len(root.Content); i += 2 {
		k, v := root.Content[i], root.Content[i+1]
		switch k.Value {
		case "id":
			rb.ID, idLine = scalar(v, "id", &errs), v.Line
		case "description":
			rb.Description = scalar(v, "description", &errs)
		case "steps":
			rb.Steps = parseRunbookSteps(v, kinds, &errs)
		default:
			errs = append(errs, lineError(k.Line, "unknown field %q", k.Value))
		}
	}
	if !idPattern.MatchString(rb.ID) {
		errs = append(errs, lineError(idLine,
			"id %q must be 1 to 64 lowercase letters, digits, - or _, starting with a letter or digit", rb.ID))
	}
	if len(rb.Steps) == 0 {
		errs = append(errs, lineError(root.Line, "a runbook needs at least one step"))
	}
	if len(rb.Steps) > maxRunbookSteps {
		errs = append(errs, lineError(root.Line, "a runbook may have at most %d steps", maxRunbookSteps))
	}
	seen := map[string]int{}
	for _, s := range rb.Steps {
		if !idPattern.MatchString(s.ID) {
			errs = append(errs, lineError(s.Line, "step id %q must be 1 to 64 lowercase letters, digits, - or _", s.ID))
		} else if prev, ok := seen[s.ID]; ok {
			errs = append(errs, lineError(s.Line, "step id %q is already used on line %d", s.ID, prev))
		}
		seen[s.ID] = s.Line
	}
	checkRunbookTemplates(rb, &errs)
	if len(errs) > 0 {
		return nil, &LoadError{File: name, Errs: errs}
	}
	return rb, nil
}

// runbookStepFields are the fields a step type may have, besides id, type and
// description; ok is false for an unknown type.
func runbookStepFields(stepType string) (fields []string, ok bool) {
	switch stepType {
	case RunbookStepAction:
		return []string{"action", "rollback"}, true
	case RunbookStepCheck:
		return []string{"check", "within", "every"}, true
	case RunbookStepPrompt:
		return []string{"prompt", "message", "secret", "timeout"}, true
	case RunbookStepWait:
		return []string{"duration"}, true
	}
	return nil, false
}

func parseRunbookSteps(n *yaml.Node, kinds Kinds, errs *[]error) []RunbookStep {
	if n.Kind != yaml.SequenceNode {
		*errs = append(*errs, lineError(n.Line, "steps must be a list"))
		return nil
	}
	var out []RunbookStep
	for i, item := range n.Content {
		if item.Kind != yaml.MappingNode {
			*errs = append(*errs, lineError(item.Line, "a step must be a mapping"))
			continue
		}
		if checkDuplicateKeys(item, errs) {
			continue
		}
		s := RunbookStep{Line: item.Line}
		fields := map[string]*yaml.Node{}
		for j := 0; j+1 < len(item.Content); j += 2 {
			k, v := item.Content[j], item.Content[j+1]
			switch k.Value {
			case "id":
				s.ID = scalar(v, "id", errs)
			case "type":
				s.Type = scalar(v, "type", errs)
			case "description":
				s.Description = scalar(v, "description", errs)
			default:
				fields[k.Value] = k
			}
		}
		allowed, ok := runbookStepFields(s.Type)
		if !ok {
			*errs = append(*errs, lineError(item.Line, "step type %q must be action, check, prompt or wait", s.Type))
			continue
		}
		for name, k := range fields {
			if !slices.Contains(allowed, name) {
				*errs = append(*errs, lineError(k.Line, "a %s step has no field %q", s.Type, name))
			}
		}
		if s.ID == "" {
			s.ID = fmt.Sprintf("%s-%d", s.Type, i+1)
		}
		value := func(key string) *yaml.Node {
			for j := 0; j+1 < len(item.Content); j += 2 {
				if item.Content[j].Value == key {
					return item.Content[j+1]
				}
			}
			return nil
		}
		parseRunbookStep(&s, value, kinds, errs)
		out = append(out, s)
	}
	return out
}

// parseRunbookStep fills in the fields of s's type.
func parseRunbookStep(s *RunbookStep, value func(string) *yaml.Node, kinds Kinds, errs *[]error) {
	duration := func(key string) time.Duration {
		n := value(key)
		if n == nil {
			return 0
		}
		var d time.Duration
		if err := n.Decode(&d); err != nil {
			*errs = append(*errs, lineError(n.Line, "%s must be a duration, such as 30s", key))
		}
		return d
	}
	switch s.Type {
	case RunbookStepAction:
		s.Action = parseRunbookAction(value("action"), s, "action", kinds, errs)
		if n := value("rollback"); n != nil {
			s.Rollback = parseRunbookAction(n, s, "rollback", kinds, errs)
		}
	case RunbookStepCheck:
		s.Check = parseRunbookCheck(value("check"), s, errs)
		s.Within, s.Every = duration("within"), duration("every")
		if s.Every == 0 {
			s.Every = defaultCheckRetry
		}
		if s.Within < 0 || s.Within > maxCheckWithin {
			*errs = append(*errs, lineError(s.Line, "within must be between 0 and %s", maxCheckWithin))
		}
		if s.Every < minEvery {
			*errs = append(*errs, lineError(s.Line, "every must be at least %s", minEvery))
		}
	case RunbookStepPrompt:
		p := &RunbookPrompt{Kind: PromptInput, Timeout: duration("timeout")}
		if n := value("prompt"); n != nil {
			p.Kind = scalar(n, "prompt", errs)
		}
		if n := value("message"); n != nil {
			p.Message = scalar(n, "message", errs)
		}
		if n := value("secret"); n != nil {
			if err := n.Decode(&p.Secret); err != nil {
				*errs = append(*errs, lineError(n.Line, "secret must be true or false"))
			}
		}
		switch {
		case p.Kind != PromptInput && p.Kind != PromptConfirm:
			*errs = append(*errs, lineError(s.Line, "prompt %q must be input or confirm", p.Kind))
		case p.Kind == PromptConfirm && p.Secret:
			*errs = append(*errs, lineError(s.Line, "a confirm prompt cannot be secret"))
		}
		if p.Message == "" {
			*errs = append(*errs, lineError(s.Line, "a prompt needs a message"))
		}
		if p.Timeout == 0 {
			p.Timeout = defaultPromptTimeout
		}
		if p.Timeout < 0 || p.Timeout > maxPromptTimeout {
			*errs = append(*errs, lineError(s.Line, "timeout must be between 0 and %s", maxPromptTimeout))
		}
		s.Prompt = p
	case RunbookStepWait:
		s.Wait = duration("duration")
		if s.Wait <= 0 || s.Wait > maxRunbookWait {
			*errs = append(*errs, lineError(s.Line, "duration must be more than 0 and at most %s", maxRunbookWait))
		}
	}
}

// parseRunbookAction builds the action in n, the same way an automation's
// action is built.
func parseRunbookAction(n *yaml.Node, s *RunbookStep, field string, kinds Kinds, errs *[]error) *Step[Action] {
	if n == nil {
		*errs = append(*errs, lineError(s.Line, "an action step needs %s", field))
		return nil
	}
	if n.Kind != yaml.MappingNode {
		*errs = append(*errs, lineError(n.Line, "%s must be a mapping with the action's type and fields", field))
		return nil
	}
	list := &yaml.Node{Kind: yaml.SequenceNode, Line: n.Line, Content: []*yaml.Node{n}}
	built := buildSteps(list, "action", kinds.Actions, errs)
	if len(built) != 1 {
		return nil
	}
	a := built[0]
	a.ID = s.ID
	if _, ok := policy.ClassOf(a.Impl.Policy()); !ok {
		*errs = append(*errs, lineError(a.Line, "action type %q has no policy class", a.Type))
		return nil
	}
	return &a
}

// parseRunbookCheck builds the check in n from the http, tcp and dns triggers.
func parseRunbookCheck(n *yaml.Node, s *RunbookStep, errs *[]error) *checkTrigger {
	if n == nil {
		*errs = append(*errs, lineError(s.Line, "a check step needs check"))
		return nil
	}
	if n.Kind != yaml.MappingNode {
		*errs = append(*errs, lineError(n.Line, "check must be a mapping with the check's type and fields"))
		return nil
	}
	deps := TriggerDeps{}
	builders := map[string]Builder[Trigger]{
		"http": func(p Params) (Trigger, error) { return buildHTTPCheck(p, deps) },
		"tcp":  func(p Params) (Trigger, error) { return buildTCPCheck(p, deps) },
		"dns":  func(p Params) (Trigger, error) { return buildDNSCheck(p, deps) },
	}
	list := &yaml.Node{Kind: yaml.SequenceNode, Line: n.Line, Content: []*yaml.Node{n}}
	built := buildSteps(list, "check", builders, errs)
	if len(built) != 1 {
		return nil
	}
	c, ok := built[0].Impl.(*checkTrigger)
	if !ok {
		return nil
	}
	if c.from != "" {
		*errs = append(*errs, lineError(n.Line, "a check step runs from the hub: from is not supported"))
		return nil
	}
	return c
}

// checkRunbookTemplates renders every template of a runbook's actions with the
// answers of the prompts before it, each action seeing only what inputScope
// allows, so that a template using an answer it may not have fails the load
// at its line. It also notes which secret answers each action needs.
func checkRunbookTemplates(rb *Runbook, errs *[]error) {
	plain, secrets, every := map[string]string{}, map[string]string{}, map[string]string{}
	for i := range rb.Steps {
		if rb.Steps[i].Type == RunbookStepPrompt {
			every[rb.Steps[i].ID] = "sample"
		}
	}
	check := func(a *Step[Action]) []string {
		if a == nil {
			return nil
		}
		tx, ok := a.Impl.(texted)
		if !ok {
			return nil
		}
		ev := runbookEvent(rb.ID, time.Time{}, inputFor(a.Impl, plain, secrets))
		failed := false
		for _, x := range tx.texts() {
			if _, err := x.Render(ev); err != nil {
				failed = true
				*errs = append(*errs, lineError(x.line, "step %s: %s", a.ID, runbookTemplateErr(a.Impl, err)))
			}
		}
		data, secret := inputScope(a.Impl)
		if failed || !data {
			return nil
		}
		// index gives "" for an answer it cannot see, without an error: what
		// a template reads shows in whether its output follows the answer.
		var needs []string
		for _, id := range slices.Sorted(maps.Keys(every)) {
			if !followsAnswer(rb.ID, tx.texts(), every, id) {
				continue
			}
			_, isPlain := plain[id]
			_, isSecret := secrets[id]
			line := tx.texts()[0].line
			switch {
			case !isPlain && !isSecret:
				*errs = append(*errs, lineError(line, "step %s: answer %s must come from an earlier prompt", a.ID, id))
			case isSecret && !secret:
				*errs = append(*errs, lineError(line,
					"step %s: secret answer %s can only be used in a webhook's body or headers", a.ID, id))
			case isSecret:
				needs = append(needs, id)
			}
		}
		return needs
	}
	for i := range rb.Steps {
		s := &rb.Steps[i]
		switch s.Type {
		case RunbookStepAction:
			s.needs, s.rollbackNeeds = check(s.Action), check(s.Rollback)
		case RunbookStepPrompt:
			if s.Prompt.Secret {
				secrets[s.ID] = "sample"
			} else {
				plain[s.ID] = ConfirmYes
			}
		}
	}
}

// followsAnswer reports whether what texts render to depends on the answer id,
// given answers to every prompt.
func followsAnswer(runbookID string, texts []Text, answers map[string]string, id string) bool {
	render := func(input map[string]string) (string, bool) {
		ev := runbookEvent(runbookID, time.Time{}, input)
		var b strings.Builder
		for _, x := range texts {
			s, err := x.Render(ev)
			if err != nil {
				return "", false
			}
			b.WriteString(s)
			b.WriteByte(0)
		}
		return b.String(), true
	}
	with := func(value string) map[string]string {
		input := maps.Clone(answers)
		input[id] = value
		return input
	}
	without := maps.Clone(answers)
	delete(without, id)
	first, _ := render(with("first-sample"))
	second, _ := render(with("the-second-sample"))
	absent, ok := render(without)
	return first != second || !ok || first != absent
}

// runbookTemplateErr says why an action's template cannot use .Input.
func runbookTemplateErr(a Action, err error) string {
	if !strings.Contains(err.Error(), ".Input") {
		return err.Error()
	}
	switch data, secret := inputScope(a); {
	case !data:
		return fmt.Sprintf("%v (prompt answers are data: this action's fields cannot use them)", err)
	case !secret:
		return fmt.Sprintf("%v (a prompt answer must come from an earlier prompt; a secret one can only be used in a webhook's body or headers)", err)
	}
	return fmt.Sprintf("%v (a prompt answer must come from an earlier prompt)", err)
}

// runbookEvent is what a step's templates see: .Input, and .Trigger as a manual
// start at the time the run started.
func runbookEvent(runbookID string, at time.Time, input map[string]string) Event {
	return Event{TriggerID: runbookID, TriggerType: "runbook", At: at, Data: map[string]any{}, Input: input}
}
