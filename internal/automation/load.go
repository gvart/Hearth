// SPDX-License-Identifier: AGPL-3.0-only

package automation

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/gvart/hearth/internal/policy"
)

// LoadError lists everything wrong with one automation file.
type LoadError struct {
	File string
	Errs []error
}

func (e *LoadError) Error() string {
	lines := make([]string, len(e.Errs))
	for i, err := range e.Errs {
		var le *lineErr
		if errors.As(err, &le) {
			lines[i] = fmt.Sprintf("%s:%d: %s", e.File, le.line, le.msg)
		} else {
			lines[i] = fmt.Sprintf("%s: %v", e.File, err)
		}
	}
	return strings.Join(lines, "\n")
}

// idPattern is what automation and step ids look like: they name the actor
// in the audit log and appear in run history.
var idPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

// LoadFile reads and validates one automation file.
func LoadFile(path string, kinds Kinds) (*Automation, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("load automation: %w", err)
	}
	return Parse(path, b, kinds)
}

// LoadDir loads every *.yaml and *.yml file in dir, not its subdirectories.
// A missing dir has no automations. Any invalid file, or two files with the
// same automation id, fails the whole load, with every problem listed.
func LoadDir(dir string, kinds Kinds) ([]*Automation, error) {
	files, err := automationFiles(dir)
	if err != nil {
		return nil, err
	}
	var (
		out  []*Automation
		errs []error
		ids  = map[string]string{}
	)
	for _, f := range files {
		a, err := LoadFile(f, kinds)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if prev, ok := ids[a.ID]; ok {
			errs = append(errs, fmt.Errorf("%s: automation id %q is already used by %s", f, a.ID, prev))
			continue
		}
		ids[a.ID] = f
		out = append(out, a)
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return out, nil
}

// DirDigest returns a SHA-256 digest, in hex, of the automation files in dir:
// their names and contents, so it does not depend on where dir is or on file
// times. A missing directory digests like an empty one.
func DirDigest(dir string) (string, error) {
	files, err := automationFiles(dir)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			return "", fmt.Errorf("read automation file: %w", err)
		}
		_, _ = fmt.Fprintf(h, "%s\x00%d\x00", filepath.Base(f), len(b))
		_, _ = h.Write(b)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Files lists the automation files the hub loads from dir, sorted. A missing
// directory has none.
func Files(dir string) ([]string, error) { return automationFiles(dir) }

// automationFiles lists the automation files in dir, sorted.
func automationFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read automations dir: %w", err)
	}
	var out []string
	for _, e := range entries {
		name := e.Name()
		ext := filepath.Ext(name)
		if e.IsDir() || strings.HasPrefix(name, ".") || (ext != ".yaml" && ext != ".yml") {
			continue
		}
		out = append(out, filepath.Join(dir, name))
	}
	slices.Sort(out)
	return out, nil
}

// Parse validates the automation in b, read from file name.
func Parse(name string, b []byte, kinds Kinds) (*Automation, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(b, &doc); err != nil {
		// yaml's own errors carry their line ("yaml: line 3: ...").
		return nil, &LoadError{File: name, Errs: []error{err}}
	}
	if len(doc.Content) == 0 {
		return nil, &LoadError{File: name, Errs: []error{errors.New("empty file")}}
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return nil, &LoadError{File: name, Errs: []error{lineError(root.Line, "an automation must be a mapping")}}
	}
	a := &Automation{File: name, Mode: ModeSingle, sum: sha256.Sum256(b)}
	var errs []error
	checkDuplicateKeys(root, &errs)
	idLine, modeLine := root.Line, root.Line
	for i := 0; i+1 < len(root.Content); i += 2 {
		k, v := root.Content[i], root.Content[i+1]
		switch k.Value {
		case "id":
			a.ID, idLine = scalar(v, "id", &errs), v.Line
		case "description":
			a.Description = scalar(v, "description", &errs)
		case "mode":
			a.Mode, modeLine = Mode(scalar(v, "mode", &errs)), v.Line
		case "triggers":
			a.Triggers = buildSteps(v, "trigger", kinds.Triggers, &errs)
		case "conditions":
			a.Conditions = buildSteps(v, "condition", kinds.Conditions, &errs)
		case "actions":
			a.Actions = buildSteps(v, "action", kinds.Actions, &errs)
		default:
			errs = append(errs, lineError(k.Line, "unknown field %q", k.Value))
		}
	}
	if !idPattern.MatchString(a.ID) {
		errs = append(errs, lineError(idLine,
			"id %q must be 1 to 64 lowercase letters, digits, - or _, starting with a letter or digit", a.ID))
	}
	switch a.Mode {
	case ModeSingle, ModeQueued, ModeRestart:
	default:
		errs = append(errs, lineError(modeLine, "mode %q must be single, queued or restart", a.Mode))
	}
	if len(a.Triggers) == 0 {
		errs = append(errs, lineError(root.Line, "an automation needs at least one trigger"))
	}
	if len(a.Actions) == 0 {
		errs = append(errs, lineError(root.Line, "an automation needs at least one action"))
	}
	for _, s := range a.Actions {
		if _, ok := policy.ClassOf(s.Impl.Policy()); !ok {
			errs = append(errs, lineError(s.Line, "action type %q has no policy class", s.Type))
		}
	}
	checkStepIDs(a, &errs)
	checkTemplates(a, &errs)
	if len(errs) > 0 {
		return nil, &LoadError{File: name, Errs: errs}
	}
	return a, nil
}

// ParseForSave validates a new version of a file, written through the web UI.
// It is stricter than Parse, which must keep loading the files a hub already
// runs: it also refuses named templates, templates over the render limits and
// more than MaxSaveSteps steps.
func ParseForSave(name string, b []byte, kinds Kinds) (*Automation, error) {
	a, err := Parse(name, b, kinds)
	if err != nil {
		return nil, err
	}
	var errs []error
	for _, p := range slices.Concat(a.named, a.Warnings) {
		errs = append(errs, lineError(p.Line, "%s", p.Message))
	}
	if n := len(a.Triggers) + len(a.Conditions) + len(a.Actions); n > MaxSaveSteps {
		errs = append(errs, fmt.Errorf("an automation may have at most %d steps, this one has %d", MaxSaveSteps, n))
	}
	if len(errs) > 0 {
		return nil, &LoadError{File: name, Errs: errs}
	}
	return a, nil
}

// MaxSaveSteps bounds the steps of a file ParseForSave accepts: every action
// of a dry run adds a row to the audit log.
const MaxSaveSteps = 64

// checkStepIDs requires every step id to be well formed and unique in its
// automation.
func checkStepIDs(a *Automation, errs *[]error) {
	type ref struct {
		id   string
		line int
	}
	var refs []ref
	for _, s := range a.Triggers {
		refs = append(refs, ref{s.ID, s.Line})
	}
	for _, s := range a.Conditions {
		refs = append(refs, ref{s.ID, s.Line})
	}
	for _, s := range a.Actions {
		refs = append(refs, ref{s.ID, s.Line})
	}
	seen := map[string]int{}
	for _, r := range refs {
		if !idPattern.MatchString(r.id) {
			*errs = append(*errs, lineError(r.line, "step id %q must be 1 to 64 lowercase letters, digits, - or _", r.id))
		} else if prev, ok := seen[r.id]; ok {
			*errs = append(*errs, lineError(r.line, "step id %q is already used on line %d", r.id, prev))
		}
		seen[r.id] = r.line
	}
}

// buildSteps builds the steps of one section from a YAML list.
func buildSteps[T any](n *yaml.Node, kind string, builders map[string]Builder[T], errs *[]error) []Step[T] {
	if n.Kind != yaml.SequenceNode {
		*errs = append(*errs, lineError(n.Line, "%ss must be a list", kind))
		return nil
	}
	var out []Step[T]
	for i, item := range n.Content {
		if item.Kind != yaml.MappingNode {
			*errs = append(*errs, lineError(item.Line, "a %s must be a mapping", kind))
			continue
		}
		if checkDuplicateKeys(item, errs) {
			continue
		}
		s := Step[T]{Line: item.Line}
		params := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map", Line: item.Line, Column: item.Column}
		typeLine := item.Line
		for j := 0; j+1 < len(item.Content); j += 2 {
			k, v := item.Content[j], item.Content[j+1]
			switch k.Value {
			case "id":
				s.ID = scalar(v, "id", errs)
			case "type":
				s.Type, typeLine = scalar(v, "type", errs), v.Line
			case "description":
				s.Description = scalar(v, "description", errs)
			default:
				params.Content = append(params.Content, k, v)
			}
		}
		if s.Type == "" {
			*errs = append(*errs, lineError(item.Line, "%s type is required", kind))
			continue
		}
		build, ok := builders[s.Type]
		if !ok {
			*errs = append(*errs, lineError(typeLine, "unknown %s type %q", kind, s.Type))
			continue
		}
		if s.ID == "" {
			s.ID = fmt.Sprintf("%s-%d", s.Type, i+1)
		}
		impl, err := build(Params{node: params})
		if err != nil {
			var le *lineErr
			if !errors.As(err, &le) {
				err = lineError(item.Line, "%s %s: %v", kind, s.ID, err)
			}
			*errs = append(*errs, err)
			continue
		}
		s.Impl = impl
		out = append(out, s)
	}
	return out
}

// checkDuplicateKeys records an error for every key of mapping m that
// repeats an earlier one, which YAML forbids, and reports whether there was
// any.
func checkDuplicateKeys(m *yaml.Node, errs *[]error) bool {
	seen := map[string]int{}
	found := false
	for i := 0; i+1 < len(m.Content); i += 2 {
		k := m.Content[i]
		if prev, ok := seen[k.Value]; ok {
			*errs = append(*errs, lineError(k.Line, "field %q is already set on line %d", k.Value, prev))
			found = true
			continue
		}
		seen[k.Value] = k.Line
	}
	return found
}

// scalar returns n's value, or records an error if n is not a scalar.
func scalar(n *yaml.Node, field string, errs *[]error) string {
	if n.Kind != yaml.ScalarNode {
		*errs = append(*errs, lineError(n.Line, "%s must be a string", field))
		return ""
	}
	return n.Value
}
