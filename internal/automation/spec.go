// SPDX-License-Identifier: AGPL-3.0-only

package automation

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/gvart/hearth/internal/policy"
)

// Mode says what a trigger does while a run of its automation is in progress.
type Mode string

// Concurrency modes.
const (
	// ModeSingle ignores the trigger: the run in progress finishes alone.
	ModeSingle Mode = "single"
	// ModeQueued runs it after the runs before it, up to MaxQueued waiting.
	ModeQueued Mode = "queued"
	// ModeRestart cancels the run in progress and starts a new one.
	ModeRestart Mode = "restart"
)

// MaxQueued is how many runs a queued automation keeps waiting; a trigger
// beyond that is dropped.
const MaxQueued = 10

// Event is one firing of a trigger.
type Event struct {
	// TriggerID is the id of the trigger that fired.
	TriggerID string
	// TriggerType is its type: device, metric, http ...
	TriggerType string
	At          time.Time
	// Data is what the trigger tells about this firing, by field name:
	// Device, Value, Error ... Action templates see it, with ID, Type and
	// At, as .Trigger.
	Data map[string]any
}

// FireFunc starts a run with the data of one firing; data has the same keys
// as the trigger's Sample.
type FireFunc func(data map[string]any)

// Trigger starts runs of its automation.
type Trigger interface {
	// Describe says when the trigger fires, for a dry run.
	Describe() string
	// Watch calls fire every time the trigger fires, until ctx is done.
	Watch(ctx context.Context, fire FireFunc) error
	// Sample is the data every firing carries, with example values: action
	// templates are checked against it when the automation is loaded.
	Sample() map[string]any
}

// Condition decides whether a run goes on to its actions.
type Condition interface {
	// Describe says what the condition checks, for a dry run.
	Describe() string
	Check(ctx context.Context, ev Event) (bool, error)
}

// Action is one step a run takes. The runtime executes it only through
// policy, as Policy() with the automation as the actor.
type Action interface {
	// Describe says what the action would do, for a dry run.
	Describe() string
	// Policy is the action policy decides on. Its class must be declared in
	// internal/policy, or the automation is rejected when loaded.
	Policy() policy.Action
	// Target is what the action acts on, for the audit log ("" if nothing).
	// The runtime renders it for each run.
	Target() Text
	Run(ctx context.Context, ev Event) error
}

// Step is a trigger, condition or action as written in a file.
type Step[T any] struct {
	ID          string
	Type        string
	Description string
	// Line is where the step starts in its file.
	Line int
	Impl T
}

// Automation is a loaded, valid automation.
type Automation struct {
	ID          string
	Description string
	Mode        Mode
	Triggers    []Step[Trigger]
	Conditions  []Step[Condition]
	Actions     []Step[Action]
	// File is the file it was loaded from.
	File string
	// sum identifies the file's content: an automation whose file has not
	// changed keeps running across a reload.
	sum [32]byte
}

// Builder makes a step's implementation from its type-specific fields.
type Builder[T any] func(p Params) (T, error)

// Kinds are the trigger, condition and action types files may use, by type
// name.
type Kinds struct {
	Triggers   map[string]Builder[Trigger]
	Conditions map[string]Builder[Condition]
	Actions    map[string]Builder[Action]
}

// Params are a step's type-specific fields: everything but id, type and
// description.
type Params struct {
	node *yaml.Node
}

// Decode decodes the fields into v, a pointer to a struct with yaml tags. A
// field v has no tag for is an error at that field's line.
func (p Params) Decode(v any) error {
	known := map[string]bool{}
	t := reflect.TypeOf(v).Elem()
	for i := range t.NumField() {
		name, _, _ := strings.Cut(t.Field(i).Tag.Get("yaml"), ",")
		if name == "" {
			name = strings.ToLower(t.Field(i).Name)
		}
		known[name] = true
	}
	for i := 0; i+1 < len(p.node.Content); i += 2 {
		if k := p.node.Content[i]; !known[k.Value] {
			return lineError(k.Line, "unknown field %q", k.Value)
		}
	}
	return p.node.Decode(v)
}

// lineErr is an error at a line of the file being loaded.
type lineErr struct {
	line int
	msg  string
}

func (e *lineErr) Error() string { return fmt.Sprintf("line %d: %s", e.line, e.msg) }

func lineError(line int, format string, args ...any) error {
	return &lineErr{line: line, msg: fmt.Sprintf(format, args...)}
}
