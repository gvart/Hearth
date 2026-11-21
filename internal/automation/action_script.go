// SPDX-License-Identifier: AGPL-3.0-only

package automation

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"math"
	"slices"
	"strings"
	"time"

	"github.com/canonical/starlark/resolve"
	"github.com/canonical/starlark/starlark"
	"github.com/canonical/starlark/syntax"
	"go.yaml.in/yaml/v3"

	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

// Script limits. A script's own timeout, max_steps and max_memory_mib may
// only lower the ceilings, which hold for the whole hub.
const (
	defaultScriptTimeout = 10 * time.Second
	maxScriptTimeout     = time.Minute
	defaultScriptSteps   = 1_000_000
	maxScriptSteps       = 100_000_000
	// The memory limits are in MiB of allocations over the whole run, as
	// Starlark estimates them: memory freed along the way still counts.
	defaultScriptMemoryMiB = 16
	maxScriptMemoryMiB     = 256
	// maxScriptSource bounds a script's source.
	maxScriptSource = 64 << 10
	// maxScriptCalls bounds the device reads and actions of one run: each is
	// a policy decision and an audit entry.
	maxScriptCalls = 100
)

var (
	// errScriptSteps is a script stopped at its max_steps.
	errScriptSteps = errors.New("script reached its step limit")
	// errScriptTimeout is a script stopped at its timeout.
	errScriptTimeout = errors.New("script reached its time limit")
	// errScriptMemory is a script stopped at its max_memory_mib.
	errScriptMemory = errors.New("script reached its memory limit")
)

// scriptSafety is what every function a script calls must declare: bounded
// CPU and memory, respect for cancellation, and no access to the host. The
// script's own builtins reach the hub only through policy, at most
// maxScriptCalls times a run.
const scriptSafety = starlark.CPUSafe | starlark.MemSafe | starlark.TimeSafe | starlark.IOSafe

// DeviceLister lists the hub's devices for scripts: store.Devices.
type DeviceLister interface {
	List(ctx context.Context) ([]store.Device, error)
}

// ScriptDeps are what the script action reads devices from. Zero values are
// enough to load and plan automations.
type ScriptDeps struct {
	// Devices nil fails devices() and device() when a script calls them.
	Devices DeviceLister
}

// Script returns the script action type: a Starlark script run on the hub.
// The script reaches the hub only through device reads and the action types
// of its file, each decided by policy and audited, as the automation. It has
// no file, network, exec or environment access of its own. Register it only
// for automations, not runbooks.
func Script(d ScriptDeps) Builder[Action] {
	return func(p Params) (Action, error) { return buildScript(p, d) }
}

// starlarkAction runs a compiled Starlark program.
type starlarkAction struct {
	deps     ScriptDeps
	prog     *starlark.Program
	lines    int
	timeout  time.Duration
	maxSteps int64
	// maxAllocs is in bytes.
	maxAllocs int64
	// actions are the types the script may call: the file's, but script.
	actions map[string]Builder[Action]
}

// scriptFileOptions are the Starlark dialect scripts are written in.
var scriptFileOptions = &syntax.FileOptions{Set: true, While: true, TopLevelControl: true, GlobalReassign: true}

// scriptGlobals are the names a script gets beyond Starlark's universe.
var scriptGlobals = []string{"trigger", "action", "devices", "device", "print"}

func buildScript(p Params, d ScriptDeps) (Action, error) {
	var cfg struct {
		Source   string        `yaml:"source"`
		Timeout  time.Duration `yaml:"timeout"`
		MaxSteps int64         `yaml:"max_steps"`
		MaxMemMB int64         `yaml:"max_memory_mib"`
	}
	if err := p.Decode(&cfg); err != nil {
		return nil, err
	}
	if strings.TrimSpace(cfg.Source) == "" {
		return nil, errors.New("source is required: the Starlark script")
	}
	if len(cfg.Source) > maxScriptSource {
		return nil, fmt.Errorf("source is longer than %d KiB", maxScriptSource>>10)
	}
	switch {
	case cfg.Timeout == 0:
		cfg.Timeout = defaultScriptTimeout
	case cfg.Timeout < 0 || cfg.Timeout > maxScriptTimeout:
		return nil, fmt.Errorf("timeout must be between 0 and %s", maxScriptTimeout)
	}
	switch {
	case cfg.MaxSteps == 0:
		cfg.MaxSteps = defaultScriptSteps
	case cfg.MaxSteps < 0 || cfg.MaxSteps > maxScriptSteps:
		return nil, fmt.Errorf("max_steps must be between 0 and %d", maxScriptSteps)
	}
	switch {
	case cfg.MaxMemMB == 0:
		cfg.MaxMemMB = defaultScriptMemoryMiB
	case cfg.MaxMemMB < 0 || cfg.MaxMemMB > maxScriptMemoryMiB:
		return nil, fmt.Errorf("max_memory_mib must be between 0 and %d", maxScriptMemoryMiB)
	}
	f, err := scriptFileOptions.Parse("script", cfg.Source, 0)
	if err != nil {
		return nil, scriptLoadErr(p, err)
	}
	for _, st := range f.Stmts {
		if l, ok := st.(*syntax.LoadStmt); ok {
			return nil, scriptLoadErr(p, syntax.Error{Pos: l.Load, Msg: "load is not available in scripts"})
		}
	}
	prog, err := starlark.FileProgram(f, func(name string) bool { return slices.Contains(scriptGlobals, name) })
	if err != nil {
		return nil, scriptLoadErr(p, err)
	}
	actions := maps.Clone(p.actions)
	delete(actions, "script")
	return &starlarkAction{
		deps: d, prog: prog, lines: strings.Count(strings.TrimRight(cfg.Source, "\n"), "\n") + 1,
		timeout: cfg.Timeout, maxSteps: cfg.MaxSteps, maxAllocs: cfg.MaxMemMB << 20, actions: actions,
	}, nil
}

// scriptLoadErr reports a syntax or resolve error at its line in the file.
func scriptLoadErr(p Params, err error) error {
	line := p.line("source")
	for i := 0; i+1 < len(p.node.Content); i += 2 {
		// A block scalar's content starts on the line after its key.
		if v := p.node.Content[i+1]; p.node.Content[i].Value == "source" && v.Style&(yaml.LiteralStyle|yaml.FoldedStyle) != 0 {
			line++
		}
	}
	var se syntax.Error
	if errors.As(err, &se) {
		return lineError(line+int(se.Pos.Line)-1, "source: %s", se.Msg)
	}
	var re resolve.ErrorList
	if errors.As(err, &re) && len(re) > 0 {
		return lineError(line+int(re[0].Pos.Line)-1, "source: %s", re[0].Msg)
	}
	return lineError(line, "source: %v", err)
}

func (a *starlarkAction) Describe() string {
	return fmt.Sprintf("run a script of %d lines (each device read and action it calls is decided by policy when it runs)", a.lines)
}

func (a *starlarkAction) Policy() policy.Action { return policy.AutomationScript }
func (a *starlarkAction) Target() Text          { return Literal("") }

// caller is the policy and request an action was allowed under: a script
// makes its own requests as the same actor.
type caller struct {
	policy Policy
	req    policy.Request
}

type callerKey struct{}

func withCaller(ctx context.Context, c caller) context.Context {
	return context.WithValue(ctx, callerKey{}, c)
}

// Run runs the script once, until it ends or reaches its step, memory or
// time limit. It runs only when policy allowed it as an automation's action.
func (a *starlarkAction) Run(ctx context.Context, ev Event) error {
	c, ok := ctx.Value(callerKey{}).(caller)
	if !ok || c.policy == nil || !policy.Granted(ctx, policy.AutomationScript) {
		return errors.New("script: runs only as an automation's action, through policy")
	}
	parent := ctx
	ctx, cancel := context.WithTimeout(ctx, a.timeout)
	defer cancel()
	thread := &starlark.Thread{Name: "script", Print: func(*starlark.Thread, string) {}}
	thread.RequireSafety(scriptSafety)
	thread.SetMaxSteps(a.maxSteps)
	thread.SetMaxAllocs(a.maxAllocs)
	thread.SetParentContext(ctx) // the thread is cancelled when ctx ends
	defer thread.Cancel("script ended")

	run := &scriptRun{a: a, c: c, ev: ev, ctx: ctx}
	_, err := a.prog.Init(thread, run.globals())
	var stepsErr *starlark.StepsSafetyError
	var allocsErr *starlark.AllocsSafetyError
	switch {
	case err == nil:
		return nil
	case errors.As(err, &stepsErr):
		return fmt.Errorf("%w (max_steps %d): %w", errScriptSteps, a.maxSteps, err)
	case errors.As(err, &allocsErr):
		return fmt.Errorf("%w (max_memory_mib %d): %w", errScriptMemory, a.maxAllocs>>20, err)
	case parent.Err() != nil:
		return fmt.Errorf("script: %w: %w", context.Cause(parent), err)
	case ctx.Err() != nil:
		return fmt.Errorf("%w (timeout %s): %w", errScriptTimeout, a.timeout, err)
	}
	return fmt.Errorf("script: %w", err)
}

// scriptRun is one run of a script: what its builtins act for.
type scriptRun struct {
	a     *starlarkAction
	c     caller
	ev    Event
	ctx   context.Context
	calls int
}

func (r *scriptRun) globals() starlark.StringDict {
	trig := toStarlark(r.ev.templateData()["Trigger"])
	trig.Freeze()
	return starlark.StringDict{
		"trigger": trig,
		"action":  starlark.NewBuiltinWithSafety("action", scriptSafety, r.action),
		"devices": starlark.NewBuiltinWithSafety("devices", scriptSafety, r.devices),
		"device":  starlark.NewBuiltinWithSafety("device", scriptSafety, r.device),
		"print": starlark.NewBuiltinWithSafety("print", scriptSafety, func(*starlark.Thread, *starlark.Builtin, starlark.Tuple, []starlark.Tuple) (starlark.Value, error) {
			return nil, errors.New(`not available in scripts: use action("log", message=...)`)
		}),
	}
}

// do decides on one request of the script, as the automation, and runs fn if
// policy allows it. Policy works on a context the script's limits do not
// cancel, so its audit entry is written, except while it holds the request
// for approval: then the script's limits end the wait.
func (r *scriptRun) do(action policy.Action, target string, detail map[string]any, impl Action,
	fn func(context.Context, Event) error,
) error {
	if r.calls >= maxScriptCalls {
		return fmt.Errorf("a script makes at most %d calls in a run", maxScriptCalls)
	}
	r.calls++
	if err := r.ctx.Err(); err != nil {
		return err
	}
	d := maps.Clone(r.c.req.Detail)
	if d == nil {
		d = map[string]any{}
	}
	maps.Copy(d, detail)
	d["call"] = r.calls
	decideCtx, cancel := context.WithCancel(context.WithoutCancel(r.ctx))
	defer cancel()
	req := policy.Request{
		ActorKind: r.c.req.ActorKind, ActorID: r.c.req.ActorID, Action: action, Target: target, Detail: d,
		OnHold: func(string, time.Time) { context.AfterFunc(r.ctx, cancel) },
	}
	if impl != nil {
		return doAction(decideCtx, r.ctx, r.c.policy, req, impl, r.ev, fn)
	}
	return r.c.policy.Do(decideCtx, req, func(granted context.Context) error {
		return fn(policy.WithGrant(r.ctx, granted), r.ev)
	})
}

// action is action(type, **fields): one action of the file's types, built
// from fields as a step of that type would be, and run through policy.
func (r *scriptRun) action(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var typ string
	if err := starlark.UnpackPositionalArgs(b.Name(), args, nil, 1, &typ); err != nil {
		return nil, err
	}
	build, ok := r.a.actions[typ]
	if !ok {
		return nil, fmt.Errorf("unknown action type %q", typ)
	}
	node := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	for _, kv := range kwargs {
		k := string(kv[0].(starlark.String))
		if k == "id" || k == "type" || k == "description" {
			return nil, fmt.Errorf("%s: field %q is not an action field", typ, k)
		}
		v, err := toYAML(kv[1])
		if err != nil {
			return nil, fmt.Errorf("%s: %s: %w", typ, k, err)
		}
		node.Content = append(node.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: k}, v)
	}
	impl, err := build(Params{node: node})
	if err != nil {
		return nil, fmt.Errorf("%s: %w", typ, err)
	}
	// No field holds a template (toYAML refuses them): the target is as given.
	target := impl.Target().String()
	err = r.do(impl.Policy(), target, map[string]any{"type": typ}, impl, impl.Run)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", typ, err)
	}
	return starlark.None, nil
}

// devices is devices(): every device, as dicts.
func (r *scriptRun) devices(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if err := starlark.UnpackPositionalArgs(b.Name(), args, kwargs, 0); err != nil {
		return nil, err
	}
	var out []starlark.Value
	err := r.read("devices", func(store.Device) bool { return true }, func(d store.Device) { out = append(out, deviceValue(d)) })
	if err != nil {
		return nil, err
	}
	list := starlark.NewList(out)
	if err := thread.AddAllocs(starlark.EstimateSize(list)); err != nil {
		return nil, err
	}
	return list, nil
}

// device is device(name): the device with this id, name or hostname, or
// None.
func (r *scriptRun) device(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var name string
	if err := starlark.UnpackPositionalArgs(b.Name(), args, kwargs, 1, &name); err != nil {
		return nil, err
	}
	var out starlark.Value = starlark.None
	match := func(d store.Device) bool { return d.ID == name || d.Name == name || d.Hostname == name }
	err := r.read(name, match, func(d store.Device) {
		if out == starlark.None {
			out = deviceValue(d)
		}
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// read lists the devices through policy, as a device.read of target, and
// passes those matching to fn.
func (r *scriptRun) read(target string, match func(store.Device) bool, fn func(store.Device)) error {
	return r.do(policy.DeviceRead, target, nil, nil, func(ctx context.Context, _ Event) error {
		if r.a.deps.Devices == nil {
			return errors.New("this hub lists no devices to scripts")
		}
		devs, err := r.a.deps.Devices.List(ctx)
		if err != nil {
			return fmt.Errorf("list devices: %w", err)
		}
		for _, d := range devs {
			if match(d) {
				fn(d)
			}
		}
		return nil
	})
}

// deviceValue is a device as a script sees it: its facts are left out.
func deviceValue(d store.Device) starlark.Value {
	labels := map[string]any{}
	for k, v := range d.Labels {
		labels[k] = v
	}
	m := map[string]any{
		"id": d.ID, "name": d.Name, "hostname": d.Hostname, "os": d.OS, "arch": d.Arch,
		"status": d.Status, "labels": labels, "last_seen": d.LastSeen.UTC().Format(time.RFC3339),
	}
	return toStarlark(m)
}

// toStarlark converts trigger data and device fields to Starlark values.
func toStarlark(v any) starlark.Value {
	switch v := v.(type) {
	case nil:
		return starlark.None
	case string:
		return starlark.String(v)
	case bool:
		return starlark.Bool(v)
	case int:
		return starlark.MakeInt(v)
	case int64:
		return starlark.MakeInt64(v)
	case float64:
		return starlark.Float(v)
	case time.Time:
		return starlark.String(v.UTC().Format(time.RFC3339))
	case []string:
		out := make([]starlark.Value, len(v))
		for i, x := range v {
			out[i] = starlark.String(x)
		}
		return starlark.NewList(out)
	case []any:
		out := make([]starlark.Value, len(v))
		for i, x := range v {
			out[i] = toStarlark(x)
		}
		return starlark.NewList(out)
	case map[string]string:
		d := starlark.NewDict(len(v))
		for _, k := range slices.Sorted(maps.Keys(v)) {
			_ = d.SetKey(starlark.String(k), starlark.String(v[k]))
		}
		return d
	case map[string]any:
		d := starlark.NewDict(len(v))
		for _, k := range slices.Sorted(maps.Keys(v)) {
			_ = d.SetKey(starlark.String(k), toStarlark(v[k]))
		}
		return d
	}
	return starlark.String(fmt.Sprint(v))
}

// toYAML converts an action field a script passes to the YAML a file would
// hold. A string with a template is refused: a script's values, which may come
// from devices, are never parsed as templates.
func toYAML(v starlark.Value) (*yaml.Node, error) {
	switch v := v.(type) {
	case starlark.NoneType:
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!null", Value: "null"}, nil
	case starlark.String:
		if strings.Contains(string(v), "{{") {
			return nil, errors.New("templates ({{ }}) are not allowed in a script's action fields")
		}
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: string(v)}, nil
	case starlark.Bool:
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!bool", Value: v.String()}, nil
	case starlark.Int:
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!int", Value: v.String()}, nil
	case starlark.Float:
		if math.IsInf(float64(v), 0) || math.IsNaN(float64(v)) {
			return nil, fmt.Errorf("%s is not a number a field can hold", v)
		}
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!float", Value: fmt.Sprint(float64(v))}, nil
	case *starlark.List, starlark.Tuple:
		seq := v.(starlark.Indexable)
		n := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
		for i := range seq.Len() {
			x, err := toYAML(seq.Index(i))
			if err != nil {
				return nil, err
			}
			n.Content = append(n.Content, x)
		}
		return n, nil
	case *starlark.Dict:
		n := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		for _, item := range v.Items() {
			k, ok := item[0].(starlark.String)
			if !ok {
				return nil, fmt.Errorf("a mapping's keys must be strings, not %s", item[0].Type())
			}
			x, err := toYAML(item[1])
			if err != nil {
				return nil, err
			}
			n.Content = append(n.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: string(k)}, x)
		}
		return n, nil
	}
	return nil, fmt.Errorf("a %s cannot be an action field", v.Type())
}
