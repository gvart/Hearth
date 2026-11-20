// SPDX-License-Identifier: AGPL-3.0-only

package automation

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"go.starlark.net/starlark"

	"github.com/gvart/hearth/internal/policy"
	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
	"github.com/gvart/hearth/internal/store"
)

type deviceList []store.Device

func (f deviceList) List(context.Context) ([]store.Device, error) { return f, nil }

// scriptHarness runs one automation whose only action is a script.
type scriptHarness struct {
	rt     *Runtime
	a      *Automation
	audit  *auditLog
	agents *fakeAgents
	fake   *fakeAction
}

func newScriptHarness(t *testing.T, fields string, cfg policy.Config) *scriptHarness {
	t.Helper()
	h := &scriptHarness{
		audit:  &auditLog{},
		agents: &fakeAgents{result: &agentv1.ExecResult{}},
		fake:   &fakeAction{policy: policy.AutomationWebhook},
	}
	kinds := actionKinds(ActionDeps{Agents: h.agents})
	kinds.Actions["fake"] = func(p Params) (Action, error) { return h.fake, p.Decode(&struct{}{}) }
	kinds.Actions["script"] = Script(ScriptDeps{Devices: deviceList{
		{ID: "dev-1", Name: "pi", Hostname: "pi.lan", Status: "online", Labels: map[string]string{"room": "attic"}},
		{ID: "dev-2", Name: "nas", Status: "offline"},
	}})
	src := "id: scripted\ntriggers:\n  - type: manual\nactions:\n  - id: s\n    type: script\n" + fields
	a, err := Parse("test.yaml", []byte(src), kinds)
	if err != nil {
		t.Fatal(err)
	}
	h.a = a
	h.rt = New(Config{Kinds: kinds, Policy: policy.NewWithConfig(h.audit, nil, cfg), Runs: &recorder{}})
	return h
}

// run runs the script step once and returns its error.
func (h *scriptHarness) run(ctx context.Context) error {
	_, err := h.rt.act(ctx, h.a, h.a.Actions[0], "run-1", Event{TriggerID: "manual-1", TriggerType: "manual"})
	return err
}

func source(script string) string {
	return "    source: |\n      " + strings.ReplaceAll(strings.TrimSpace(script), "\n", "\n      ") + "\n"
}

func TestScriptStepLimit(t *testing.T) {
	h := newScriptHarness(t, "    max_steps: 10000\n    timeout: 1m\n"+source("while True:\n  pass"), policy.Config{})
	start := time.Now()
	err := h.run(t.Context())
	if !errors.Is(err, errScriptSteps) {
		t.Fatalf("err = %v, want the step limit", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatalf("stopped after %s", time.Since(start))
	}
}

func TestScriptTimeout(t *testing.T) {
	h := newScriptHarness(t, "    max_steps: 100000000\n    timeout: 200ms\n"+source("while True:\n  pass"), policy.Config{})
	start := time.Now()
	err := h.run(t.Context())
	if !errors.Is(err, errScriptTimeout) || errors.Is(err, errScriptSteps) {
		t.Fatalf("err = %v, want the time limit", err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("stopped after %s", d)
	}
}

// A script blocked in an action it called stops at its time limit too.
func TestScriptTimeoutInsideCall(t *testing.T) {
	h := newScriptHarness(t, "    timeout: 200ms\n"+source(`action("fake")`), policy.Config{})
	h.fake.gate = make(chan struct{}) // never released
	start := time.Now()
	err := h.run(t.Context())
	if !errors.Is(err, errScriptTimeout) {
		t.Fatalf("err = %v, want the time limit", err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("stopped after %s", d)
	}
	if h.fake.started() != 1 {
		t.Fatalf("fake ran %d times", h.fake.started())
	}
}

// A runaway script fails the run at its limit, recorded in history.
func TestScriptRunawayRunFails(t *testing.T) {
	h := newScriptHarness(t, "    max_steps: 1000\n"+source("x = 0\nwhile True:\n  x += 1"), policy.Config{})
	rec := &recorder{}
	h.rt.cfg.Runs = rec
	if status := h.rt.execute(t.Context(), h.a, Event{TriggerID: "manual-1"}); status != StatusFailed {
		t.Fatalf("status = %s", status)
	}
	if e := rec.all()[0].Error; !strings.Contains(e, "step limit") {
		t.Fatalf("error = %q", e)
	}
}

// entries returns the audit entries of action a.
func (h *scriptHarness) entries(a policy.Action) []store.AuditEntry {
	var out []store.AuditEntry
	for _, e := range h.audit.all() {
		if e.Action == string(a) {
			out = append(out, e)
		}
	}
	return out
}

func TestScriptCannotBypassPolicy(t *testing.T) {
	script := source(`
d = device("pi")
if d["labels"]["room"] == "attic":
    action("exec", device=d["name"], command=["/usr/bin/reboot"])
`)
	t.Run("dangerous call denied and audited", func(t *testing.T) {
		h := newScriptHarness(t, script, policy.Config{})
		err := h.run(t.Context())
		if !errors.Is(err, policy.ErrDenied) {
			t.Fatalf("err = %v, want a denial", err)
		}
		if n := len(h.agents.requests()); n != 0 {
			t.Fatalf("agent got %d requests", n)
		}
		got := h.entries(policy.AutomationExec)
		if len(got) != 1 || got[0].Decision != policy.Deny || got[0].ActorKind != policy.ActorAutomation ||
			got[0].ActorID != "scripted" || got[0].Target != "pi" {
			t.Fatalf("exec entries = %+v", got)
		}
		var d map[string]any
		_ = json.Unmarshal(got[0].Detail, &d)
		if d["run"] != "run-1" || d["step"] != "s" || d["type"] != "exec" {
			t.Fatalf("detail = %v", d)
		}
		if reads := h.entries(policy.DeviceRead); len(reads) != 1 || reads[0].Decision != policy.Allow {
			t.Fatalf("device.read entries = %+v", reads)
		}
		// The run is recorded as denied, like a denied YAML action.
		rec := &recorder{}
		h.rt.cfg.Runs = rec
		if status := h.rt.execute(t.Context(), h.a, Event{TriggerID: "manual-1"}); status != StatusDenied {
			t.Fatalf("status = %s", status)
		}
	})
	t.Run("granted automation may", func(t *testing.T) {
		h := newScriptHarness(t, script, policy.Config{DangerousAutomations: []string{"scripted"}})
		if err := h.run(t.Context()); err != nil {
			t.Fatal(err)
		}
		if n := len(h.agents.requests()); n != 1 {
			t.Fatalf("agent got %d requests", n)
		}
		if got := h.entries(policy.AutomationExec); len(got) != 1 || got[0].Result != "ok" {
			t.Fatalf("exec entries = %+v", got)
		}
	})
	t.Run("reads denied by configuration", func(t *testing.T) {
		cfg := policy.Config{Actors: map[string]map[policy.Class]policy.Mode{
			policy.ActorAutomation: {policy.Read: policy.ModeDeny},
		}}
		h := newScriptHarness(t, source(`devices()`), cfg)
		if err := h.run(t.Context()); !errors.Is(err, policy.ErrDenied) {
			t.Fatalf("err = %v, want a denial", err)
		}
		if got := h.entries(policy.DeviceRead); len(got) != 1 || got[0].Decision != policy.Deny {
			t.Fatalf("device.read entries = %+v", got)
		}
	})
	t.Run("script denied runs nothing", func(t *testing.T) {
		cfg := policy.Config{Actors: map[string]map[policy.Class]policy.Mode{
			policy.ActorAutomation: {policy.Safe: policy.ModeDeny},
		}}
		h := newScriptHarness(t, source(`devices()`), cfg)
		if err := h.run(t.Context()); !errors.Is(err, policy.ErrDenied) {
			t.Fatalf("err = %v, want a denial", err)
		}
		if got := h.entries(policy.DeviceRead); len(got) != 0 {
			t.Fatalf("device.read entries = %+v", got)
		}
	})
	t.Run("not run outside policy", func(t *testing.T) {
		h := newScriptHarness(t, source(`devices()`), policy.Config{})
		if err := h.a.Actions[0].Impl.Run(t.Context(), Event{}); err == nil {
			t.Fatal("ran outside policy")
		}
		// Nor with a caller but no grant.
		ctx := withCaller(t.Context(), caller{policy: h.rt.cfg.Policy, req: policy.Request{
			ActorKind: policy.ActorAutomation, ActorID: "scripted",
		}})
		if err := h.a.Actions[0].Impl.Run(ctx, Event{}); err == nil {
			t.Fatal("ran without a grant")
		}
		if n := len(h.audit.all()); n != 0 {
			t.Fatalf("%d audit entries", n)
		}
	})
}

func TestScriptCallsAudited(t *testing.T) {
	h := newScriptHarness(t, source(`
names = [d["name"] for d in devices() if d["status"] == "online"]
action("log", message="online: " + ", ".join(names) + " via " + trigger["ID"])
action("fake")
`), policy.Config{})
	if err := h.run(t.Context()); err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, e := range h.audit.all() {
		if e.ActorID != "scripted" || e.Decision != policy.Allow {
			t.Fatalf("entry %+v", e)
		}
		got = append(got, e.Action)
	}
	want := []string{"automation.script", "device.read", "automation.log", "automation.webhook"}
	if !slices.Equal(got, want) {
		t.Fatalf("audited %v, want %v", got, want)
	}
	if h.fake.started() != 1 {
		t.Fatal("fake did not run")
	}
}

func TestScriptCallLimit(t *testing.T) {
	h := newScriptHarness(t, source(`
for i in range(1000):
    action("log", message="x")
`), policy.Config{})
	err := h.run(t.Context())
	if err == nil || !strings.Contains(err.Error(), "at most") {
		t.Fatalf("err = %v", err)
	}
	if n := len(h.entries(policy.AutomationLog)); n != maxScriptCalls {
		t.Fatalf("%d log entries", n)
	}
}

func TestScriptDryRunRunsNothing(t *testing.T) {
	h := newScriptHarness(t, source(`action("fake")`), policy.Config{})
	h.rt.cfg.DryRun = true
	if err := h.run(t.Context()); err != nil {
		t.Fatal(err)
	}
	if h.fake.started() != 0 {
		t.Fatal("dry run ran the script")
	}
}

// No builtin a script can reach does I/O: Starlark's universe is the pure
// language core, and the script's own globals go through policy.
func TestScriptHasNoIO(t *testing.T) {
	pure := []string{
		"None", "True", "False", "abs", "any", "all", "bool", "bytes", "chr", "dict", "dir", "enumerate",
		"fail", "float", "getattr", "hasattr", "hash", "int", "len", "list", "max", "min", "ord", "print",
		"range", "repr", "reversed", "set", "sorted", "str", "tuple", "type", "zip",
	}
	for name := range starlark.Universe {
		if !slices.Contains(pure, name) {
			t.Errorf("Starlark's universe has %q: check it does no I/O, then add it here", name)
		}
	}
	if !slices.Equal(scriptGlobals, []string{"trigger", "action", "devices", "device", "print"}) {
		t.Errorf("script globals %v: check each goes through policy, then update this test", scriptGlobals)
	}

	for _, script := range []string{
		`load("os", "getenv")`,
		`open("/etc/passwd")`,
		`exec("x")`,
		`getenv("HOME")`,
		`os.environ`,
		`http.get("http://example.com")`,
	} {
		_, err := Parse("t.yaml", []byte("id: x\ntriggers:\n  - type: manual\nactions:\n  - type: script\n"+source(script)),
			scriptKinds())
		if err == nil {
			t.Errorf("%s loaded", script)
		}
	}

	for _, tc := range []struct{ script, want string }{
		{`print("x")`, "not available"},
		{`action("script", source="x = 1")`, "unknown action type"},
		{`action("log", message="{{ .Trigger.ID }}")`, "templates"},
		{`action("log", id="x", message="y")`, "not an action field"},
	} {
		h := newScriptHarness(t, source(tc.script), policy.Config{})
		if err := h.run(t.Context()); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want %q", tc.script, err, tc.want)
		}
	}
}

func scriptKinds() Kinds {
	k := actionKinds(ActionDeps{})
	k.Actions["script"] = Script(ScriptDeps{})
	return k
}

func TestScriptLoadErrors(t *testing.T) {
	for _, tc := range []struct{ fields, want string }{
		{"    timeout: 2m\n" + source("x = 1"), "timeout must be"},
		{"    timeout: -1s\n" + source("x = 1"), "timeout must be"},
		{"    max_steps: 1000000000\n" + source("x = 1"), "max_steps must be"},
		{"    source: ''\n", "source is required"},
		{"    source: |\n      x = 1\n      y = (\n", "t.yaml:9: source:"},
		{"    source: |\n      x = 1\n      y = undefined_name\n", "t.yaml:8: source: undefined: undefined_name"},
		{"    source: |\n      def f():\n        return f()\n", ""}, // recursion is a run-time error
		{"    sauce: x = 1\n", "unknown field"},
	} {
		_, err := Parse("t.yaml", []byte("id: x\ntriggers:\n  - type: manual\nactions:\n  - type: script\n"+tc.fields), scriptKinds())
		if tc.want == "" {
			if err != nil {
				t.Errorf("%q: %v", tc.fields, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%q: err = %v, want %q", tc.fields, err, tc.want)
		}
	}
}
