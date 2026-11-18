// SPDX-License-Identifier: AGPL-3.0-only

package automation

import (
	"context"
	"encoding/json"
	"log/slog"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

// fakeAction records its runs. With a gate it blocks each run until the gate
// is released or the run is cancelled.
type fakeAction struct {
	policy policy.Action
	gate   chan struct{}

	mu   sync.Mutex
	runs []string // trigger of each run started
}

func (a *fakeAction) Describe() string      { return "do the fake thing" }
func (a *fakeAction) Policy() policy.Action { return a.policy }
func (a *fakeAction) Target() string        { return "fake-target" }

func (a *fakeAction) Run(ctx context.Context, ev Event) error {
	a.mu.Lock()
	a.runs = append(a.runs, ev.TriggerID)
	a.mu.Unlock()
	if a.gate == nil {
		return nil
	}
	select {
	case <-a.gate:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (a *fakeAction) started() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.runs)
}

// fakeCondition holds or not, and counts its checks.
type fakeCondition struct {
	holds  bool
	mu     sync.Mutex
	checks int
}

func (c *fakeCondition) Describe() string { return "the fake condition holds" }

func (c *fakeCondition) Check(context.Context, Event) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.checks++
	return c.holds, nil
}

// fakeTrigger counts how often it was watched, and fires on demand.
type fakeTrigger struct {
	mu      sync.Mutex
	watched int
}

func (t *fakeTrigger) Describe() string { return "fires in tests" }

func (t *fakeTrigger) Watch(ctx context.Context, _ func()) error {
	t.mu.Lock()
	t.watched++
	t.mu.Unlock()
	<-ctx.Done()
	return nil
}

// testKinds are the built-ins plus "fake" steps backed by the given values.
func testKinds(act *fakeAction, cond *fakeCondition, trig *fakeTrigger) Kinds {
	k := Builtin(slog.New(slog.DiscardHandler))
	k.Actions["fake"] = func(p Params) (Action, error) { return act, p.Decode(&struct{}{}) }
	k.Conditions["fake"] = func(p Params) (Condition, error) { return cond, p.Decode(&struct{}{}) }
	k.Triggers["fake"] = func(p Params) (Trigger, error) { return trig, p.Decode(&struct{}{}) }
	return k
}

// recorder is an in-memory run history.
type recorder struct {
	mu   sync.Mutex
	runs []store.AutomationRun
}

func (r *recorder) Record(_ context.Context, run store.AutomationRun) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.runs = append(r.runs, run)
	return nil
}

func (r *recorder) all() []store.AutomationRun {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.runs)
}

func (r *recorder) statuses() []string {
	var out []string
	for _, run := range r.all() {
		out = append(out, run.Status)
	}
	return out
}

func steps(t *testing.T, run store.AutomationRun) []StepResult {
	t.Helper()
	var out []StepResult
	if err := json.Unmarshal(run.Steps, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// auditLog is an in-memory policy.Auditor.
type auditLog struct {
	mu      sync.Mutex
	entries []store.AuditEntry
}

func (a *auditLog) Append(_ context.Context, e store.AuditEntry) (int64, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.entries = append(a.entries, e)
	return int64(len(a.entries)), nil
}

func (a *auditLog) all() []store.AuditEntry {
	a.mu.Lock()
	defer a.mu.Unlock()
	return slices.Clone(a.entries)
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// harness is a runtime over one parsed automation, without a directory.
type harness struct {
	rt    *Runtime
	rec   *recorder
	audit *auditLog
}

func newHarness(t *testing.T, yaml string, kinds Kinds) *harness {
	t.Helper()
	a, err := Parse("test.yaml", []byte(yaml), kinds)
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{rec: &recorder{}, audit: &auditLog{}}
	h.rt = New(Config{Kinds: kinds, Policy: policy.New(h.audit), Runs: h.rec})
	ctx, cancel := context.WithCancel(context.Background())
	h.rt.reconcile(ctx, []*Automation{a})
	t.Cleanup(func() {
		cancel()
		h.rt.reconcile(ctx, nil)
	})
	return h
}
