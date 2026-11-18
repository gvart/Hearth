// SPDX-License-Identifier: AGPL-3.0-only

package automation

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/policy"
)

const fakeYAML = `id: fake
mode: %MODE%
triggers:
  - id: go
    type: manual
conditions:
  - id: check
    type: fake
actions:
  - id: act
    type: fake
`

func fakeAutomation(mode Mode) string { return strings.ReplaceAll(fakeYAML, "%MODE%", string(mode)) }

func TestRunSucceedsThroughPolicy(t *testing.T) {
	act := &fakeAction{policy: policy.AutomationLog}
	cond := &fakeCondition{holds: true}
	h := newHarness(t, fakeAutomation(ModeSingle), testKinds(act, cond, nil))

	if err := h.rt.Fire("fake", "go"); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the run recorded", func() bool { return len(h.rec.all()) == 1 })
	run := h.rec.all()[0]
	if run.Status != StatusSucceeded || run.AutomationID != "fake" || run.TriggerID != "go" || run.ID == "" ||
		run.Error != "" || run.FinishedAt.Before(run.StartedAt) {
		t.Errorf("run = %+v", run)
	}
	want := []StepResult{
		{ID: "go", Type: "manual", Status: "fired"},
		{ID: "check", Type: "fake", Status: "ok"},
		{ID: "act", Type: "fake", Status: "ok"},
	}
	if got := steps(t, run); !reflect.DeepEqual(got, want) {
		t.Errorf("steps = %+v, want %+v", got, want)
	}
	// One audit entry for the action, with the automation as the actor.
	entries := h.audit.all()
	if len(entries) != 1 {
		t.Fatalf("audit entries = %+v, want 1", entries)
	}
	e := entries[0]
	if e.ActorKind != policy.ActorAutomation || e.ActorID != "fake" || e.Action != string(policy.AutomationLog) ||
		e.Target != "fake-target" || e.Decision != policy.Allow || e.Result != "ok" ||
		!strings.Contains(string(e.Detail), `"run":"`+run.ID+`"`) {
		t.Errorf("audit entry = %+v (%s)", e, e.Detail)
	}
}

func TestRunSkippedWhenConditionFails(t *testing.T) {
	act := &fakeAction{policy: policy.AutomationLog}
	h := newHarness(t, fakeAutomation(ModeSingle), testKinds(act, &fakeCondition{holds: false}, nil))
	if err := h.rt.Fire("fake", "go"); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the run recorded", func() bool { return len(h.rec.all()) == 1 })
	run := h.rec.all()[0]
	if run.Status != StatusSkipped || act.started() != 0 || len(h.audit.all()) != 0 {
		t.Errorf("run = %+v, actions started %d, audit %v; want skipped with nothing done", run, act.started(), h.audit.all())
	}
	if got := steps(t, run); len(got) != 2 || got[1].Status != "not_met" {
		t.Errorf("steps = %+v", got)
	}
}

// A denied action does not run, stops the run, and is in the run history
// and the audit log.
func TestRunDeniedByPolicy(t *testing.T) {
	// device.revoke is for admins only.
	act := &fakeAction{policy: policy.DeviceRevoke}
	h := newHarness(t, fakeAutomation(ModeSingle)+"  - id: after\n    type: log\n    message: never\n",
		testKinds(act, &fakeCondition{holds: true}, nil))
	if err := h.rt.Fire("fake", "go"); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the run recorded", func() bool { return len(h.rec.all()) == 1 })
	run := h.rec.all()[0]
	if run.Status != StatusDenied || !strings.Contains(run.Error, "denied by policy") || act.started() != 0 {
		t.Errorf("run = %+v, action started %d times", run, act.started())
	}
	if got := steps(t, run); len(got) != 3 || got[2].ID != "act" || got[2].Status != "denied" {
		t.Errorf("steps = %+v, want the denial last", got)
	}
	entries := h.audit.all()
	if len(entries) != 1 || entries[0].Decision != policy.Deny || entries[0].ActorID != "fake" {
		t.Errorf("audit = %+v, want one denial for automation fake", entries)
	}
}

func TestFireUnknown(t *testing.T) {
	h := newHarness(t, fakeAutomation(ModeSingle), testKinds(&fakeAction{policy: policy.AutomationLog}, &fakeCondition{}, nil))
	if err := h.rt.Fire("nope", "go"); !errors.Is(err, ErrNotRunning) {
		t.Errorf("Fire(unknown automation) = %v, want ErrNotRunning", err)
	}
	if err := h.rt.Fire("fake", "nope"); err == nil {
		t.Error("Fire(unknown trigger) = nil, want an error")
	}
}

func TestModes(t *testing.T) {
	tests := []struct {
		mode Mode
		// starts is how many runs start while the first blocks and two more
		// triggers fire; want the statuses once every run is released.
		starts int
		want   []string
	}{
		{mode: ModeSingle, starts: 1, want: []string{StatusSucceeded}},
		{mode: ModeQueued, starts: 1, want: []string{StatusSucceeded, StatusSucceeded, StatusSucceeded}},
		{mode: ModeRestart, starts: 3, want: []string{StatusCancelled, StatusCancelled, StatusSucceeded}},
	}
	for _, tt := range tests {
		t.Run(string(tt.mode), func(t *testing.T) {
			gate := make(chan struct{})
			act := &fakeAction{policy: policy.AutomationLog, gate: gate}
			h := newHarness(t, fakeAutomation(tt.mode), testKinds(act, &fakeCondition{holds: true}, nil))

			if err := h.rt.Fire("fake", "go"); err != nil {
				t.Fatal(err)
			}
			eventually(t, "the first run started", func() bool { return act.started() == 1 })
			for i := range 2 {
				if err := h.rt.Fire("fake", "go"); err != nil {
					t.Fatal(err)
				}
				if tt.mode == ModeRestart {
					eventually(t, "the restarted run", func() bool { return act.started() == i+2 })
				}
			}
			time.Sleep(20 * time.Millisecond)
			if got := act.started(); got != tt.starts {
				t.Fatalf("%d runs started while the first blocked, want %d", got, tt.starts)
			}
			close(gate)
			eventually(t, "every run recorded", func() bool { return len(h.rec.all()) == len(tt.want) })
			time.Sleep(20 * time.Millisecond)
			if got := h.rec.statuses(); !slices.Equal(got, tt.want) {
				t.Errorf("statuses = %v, want %v", got, tt.want)
			}
			// Every action that started was audited, the cancelled ones too.
			if got := len(h.audit.all()); got != act.started() {
				t.Errorf("%d audit entries for %d actions", got, act.started())
			}
		})
	}
}

func TestQueuedDropsBeyondMax(t *testing.T) {
	gate := make(chan struct{})
	act := &fakeAction{policy: policy.AutomationLog, gate: gate}
	h := newHarness(t, fakeAutomation(ModeQueued), testKinds(act, &fakeCondition{holds: true}, nil))
	if err := h.rt.Fire("fake", "go"); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the first run started", func() bool { return act.started() == 1 })
	for range MaxQueued + 5 {
		if err := h.rt.Fire("fake", "go"); err != nil {
			t.Fatal(err)
		}
	}
	close(gate)
	eventually(t, "the queue drained", func() bool { return len(h.rec.all()) == MaxQueued+1 })
	time.Sleep(20 * time.Millisecond)
	if got := len(h.rec.all()); got != MaxQueued+1 {
		t.Errorf("%d runs, want %d", got, MaxQueued+1)
	}
}

// Run reloads the directory: new files start, changed ones restart, removed
// ones stop, and an invalid file changes nothing.
func TestRunHotReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hello.yaml")
	write := func(content string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	trig := &fakeTrigger{}
	kinds := testKinds(&fakeAction{policy: policy.AutomationLog}, &fakeCondition{holds: true}, trig)
	rec := &recorder{}
	rt := New(Config{Dir: dir, Kinds: kinds, Policy: policy.New(&auditLog{}), Runs: rec, ReloadEvery: 10 * time.Millisecond})
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- rt.Run(ctx) }()
	running := func(id string) func() bool {
		return func() bool { return !errors.Is(rt.Fire(id, "go"), ErrNotRunning) }
	}
	watched := func() int {
		trig.mu.Lock()
		defer trig.mu.Unlock()
		return trig.watched
	}

	const v1 = "id: hello\ntriggers:\n  - {id: go, type: manual}\n  - {id: tick, type: fake}\nactions: [{type: log, message: v1}]\n"
	write(v1)
	eventually(t, "hello loaded", running("hello"))
	eventually(t, "hello's trigger watched", func() bool { return watched() == 1 })

	write("id: hello\ntriggers: [{type: manual}\n") // invalid YAML
	time.Sleep(50 * time.Millisecond)
	if !running("hello")() || watched() != 1 {
		t.Fatal("an invalid file stopped or restarted the running automation")
	}

	write(strings.Replace(v1, "v1", "v2", 1))
	eventually(t, "hello restarted", func() bool { return watched() == 2 })

	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	eventually(t, "hello stopped", func() bool { return !running("hello")() })

	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// When Run returns, the run in progress has been cancelled and recorded.
func TestRunStopCancelsRuns(t *testing.T) {
	dir := t.TempDir()
	act := &fakeAction{policy: policy.AutomationLog, gate: make(chan struct{})}
	if err := os.WriteFile(filepath.Join(dir, "a.yaml"), []byte(fakeAutomation(ModeSingle)), 0o600); err != nil {
		t.Fatal(err)
	}
	rec := &recorder{}
	rt := New(Config{Dir: dir, Kinds: testKinds(act, &fakeCondition{holds: true}, nil), Policy: policy.New(&auditLog{}), Runs: rec})
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- rt.Run(ctx) }()
	eventually(t, "fired", func() bool { return rt.Fire("fake", "go") == nil })
	eventually(t, "the run started", func() bool { return act.started() == 1 })
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if got := rec.statuses(); !slices.Equal(got, []string{StatusCancelled}) {
		t.Errorf("statuses = %v, want the run cancelled and recorded before Run returned", got)
	}
}
