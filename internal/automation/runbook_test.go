// SPDX-License-Identifier: AGPL-3.0-only

package automation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/policy"
	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
	"github.com/gvart/hearth/internal/store"
)

// xorSealer stands in for the hub's sealer: what it stores is not the file.
type xorSealer struct{}

func (xorSealer) Seal(_ string, b []byte) ([]byte, error) { return xor(b), nil }
func (xorSealer) Open(_ string, b []byte) ([]byte, error) { return xor(b), nil }

func xor(b []byte) []byte {
	out := make([]byte, len(b))
	for i, c := range b {
		out[i] = c ^ 0x5a
	}
	return out
}

// script is what the "script" action kind does: it records every run by name,
// and fails or blocks the runs it is told to.
type script struct {
	mu    sync.Mutex
	ran   []string
	fails map[string]int
	gates map[string]chan struct{}
}

func (s *script) calls() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.ran)
}

func (s *script) count(name string) int {
	n := 0
	for _, c := range s.calls() {
		if c == name {
			n++
		}
	}
	return n
}

// failNext makes the next n runs of name fail.
func (s *script) failNext(name string, n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fails[name] = n
}

// gate makes runs of name block until the returned channel is closed.
func (s *script) gate(name string) chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := make(chan struct{})
	s.gates[name] = c
	return c
}

type scriptAction struct {
	s      *script
	name   string
	policy policy.Action
}

func (a *scriptAction) Describe() string      { return "script " + a.name }
func (a *scriptAction) Policy() policy.Action { return a.policy }
func (a *scriptAction) Target() Text          { return Literal(a.name) }

func (a *scriptAction) Run(ctx context.Context, _ Event) error {
	a.s.mu.Lock()
	a.s.ran = append(a.s.ran, a.name)
	gate := a.s.gates[a.name]
	fail := a.s.fails[a.name] > 0
	if fail {
		a.s.fails[a.name]--
	}
	a.s.mu.Unlock()
	if gate != nil {
		select {
		case <-gate:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if fail {
		return errors.New("boom from " + a.name)
	}
	return nil
}

// rbHarness is an engine over a real store in a temp dir.
type rbHarness struct {
	t      *testing.T
	dbPath string
	dir    string
	st     *store.Store
	script *script
	audit  *auditLog
	cfg    policy.Config
	kinds  Kinds
	rb     *Runbooks
}

func newRBHarness(t *testing.T, yaml string, cfg policy.Config) *rbHarness {
	t.Helper()
	dir := t.TempDir()
	h := &rbHarness{
		t: t, dbPath: filepath.Join(dir, "hearth.db"), dir: filepath.Join(dir, "runbooks"),
		script: &script{fails: map[string]int{}, gates: map[string]chan struct{}{}},
		audit:  &auditLog{}, cfg: cfg,
	}
	if err := os.MkdirAll(h.dir, 0o700); err != nil {
		t.Fatal(err)
	}
	h.kinds = Builtin(slog.New(slog.DiscardHandler))
	maps.Copy(h.kinds.Actions, Actions(ActionDeps{Agents: &recordingAgents{}}))
	h.kinds.Actions["script"] = func(p Params) (Action, error) {
		var c struct {
			Name   string `yaml:"name"`
			Policy string `yaml:"policy"`
		}
		if err := p.Decode(&c); err != nil {
			return nil, err
		}
		pol := policy.AutomationRestart
		if c.Policy != "" {
			pol = policy.Action(c.Policy)
		}
		return &scriptAction{s: h.script, name: c.Name, policy: pol}, nil
	}
	h.write("rb.yaml", yaml)
	h.open()
	return h
}

func (h *rbHarness) write(name, yaml string) {
	h.t.Helper()
	if err := os.WriteFile(filepath.Join(h.dir, name), []byte(yaml), 0o600); err != nil {
		h.t.Fatal(err)
	}
}

// open opens the store and a new engine on it, as a starting hub does.
func (h *rbHarness) open() {
	h.t.Helper()
	st, err := store.Open(context.Background(), h.dbPath)
	if err != nil {
		h.t.Fatal(err)
	}
	h.t.Cleanup(func() { _ = st.Close() })
	h.st = st
	h.rb = h.engine()
}

func (h *rbHarness) engine() *Runbooks {
	return NewRunbooks(RunbooksConfig{
		Dir: h.dir, Kinds: h.kinds, Policy: policy.NewWithConfig(h.audit, nil, h.cfg),
		Runs: h.st.RunbookRuns(), Sealer: xorSealer{}, Poll: 5 * time.Millisecond,
	})
}

// run starts e and returns a function that stops it and waits for it.
func (h *rbHarness) run(e *Runbooks) (stop func()) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = e.Run(ctx)
	}()
	var once sync.Once
	stop = func() {
		once.Do(func() {
			cancel()
			<-done
		})
	}
	h.t.Cleanup(stop)
	eventually(h.t, "the engine leading", func() bool {
		e.mu.Lock()
		defer e.mu.Unlock()
		return e.leading
	})
	return stop
}

func (h *rbHarness) start(id string) string {
	h.t.Helper()
	run, err := h.rb.Start(context.Background(), policy.ActorWeb, "10.0.0.9", id)
	if err != nil {
		h.t.Fatal(err)
	}
	return run.ID
}

func (h *rbHarness) get(id string) RunbookRunJSON {
	h.t.Helper()
	run, err := h.rb.GetRun(context.Background(), id)
	if err != nil {
		h.t.Fatal(err)
	}
	return run
}

// await waits for the run to reach status.
func (h *rbHarness) await(id, status string) RunbookRunJSON {
	h.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		run := h.get(id)
		if run.Status == status {
			return run
		}
		if time.Now().After(deadline) {
			h.t.Fatalf("run is %s, want %s: %+v", run.Status, status, run.Steps)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func (h *rbHarness) answer(id, step, value string) {
	h.t.Helper()
	if _, err := h.rb.Answer(context.Background(), policy.ActorWeb, "10.0.0.9", id, step, value); err != nil {
		h.t.Fatal(err)
	}
}

func (h *rbHarness) retry(id string) {
	h.t.Helper()
	if _, err := h.rb.Retry(context.Background(), policy.ActorWeb, "10.0.0.9", id); err != nil {
		h.t.Fatal(err)
	}
}

func (h *rbHarness) rollback(id string) {
	h.t.Helper()
	if _, err := h.rb.Rollback(context.Background(), policy.ActorWeb, "10.0.0.9", id); err != nil {
		h.t.Fatal(err)
	}
}

// audited are the audit entries of action.
func (h *rbHarness) audited(action policy.Action) []store.AuditEntry {
	var out []store.AuditEntry
	for _, e := range h.audit.all() {
		if e.Action == string(action) {
			out = append(out, e)
		}
	}
	return out
}

// tcpListener returns the address of a port that accepts connections.
func tcpListener(t *testing.T) string {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	return ln.Addr().String()
}

const threeSteps = `id: rb
steps:
  - id: one
    type: action
    action: {type: script, name: one}
    rollback: {type: script, name: undo-one}
  - id: two
    type: action
    action: {type: script, name: two}
    rollback: {type: script, name: undo-two}
  - id: three
    type: action
    action: {type: script, name: three}
    rollback: {type: script, name: undo-three}
`

func TestRunbookEveryStepType(t *testing.T) {
	yaml := fmt.Sprintf(`id: rb
steps:
  - id: ask
    type: prompt
    message: Which release?
  - id: sure
    type: prompt
    prompt: confirm
    message: Go ahead?
  - id: act
    type: action
    action: {type: script, name: act}
  - id: reachable
    type: check
    check: {type: tcp, address: %q}
  - id: settle
    type: wait
    duration: 20ms
  - id: after
    type: action
    action: {type: script, name: after}
`, tcpListener(t))
	h := newRBHarness(t, yaml, policy.Config{})
	h.run(h.rb)
	id := h.start("rb")

	run := h.await(id, RunbookWaiting)
	if run.Awaiting != "ask" || run.Deadline == nil {
		t.Fatalf("awaiting = %q, deadline %v", run.Awaiting, run.Deadline)
	}
	h.answer(id, "ask", "v1.2")
	eventually(t, "the confirm prompt", func() bool { return h.get(id).Awaiting == "sure" })
	if n := len(h.script.calls()); n != 0 {
		t.Fatalf("%d actions ran before the prompts were answered", n)
	}
	h.answer(id, "sure", ConfirmYes)

	run = h.await(id, RunbookSucceeded)
	if got, want := h.script.calls(), []string{"act", "after"}; !reflect.DeepEqual(got, want) {
		t.Errorf("ran %v, want %v", got, want)
	}
	for _, s := range run.Steps {
		if s.Status != stepOK {
			t.Errorf("step %s is %s", s.ID, s.Status)
		}
	}
	if run.Inputs["ask"] != "v1.2" {
		t.Errorf("inputs = %v", run.Inputs)
	}
	if run.FinishedAt == nil {
		t.Error("a finished run has no finish time")
	}
}

func TestRunbookCheckFailureStopsTheRun(t *testing.T) {
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close() // nothing listens here any more
	h := newRBHarness(t, fmt.Sprintf(`id: rb
steps:
  - id: reachable
    type: check
    check: {type: tcp, address: %q}
  - id: after
    type: action
    action: {type: script, name: after}
`, addr), policy.Config{})
	h.run(h.rb)
	id := h.start("rb")
	run := h.await(id, RunbookFailed)
	if run.Steps[0].Status != stepFailed || run.Steps[0].Error == "" {
		t.Errorf("step = %+v", run.Steps[0])
	}
	if n := h.script.count("after"); n != 0 {
		t.Errorf("the step after a failed check ran %d times", n)
	}
}

func TestRunbookConfirmDeclinedStopsTheRun(t *testing.T) {
	h := newRBHarness(t, `id: rb
steps:
  - id: sure
    type: prompt
    prompt: confirm
    message: Go ahead?
  - id: after
    type: action
    action: {type: script, name: after}
`, policy.Config{})
	h.run(h.rb)
	id := h.start("rb")
	h.await(id, RunbookWaiting)
	h.answer(id, "sure", ConfirmNo)
	run := h.await(id, RunbookFailed)
	if !strings.Contains(run.Steps[0].Error, "declined by web/10.0.0.9") {
		t.Errorf("error = %q", run.Steps[0].Error)
	}
	if h.script.count("after") != 0 {
		t.Error("a declined run went on")
	}
	if _, err := h.rb.Answer(context.Background(), policy.ActorWeb, "x", id, "sure", ConfirmYes); !errors.Is(err, ErrRunbookState) {
		t.Errorf("answering a closed prompt: %v", err)
	}
}

func TestRunbookPlanExecutesNothing(t *testing.T) {
	h := newRBHarness(t, `id: rb
steps:
  - id: ask
    type: prompt
    message: Why?
  - id: safe
    type: action
    action: {type: script, name: safe}
    rollback: {type: script, name: undo-safe}
  - id: risky
    type: action
    action: {type: exec, device: pi4, command: [/usr/bin/reboot]}
  - id: pause
    type: wait
    duration: 1h
`, policy.Config{})
	h.run(h.rb)
	plan, err := h.rb.Plan(context.Background(), "rb")
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Steps) != 4 {
		t.Fatalf("plan has %d steps", len(plan.Steps))
	}
	safe, risky := plan.Steps[1], plan.Steps[2]
	if safe.Decision != policy.Allow || safe.Class != string(policy.Safe) || safe.Rollback == nil || safe.Rollback.Decision != policy.Allow {
		t.Errorf("safe step plan = %+v", safe)
	}
	if risky.Decision != policy.Deny || risky.Reason == "" || risky.Action != string(policy.AutomationExec) {
		t.Errorf("risky step plan = %+v", risky)
	}
	if n := len(h.script.calls()); n != 0 {
		t.Errorf("planning ran %d actions", n)
	}
	if n := len(h.audit.all()); n != 0 {
		t.Errorf("planning wrote %d audit entries", n)
	}
	runs, err := h.rb.Runs(context.Background(), "", 10)
	if err != nil || len(runs) != 0 {
		t.Errorf("planning made runs: %v, %v", runs, err)
	}
}

func TestRunbookPlanShowsTheCapabilityCeiling(t *testing.T) {
	agents := &recordingAgents{ceiling: fmt.Errorf("no: %w", policy.ErrBeyondCeiling)}
	h := newRBHarness(t, `id: rb
steps:
  - id: restart
    type: action
    action: {type: restart, device: pi4, service: "systemd:pihole-FTL.service"}
`, policy.Config{})
	maps.Copy(h.kinds.Actions, Actions(ActionDeps{Agents: agents}))
	plan, err := h.engine().Plan(context.Background(), "rb")
	if err != nil {
		t.Fatal(err)
	}
	if s := plan.Steps[0]; s.Decision != policy.Deny || !strings.Contains(s.Reason, "ceiling") {
		t.Errorf("plan = %+v", s)
	}
	if agents.execs() != 0 {
		t.Error("planning sent a request to the agent")
	}
}

func TestRunbookRetryRunsTheFailedStepAgain(t *testing.T) {
	h := newRBHarness(t, threeSteps, policy.Config{})
	h.script.failNext("two", 1)
	h.run(h.rb)
	id := h.start("rb")

	run := h.await(id, RunbookFailed)
	if run.Cursor != 1 || run.Steps[1].Status != stepFailed || !strings.Contains(run.Steps[1].Error, "boom") ||
		!run.CanRetry || !run.CanRollback {
		t.Fatalf("run = %+v", run)
	}
	h.retry(id)
	run = h.await(id, RunbookSucceeded)
	if got, want := h.script.calls(), []string{"one", "two", "two", "three"}; !reflect.DeepEqual(got, want) {
		t.Errorf("ran %v, want %v", got, want)
	}
	if run.Steps[1].Attempts != 2 {
		t.Errorf("attempts = %d", run.Steps[1].Attempts)
	}
	// Each attempt of the step has its own decision; the retry its own entry.
	var two int
	for _, e := range h.audited(policy.AutomationRestart) {
		if e.Target == "two" {
			two++
		}
	}
	if two != 2 {
		t.Errorf("step two has %d audit entries, want 2", two)
	}
	retries := h.audited(policy.RunbookRetry)
	if len(retries) != 1 || retries[0].ActorKind != policy.ActorWeb || retries[0].ActorID != "10.0.0.9" || retries[0].Target != id {
		t.Errorf("retry audit = %+v", retries)
	}
	if _, err := h.rb.Retry(context.Background(), policy.ActorWeb, "x", id); !errors.Is(err, ErrRunbookState) {
		t.Errorf("retrying a finished run: %v", err)
	}
}

func TestRunbookRollbackRunsInReverseOrder(t *testing.T) {
	h := newRBHarness(t, threeSteps, policy.Config{})
	h.script.failNext("three", 1)
	h.run(h.rb)
	id := h.start("rb")
	h.await(id, RunbookFailed)

	h.rollback(id)
	run := h.await(id, RunbookRolledBack)
	want := []string{"one", "two", "three", "undo-two", "undo-one"}
	if got := h.script.calls(); !reflect.DeepEqual(got, want) {
		t.Errorf("ran %v, want %v (a step that failed is not undone)", got, want)
	}
	if run.Steps[2].Rollback.Status != stepPending || run.Steps[1].Rollback.Status != stepOK {
		t.Errorf("rollback states: %+v %+v", run.Steps[2].Rollback, run.Steps[1].Rollback)
	}
	for _, name := range []string{"undo-one", "undo-two"} {
		var n int
		for _, e := range h.audited(policy.AutomationRestart) {
			if e.Target == name && strings.Contains(string(e.Detail), `"phase":"rollback"`) {
				n++
			}
		}
		if n != 1 {
			t.Errorf("%s has %d audit entries, want 1", name, n)
		}
	}
	if len(h.audited(policy.RunbookRollback)) != 1 {
		t.Error("the rollback was not audited")
	}
}

func TestRunbookFailingRollbackStepStopsAndCanBeRetried(t *testing.T) {
	h := newRBHarness(t, threeSteps, policy.Config{})
	h.script.failNext("three", 1)
	h.script.failNext("undo-two", 1)
	h.run(h.rb)
	id := h.start("rb")
	h.await(id, RunbookFailed)
	h.rollback(id)

	run := h.await(id, RunbookRollbackFailed)
	if run.Steps[1].Rollback.Status != stepFailed || !strings.Contains(run.Steps[1].Rollback.Error, "boom") {
		t.Fatalf("rollback = %+v", run.Steps[1].Rollback)
	}
	if h.script.count("undo-one") != 0 {
		t.Fatal("the rollback went past the step that failed")
	}
	h.retry(id)
	h.await(id, RunbookRolledBack)
	want := []string{"one", "two", "three", "undo-two", "undo-two", "undo-one"}
	if got := h.script.calls(); !reflect.DeepEqual(got, want) {
		t.Errorf("ran %v, want %v", got, want)
	}
}

func TestRunbookFailingRollbackStepCanBePassedOver(t *testing.T) {
	h := newRBHarness(t, threeSteps, policy.Config{})
	h.script.failNext("three", 1)
	h.script.failNext("undo-two", 1)
	h.run(h.rb)
	id := h.start("rb")
	h.await(id, RunbookFailed)
	h.rollback(id)
	h.await(id, RunbookRollbackFailed)

	h.rollback(id)
	run := h.await(id, RunbookRolledBack)
	if run.Steps[1].Rollback.Status != stepSkipped {
		t.Errorf("rollback of two = %+v", run.Steps[1].Rollback)
	}
	if h.script.count("undo-two") != 1 || h.script.count("undo-one") != 1 {
		t.Errorf("ran %v", h.script.calls())
	}
}

func TestRunbookPromptTimesOut(t *testing.T) {
	h := newRBHarness(t, `id: rb
steps:
  - id: ask
    type: prompt
    message: Anyone there?
    timeout: 30ms
  - id: after
    type: action
    action: {type: script, name: after}
`, policy.Config{})
	h.run(h.rb)
	id := h.start("rb")
	run := h.await(id, RunbookFailed)
	if run.Steps[0].Status != stepFailed || !strings.Contains(run.Steps[0].Error, "no answer") || run.Awaiting != "" {
		t.Fatalf("run = %+v", run)
	}
	if _, err := h.rb.Answer(context.Background(), policy.ActorWeb, "x", id, "ask", "late"); !errors.Is(err, ErrRunbookState) {
		t.Errorf("a late answer: %v", err)
	}
	// A retry asks again, with a new deadline.
	h.retry(id)
	h.await(id, RunbookWaiting)
	h.answer(id, "ask", "here")
	h.await(id, RunbookSucceeded)
	if h.script.count("after") != 1 {
		t.Error("the run did not go on")
	}
}

func TestRunbookSurvivesHubRestartAndContinuesWhereItStopped(t *testing.T) {
	h := newRBHarness(t, `id: rb
steps:
  - id: one
    type: action
    action: {type: script, name: one}
  - id: ask
    type: prompt
    message: Carry on?
  - id: pause
    type: wait
    duration: 150ms
  - id: two
    type: action
    action: {type: script, name: two}
`, policy.Config{})
	stop := h.run(h.rb)
	id := h.start("rb")
	h.await(id, RunbookWaiting)

	// The hub restarts at the prompt: the engine stops, the store closes.
	stop()
	if err := h.st.Close(); err != nil {
		t.Fatal(err)
	}
	h.open()
	stop = h.run(h.rb)
	if run := h.get(id); run.Status != RunbookWaiting || run.Awaiting != "ask" {
		t.Fatalf("after the restart: %+v", run)
	}
	h.answer(id, "ask", "yes")
	eventually(t, "the wait step", func() bool { return h.get(id).Steps[2].Status == stepRunning })

	// And again in the middle of the wait, which keeps its deadline.
	deadline := h.get(id).Steps[2].Deadline
	stop()
	if err := h.st.Close(); err != nil {
		t.Fatal(err)
	}
	h.open()
	h.run(h.rb)
	run := h.await(id, RunbookSucceeded)
	if !run.Steps[2].Deadline.Equal(*deadline) || run.Steps[2].Attempts != 1 {
		t.Errorf("wait step = %+v, deadline was %v", run.Steps[2], deadline)
	}
	if got, want := h.script.calls(), []string{"one", "two"}; !reflect.DeepEqual(got, want) {
		t.Errorf("ran %v, want %v: a completed step was repeated", got, want)
	}
}

func TestRunbookStepInterruptedByTheHubIsNeverRepeatedOnItsOwn(t *testing.T) {
	for _, tc := range []struct {
		name    string
		resolve func(h *rbHarness, id string)
		status  string
		want    []string
	}{
		{"operator retries", func(h *rbHarness, id string) { h.retry(id) }, RunbookSucceeded,
			[]string{"one", "two", "two", "three"}},
		{"operator rolls back", func(h *rbHarness, id string) { h.rollback(id) }, RunbookRolledBack,
			[]string{"one", "two", "undo-two", "undo-one"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newRBHarness(t, threeSteps, policy.Config{})
			gate := h.script.gate("two")
			stop := h.run(h.rb)
			id := h.start("rb")
			eventually(t, "step two running", func() bool { return h.script.count("two") == 1 })

			// The hub dies in the middle of step two.
			stop()
			h.script.mu.Lock()
			delete(h.script.gates, "two")
			h.script.mu.Unlock()
			close(gate)
			if s := h.get(id).Steps[1].Status; s != stepRunning {
				t.Fatalf("after the crash step two is %s", s)
			}

			next := h.engine()
			h.rb = next
			h.run(next)
			run := h.await(id, RunbookUnknown)
			if run.Steps[1].Status != stepUnknown || !strings.Contains(run.Steps[1].Error, "may or may not") {
				t.Fatalf("step two = %+v", run.Steps[1])
			}
			time.Sleep(50 * time.Millisecond)
			if n := h.script.count("two"); n != 1 {
				t.Fatalf("step two ran %d times with no operator asking", n)
			}
			if h.script.count("three") != 0 {
				t.Fatal("the run went past a step of unknown outcome")
			}

			tc.resolve(h, id)
			h.await(id, tc.status)
			if got := h.script.calls(); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("ran %v, want %v", got, tc.want)
			}
		})
	}
}

func TestRunbookInterruptedRollbackStepAsksTheOperator(t *testing.T) {
	h := newRBHarness(t, threeSteps, policy.Config{})
	h.script.failNext("three", 1)
	gate := h.script.gate("undo-two")
	stop := h.run(h.rb)
	id := h.start("rb")
	h.await(id, RunbookFailed)
	h.rollback(id)
	eventually(t, "the rollback step running", func() bool { return h.script.count("undo-two") == 1 })
	stop()
	h.script.mu.Lock()
	delete(h.script.gates, "undo-two")
	h.script.mu.Unlock()
	close(gate)

	h.rb = h.engine()
	h.run(h.rb)
	run := h.await(id, RunbookUnknown)
	if run.Phase != phaseRollback || run.Steps[1].Rollback.Status != stepUnknown {
		t.Fatalf("run = %+v", run)
	}
	time.Sleep(30 * time.Millisecond)
	if h.script.count("undo-two") != 1 {
		t.Fatal("the rollback step was repeated on its own")
	}
	h.retry(id)
	h.await(id, RunbookRolledBack)
	if h.script.count("undo-two") != 2 || h.script.count("undo-one") != 1 {
		t.Errorf("ran %v", h.script.calls())
	}
}

func TestRunbookDeposedLeaderCannotAdvanceARun(t *testing.T) {
	h := newRBHarness(t, threeSteps, policy.Config{})
	gate := h.script.gate("two")
	old := h.rb
	h.run(old)
	id := h.start("rb")
	eventually(t, "step two running", func() bool { return h.script.count("two") == 1 })

	// A new leader takes over while the old one still works on step two.
	next := h.engine()
	h.rb = next
	h.run(next)
	h.await(id, RunbookUnknown)

	// The old leader finishes the step: its write must not count.
	close(gate)
	time.Sleep(50 * time.Millisecond)
	run := h.get(id)
	if run.Status != RunbookUnknown || run.Steps[1].Status != stepUnknown || run.Cursor != 1 {
		t.Fatalf("the deposed leader changed the run: %+v", run)
	}
	if h.script.count("three") != 0 || h.script.count("two") != 1 {
		t.Errorf("ran %v", h.script.calls())
	}
}

func TestRunbookStaleOperatorWriteIsRefused(t *testing.T) {
	h := newRBHarness(t, threeSteps, policy.Config{})
	h.script.failNext("two", 1)
	h.run(h.rb)
	id := h.start("rb")
	h.await(id, RunbookFailed)
	stale, err := h.st.RunbookRuns().Get(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	h.retry(id)
	h.await(id, RunbookSucceeded)
	if _, err := h.st.RunbookRuns().Save(context.Background(), stale); !errors.Is(err, store.ErrRunbookRunConflict) {
		t.Errorf("saving from an old version: %v", err)
	}
}

func TestRunbookDeniedStepNeverExecutesAndFailsTheRun(t *testing.T) {
	yaml := `id: rb
steps:
  - id: risky
    type: action
    action: {type: script, name: risky, policy: automation.exec}
  - id: after
    type: action
    action: {type: script, name: after}
`
	h := newRBHarness(t, yaml, policy.Config{})
	h.run(h.rb)
	id := h.start("rb")
	run := h.await(id, RunbookFailed)
	if run.Steps[0].Status != stepDenied || !strings.Contains(run.Steps[0].Error, "denied by policy") {
		t.Fatalf("step = %+v", run.Steps[0])
	}
	if n := len(h.script.calls()); n != 0 {
		t.Fatalf("%d actions ran", n)
	}
	entries := h.audited(policy.AutomationExec)
	if len(entries) != 1 || entries[0].Decision != policy.Deny || entries[0].ActorID != "runbook/rb" {
		t.Fatalf("audit = %+v", entries)
	}
	// A retry is decided again, and denied again.
	h.retry(id)
	eventually(t, "the second denial", func() bool { return len(h.audited(policy.AutomationExec)) == 2 })
	h.await(id, RunbookFailed)
	if n := len(h.script.calls()); n != 0 {
		t.Fatalf("%d actions ran on the retry", n)
	}
}

func TestRunbookDeniedRollbackStepNeverExecutes(t *testing.T) {
	h := newRBHarness(t, `id: rb
steps:
  - id: one
    type: action
    action: {type: script, name: one}
    rollback: {type: script, name: undo-one, policy: automation.exec}
  - id: two
    type: action
    action: {type: script, name: two}
`, policy.Config{})
	h.script.failNext("two", 1)
	h.run(h.rb)
	id := h.start("rb")
	h.await(id, RunbookFailed)
	h.rollback(id)
	run := h.await(id, RunbookRollbackFailed)
	if run.Steps[0].Rollback.Status != stepDenied {
		t.Fatalf("rollback = %+v", run.Steps[0].Rollback)
	}
	if h.script.count("undo-one") != 0 {
		t.Error("a denied rollback step ran")
	}
	if e := h.audited(policy.AutomationExec); len(e) != 1 || e[0].Decision != policy.Deny {
		t.Errorf("audit = %+v", e)
	}
}

func TestRunbookDoesNotInheritAnAutomationsGrant(t *testing.T) {
	yaml := `id: rb
steps:
  - id: risky
    type: action
    action: {type: script, name: risky, policy: automation.exec}
`
	for _, tc := range []struct {
		name   string
		grants []string
		status string
		ran    int
	}{
		{"granted to the automation of the same id", []string{"rb"}, RunbookFailed, 0},
		{"granted to the runbook", []string{"runbook/rb"}, RunbookSucceeded, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newRBHarness(t, yaml, policy.Config{DangerousAutomations: tc.grants})
			h.run(h.rb)
			h.await(h.start("rb"), tc.status)
			if n := len(h.script.calls()); n != tc.ran {
				t.Errorf("ran %d actions, want %d", n, tc.ran)
			}
		})
	}
}

func TestRunbookOperatorsAreAudited(t *testing.T) {
	h := newRBHarness(t, `id: rb
steps:
  - id: ask
    type: prompt
    message: Name?
`, policy.Config{})
	h.run(h.rb)
	id := h.start("rb")
	h.await(id, RunbookWaiting)
	h.answer(id, "ask", "the-answer-value")
	h.await(id, RunbookSucceeded)

	for _, action := range []policy.Action{policy.RunbookStart, policy.RunbookAnswer} {
		e := h.audited(action)
		if len(e) != 1 || e[0].ActorKind != policy.ActorWeb || e[0].ActorID != "10.0.0.9" || e[0].Decision != policy.Allow {
			t.Errorf("%s audit = %+v", action, e)
		}
	}
	if b, _ := json.Marshal(h.audit.all()); bytes.Contains(b, []byte("the-answer-value")) {
		t.Error("the audit log holds a prompt's answer")
	}
	if got := h.get(id).StartedBy; got != "web/10.0.0.9" {
		t.Errorf("started by %q", got)
	}
}

// bodyServer records the requests a webhook sends.
type bodyServer struct {
	*httptest.Server
	mu     sync.Mutex
	bodies []string
}

func newBodyServer(t *testing.T) *bodyServer {
	t.Helper()
	b := &bodyServer{}
	b.Server = httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		b.mu.Lock()
		defer b.mu.Unlock()
		b.bodies = append(b.bodies, string(body))
	}))
	t.Cleanup(b.Close)
	return b
}

func (b *bodyServer) got() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return slices.Clone(b.bodies)
}

func TestRunbookInputIsDataAndIsNeverParsed(t *testing.T) {
	srv := newBodyServer(t)
	h := newRBHarness(t, fmt.Sprintf(`id: rb
steps:
  - id: note
    type: prompt
    message: A note?
  - id: tell
    type: action
    action:
      type: webhook
      url: %s/hook
      body: "note={{ .Input.note }}"
`, srv.URL), policy.Config{})
	h.run(h.rb)
	id := h.start("rb")
	h.await(id, RunbookWaiting)

	hostile := `{{ .Trigger.ID }}; rm -rf / $(reboot) ` + "`id`"
	h.answer(id, "note", hostile)
	h.await(id, RunbookSucceeded)
	if got := srv.got(); len(got) != 1 || got[0] != "note="+hostile {
		t.Errorf("webhook got %q", got)
	}
}

func TestRunbookCommandsAreNotTemplates(t *testing.T) {
	agents := &recordingAgents{}
	h := newRBHarness(t, `id: rb
steps:
  - id: note
    type: prompt
    message: A note?
  - id: run
    type: action
    action: {type: exec, device: pi4, command: [/bin/echo, "{{ .Input.note }}"]}
`, policy.Config{DangerousAutomations: []string{"runbook/rb"}})
	maps.Copy(h.kinds.Actions, Actions(ActionDeps{Agents: agents}))
	h.rb = h.engine()
	h.run(h.rb)
	id := h.start("rb")
	h.await(id, RunbookWaiting)
	h.answer(id, "note", "$(reboot)")
	h.await(id, RunbookSucceeded)
	want := []string{"/bin/echo", "{{ .Input.note }}"}
	if got := agents.lastArgv(); !reflect.DeepEqual(got, want) {
		t.Errorf("argv = %q, want %q: an answer reached a command", got, want)
	}
}

func TestRunbookSecretIsNeverStoredLoggedOrShown(t *testing.T) {
	const secret = "hunter2-very-secret"
	srv := newBodyServer(t)
	h := newRBHarness(t, fmt.Sprintf(`id: rb
steps:
  - id: token
    type: prompt
    message: The token?
    secret: true
  - id: use
    type: action
    action:
      type: webhook
      url: %s/hook
      headers: {Authorization: "Bearer {{ .Input.token }}"}
      body: "t={{ .Input.token }}"
`, srv.URL), policy.Config{})
	h.run(h.rb)
	id := h.start("rb")
	h.await(id, RunbookWaiting)
	h.answer(id, "token", secret)
	run := h.await(id, RunbookSucceeded)
	if got := srv.got(); len(got) != 1 || got[0] != "t="+secret {
		t.Fatalf("webhook got %q", got)
	}

	stored, err := h.st.RunbookRuns().Get(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	view, _ := json.Marshal(run)
	audit, _ := json.Marshal(h.audit.all())
	for what, b := range map[string][]byte{"state": stored.State, "source": stored.Source, "API": view, "audit": audit} {
		if bytes.Contains(b, []byte(secret)) {
			t.Errorf("the secret is in the %s", what)
		}
	}
	if len(h.rb.secretsOf(id)) != 0 {
		t.Error("the hub still holds the secret of a finished run")
	}
}

func TestRunbookSecretIsAskedAgainAfterARestart(t *testing.T) {
	const first, second = "first-secret-value", "second-secret-value"
	srv := newBodyServer(t)
	h := newRBHarness(t, fmt.Sprintf(`id: rb
steps:
  - id: token
    type: prompt
    message: The token?
    secret: true
  - id: pause
    type: prompt
    prompt: confirm
    message: Carry on?
  - id: use
    type: action
    action: {type: webhook, url: %s/hook, body: "t={{ .Input.token }}"}
`, srv.URL), policy.Config{})
	stop := h.run(h.rb)
	id := h.start("rb")
	h.await(id, RunbookWaiting)
	h.answer(id, "token", first)
	eventually(t, "the second prompt", func() bool { return h.get(id).Awaiting == "pause" })

	stop()
	h.rb = h.engine()
	h.run(h.rb)
	h.answer(id, "pause", ConfirmYes)

	// The answer is gone: the run asks for it rather than send nothing.
	eventually(t, "the secret asked for again", func() bool {
		run := h.get(id)
		return run.Status == RunbookWaiting && run.Awaiting == "token"
	})
	if got := srv.got(); len(got) != 0 {
		t.Fatalf("webhook sent without its secret: %q", got)
	}
	h.answer(id, "token", second)
	h.await(id, RunbookSucceeded)
	if got := srv.got(); len(got) != 1 || got[0] != "t="+second {
		t.Errorf("webhook got %q", got)
	}
}

func TestRunbookSecretAnswerNeedsTheLeader(t *testing.T) {
	h := newRBHarness(t, `id: rb
steps:
  - id: token
    type: prompt
    message: The token?
    secret: true
`, policy.Config{})
	h.run(h.rb)
	id := h.start("rb")
	h.await(id, RunbookWaiting)

	follower := h.engine() // never Run: it is not leading
	_, err := follower.Answer(context.Background(), policy.ActorWeb, "x", id, "token", "s3cret")
	if !errors.Is(err, ErrRunbookNotLeading) {
		t.Fatalf("err = %v", err)
	}
	if run := h.get(id); run.Status != RunbookWaiting || run.Awaiting != "token" {
		t.Errorf("run = %+v", run)
	}
}

func TestRunbookSecretIsScrubbedFromErrors(t *testing.T) {
	err := fmt.Errorf("oops: %w", policy.ErrDenied)
	wrapped := fmt.Errorf("sent tok3n and failed: %w", err)
	got := scrubSecrets(wrapped, map[string]string{"t": "tok3n"})
	if strings.Contains(got.Error(), "tok3n") {
		t.Errorf("error = %q", got)
	}
	if !errors.Is(got, policy.ErrDenied) {
		t.Error("scrubbing lost what the error wraps")
	}
}

func TestRunbookKeepsTheDefinitionItStartedFrom(t *testing.T) {
	h := newRBHarness(t, threeSteps, policy.Config{})
	gate := h.script.gate("one")
	h.run(h.rb)
	id := h.start("rb")
	eventually(t, "step one running", func() bool { return h.script.count("one") == 1 })

	h.write("rb.yaml", `id: rb
steps:
  - id: other
    type: action
    action: {type: script, name: other}
`)
	close(gate)
	h.await(id, RunbookSucceeded)
	if got, want := h.script.calls(), []string{"one", "two", "three"}; !reflect.DeepEqual(got, want) {
		t.Errorf("ran %v, want %v", got, want)
	}
	stored, err := h.st.RunbookRuns().Get(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(stored.Source, []byte("undo-one")) {
		t.Error("the run's copy of the file is not sealed")
	}
}

func TestRunbookDryRunExecutesNothing(t *testing.T) {
	h := newRBHarness(t, threeSteps, policy.Config{})
	e := h.engine()
	e.cfg.DryRun = true
	h.rb = e
	h.run(e)
	h.await(h.start("rb"), RunbookSucceeded)
	if n := len(h.script.calls()); n != 0 {
		t.Errorf("a dry run ran %d actions", n)
	}
	if e := h.audited(policy.AutomationRestart); len(e) != 3 || e[0].Result != policy.DryRun {
		t.Errorf("audit = %+v", e)
	}
}

func TestParseRunbookRejects(t *testing.T) {
	kinds := Builtin(slog.New(slog.DiscardHandler))
	maps.Copy(kinds.Actions, Actions(ActionDeps{}))
	head := "id: rb\nsteps:\n"
	for _, tc := range []struct {
		name, yaml, want string
	}{
		{"no steps", "id: rb\nsteps: []\n", "at least one step"},
		{"bad id", "id: Bad!\nsteps:\n  - {type: wait, duration: 1s}\n", "id \"Bad!\""},
		{"unknown step type", head + "  - {type: dance}\n", `step type "dance"`},
		{"duplicate step id", head + "  - {id: a, type: wait, duration: 1s}\n  - {id: a, type: wait, duration: 1s}\n", "already used"},
		{"field of another type", head + "  - {type: wait, duration: 1s, message: hi}\n", `no field "message"`},
		{"wait without duration", head + "  - {type: wait}\n", "duration must be"},
		{"prompt without message", head + "  - {type: prompt}\n", "needs a message"},
		{"secret confirm", head + "  - {type: prompt, prompt: confirm, secret: true, message: hi}\n", "cannot be secret"},
		{"action without action", head + "  - {type: action}\n", "needs action"},
		{"check from a device", head + "  - {type: check, check: {type: tcp, address: 'a:1', from: pi}}\n", "from is not supported"},
		{
			"input in a device field",
			head + "  - {id: a, type: prompt, message: hi}\n" +
				"  - {type: action, action: {type: restart, device: '{{ .Input.a }}', service: 'docker:x'}}\n",
			"cannot use them",
		},
		{
			"input in a kube field",
			head + "  - {id: a, type: prompt, message: hi}\n" +
				"  - {type: action, action: {type: kube_cordon, cluster: lab, node: '{{ .Input.a }}'}}\n",
			"cannot use them",
		},
		{
			"secret in a log line",
			head + "  - {id: a, type: prompt, message: hi, secret: true}\n" +
				"  - {type: action, action: {type: log, message: '{{ .Input.a }}'}}\n",
			"secret one can only be used",
		},
		{
			"input from a later prompt",
			head + "  - {type: action, action: {type: log, message: '{{ .Input.a }}'}}\n" +
				"  - {id: a, type: prompt, message: hi}\n",
			"earlier prompt",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseRunbook("t.yaml", []byte(tc.yaml), kinds)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}

func TestLoadRunbooksLeavesOutInvalidFiles(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"a.yaml":  "id: good\nsteps:\n  - {type: wait, duration: 1s}\n",
		"b.yaml":  "id: broken\n",
		"c.yml":   "id: good\nsteps:\n  - {type: wait, duration: 1s}\n",
		"d.txt":   "ignored",
		".h.yaml": "ignored",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	got, errs := LoadRunbooks(dir, Builtin(slog.New(slog.DiscardHandler)))
	if len(got) != 1 || got[0].ID != "good" {
		t.Errorf("runbooks = %+v", got)
	}
	if len(errs) != 2 {
		t.Errorf("errors = %v", errs)
	}
	if got, errs := LoadRunbooks(filepath.Join(dir, "missing"), Kinds{}); len(got) != 0 || len(errs) != 0 {
		t.Errorf("a missing dir: %v, %v", got, errs)
	}
}

// recordingAgents stands in for the hub's agents.
type recordingAgents struct {
	ceiling error

	mu   sync.Mutex
	argv [][]string
}

func (a *recordingAgents) Check(context.Context, string, *agentv1.ExecRequest) error {
	return a.ceiling
}

func (a *recordingAgents) Exec(_ context.Context, _ string, req *agentv1.ExecRequest) (*agentv1.ExecResult, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.argv = append(a.argv, req.GetCommand().GetArgv())
	return &agentv1.ExecResult{}, nil
}

func (a *recordingAgents) execs() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.argv)
}

func (a *recordingAgents) lastArgv() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.argv) == 0 {
		return nil
	}
	return a.argv[len(a.argv)-1]
}
