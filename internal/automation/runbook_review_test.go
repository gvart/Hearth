// SPDX-License-Identifier: AGPL-3.0-only

package automation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/policy"
	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
	"github.com/gvart/hearth/internal/store"
)

// TestRunbookSecretUsedThroughIndexIsAskedAgain: a hyphenated step id can only
// be read with index, which gives "" for an absent answer rather than an error.
func TestRunbookSecretUsedThroughIndexIsAskedAgain(t *testing.T) {
	const first, second = "first-secret-value", "second-secret-value"
	srv := newBodyServer(t)
	h := newRBHarness(t, fmt.Sprintf(`id: rb
steps:
  - id: api-token
    type: prompt
    message: The token?
    secret: true
  - id: pause
    type: prompt
    prompt: confirm
    message: Carry on?
  - id: use
    type: action
    action: {type: webhook, url: %s/hook, body: 't=[{{ index .Input "api-token" }}]'}
`, srv.URL), policy.Config{})
	stop := h.run(h.rb)
	id := h.start("rb")
	h.await(id, RunbookWaiting)
	h.answer(id, "api-token", first)
	eventually(t, "the second prompt", func() bool { return h.get(id).Awaiting == "pause" })

	stop()
	h.rb = h.engine()
	h.run(h.rb)
	h.answer(id, "pause", ConfirmYes)

	eventually(t, "the secret asked for again", func() bool {
		run := h.get(id)
		return run.Awaiting == "api-token" || runbookFinished(run.Status)
	})
	if got := srv.got(); len(got) != 0 {
		t.Fatalf("webhook sent without its secret: %q", got)
	}
	h.answer(id, "api-token", second)
	h.await(id, RunbookSucceeded)
	if got := srv.got(); len(got) != 1 || got[0] != "t=["+second+"]" {
		t.Errorf("webhook got %q", got)
	}
}

func TestParseRunbookRejectsAnswersOutOfReach(t *testing.T) {
	h := newRBHarness(t, "id: rb\nsteps:\n  - {id: w, type: wait, duration: 1ms}\n", policy.Config{})
	for _, tc := range []struct{ name, yaml, want string }{
		{"a later prompt through index", `id: rb
steps:
  - id: early
    type: action
    action: {type: log, message: '{{ index .Input "later-one" }}'}
  - id: later-one
    type: prompt
    message: Later?
`, "earlier prompt"},
		{"a later prompt only tested for being there", `id: rb
steps:
  - id: early
    type: action
    action: {type: log, message: '{{ if index .Input "later-one" }}yes{{ end }}'}
  - id: later-one
    type: prompt
    message: Later?
`, "earlier prompt"},
		{"a secret in a log line through index", `id: rb
steps:
  - id: api-token
    type: prompt
    message: Token?
    secret: true
  - id: note
    type: action
    action: {type: log, message: '{{ index .Input "api-token" }}'}
`, "secret"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseRunbook("rb.yaml", []byte(tc.yaml), h.kinds)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}

// TestRunbookOperatorsObeyTheHubsPolicy: a policy file that denies safe web
// actions stops retrying and rolling back too.
func TestRunbookOperatorsObeyTheHubsPolicy(t *testing.T) {
	h := newRBHarness(t, threeSteps, policy.Config{})
	h.script.failNext("three", 1)
	stop := h.run(h.rb)
	id := h.start("rb")
	h.await(id, RunbookFailed)
	stop()

	h.cfg = policy.Config{Actors: map[string]map[policy.Class]policy.Mode{policy.ActorWeb: {policy.Safe: policy.ModeDeny}}}
	h.rb = h.engine()
	h.run(h.rb)
	version := runVersion(t, h, id)
	if _, err := h.rb.Retry(t.Context(), policy.ActorWeb, "10.0.0.9", id, version); !errors.Is(err, policy.ErrDenied) {
		t.Errorf("retry = %v, want denied", err)
	}
	if _, err := h.rb.Rollback(t.Context(), policy.ActorWeb, "10.0.0.9", id, version); !errors.Is(err, policy.ErrDenied) {
		t.Errorf("rollback = %v, want denied", err)
	}
	if got := h.get(id).Status; got != RunbookFailed {
		t.Errorf("status = %s, want it unchanged", got)
	}
}

// countingRuns counts reads and saves, and fails saves while failing is set.
type countingRuns struct {
	RunbookStore
	gets, saves atomic.Int64
	failing     atomic.Bool
}

func (c *countingRuns) Get(ctx context.Context, id string) (store.RunbookRun, error) {
	c.gets.Add(1)
	return c.RunbookStore.Get(ctx, id)
}

func (c *countingRuns) Save(ctx context.Context, run store.RunbookRun) (int64, error) {
	c.saves.Add(1)
	if c.failing.Load() {
		return 0, errors.New("the store is unavailable")
	}
	return c.RunbookStore.Save(ctx, run)
}

// engineOver is the harness's engine over runs.
func (h *rbHarness) engineOver(runs RunbookStore, poll time.Duration) *Runbooks {
	return NewRunbooks(RunbooksConfig{
		Dir: h.dir, Kinds: h.kinds, Policy: policy.NewWithConfig(h.audit, nil, h.cfg),
		Runs: runs, Sealer: xorSealer{}, Poll: poll,
	})
}

func TestRunbookEngineWaitsForTheNextTickWhenItCannotProgress(t *testing.T) {
	const poll, watch = 100 * time.Millisecond, 450 * time.Millisecond
	const most = 8 // one attempt a tick, and some slack

	t.Run("a run that cannot be saved", func(t *testing.T) {
		h := newRBHarness(t, threeSteps, policy.Config{})
		runs := &countingRuns{RunbookStore: h.st.RunbookRuns()}
		runs.failing.Store(true)
		e := h.engineOver(runs, poll)
		h.rb = e
		if err := h.st.RunbookRuns().Create(t.Context(), startedRun(t, e)); err != nil {
			t.Fatal(err)
		}
		h.run(e)
		time.Sleep(watch)
		if n := runs.saves.Load(); n > most {
			t.Errorf("%d attempts to save in %s, want at most %d", n, watch, most)
		}
	})

	t.Run("a run whose state cannot be decoded", func(t *testing.T) {
		h := newRBHarness(t, threeSteps, policy.Config{})
		runs := &countingRuns{RunbookStore: h.st.RunbookRuns()}
		now := time.Now()
		if err := h.st.RunbookRuns().Create(t.Context(), store.RunbookRun{
			ID: "broken", RunbookID: "rb", Status: RunbookRunning, StartedBy: "web/x", StartedAt: now, UpdatedAt: now,
			Source: []byte("x"), State: []byte(`[1]`),
		}); err != nil {
			t.Fatal(err)
		}
		h.run(h.engineOver(runs, poll))
		time.Sleep(watch)
		if n := runs.gets.Load(); n > most {
			t.Errorf("%d reads in %s, want at most %d", n, watch, most)
		}
	})
}

// runVersion is the version a run is stored at now.
func runVersion(t *testing.T, h *rbHarness, id string) int64 {
	t.Helper()
	run, err := h.st.RunbookRuns().Get(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	return run.Version
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// startedRun is a stored run of rb that no engine has picked up yet.
func startedRun(t *testing.T, e *Runbooks) store.RunbookRun {
	t.Helper()
	rb, err := e.find("rb")
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := xorSealer{}.Seal(runbookSealID("stuck"), rb.source)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	return store.RunbookRun{
		ID: "stuck", RunbookID: "rb", Status: RunbookRunning, StartedBy: "web/x", StartedAt: now, UpdatedAt: now,
		Source: sealed, State: mustJSON(t, newRunbookState(rb)),
	}
}

// TestRunbookRepeatedRollbackDoesNotPassOverAFailedStep: the same request sent
// twice must not turn into skipping the rollback step that failed.
func TestRunbookRepeatedRollbackDoesNotPassOverAFailedStep(t *testing.T) {
	h := newRBHarness(t, threeSteps, policy.Config{})
	h.script.failNext("three", 1)
	h.script.failNext("undo-two", 1)
	h.run(h.rb)
	id := h.start("rb")
	h.await(id, RunbookFailed)
	version := runVersion(t, h, id)
	if _, err := h.rb.Rollback(t.Context(), policy.ActorWeb, "10.0.0.9", id, version); err != nil {
		t.Fatal(err)
	}
	h.await(id, RunbookRollbackFailed)

	for _, v := range []int64{version, runVersion(t, h, id)} {
		if _, err := h.rb.Rollback(t.Context(), policy.ActorWeb, "10.0.0.9", id, v); !errors.Is(err, ErrRunbookState) {
			t.Errorf("rollback from version %d = %v, want ErrRunbookState", v, err)
		}
	}
	run := h.get(id)
	if run.Status != RunbookRollbackFailed || run.Steps[1].Rollback.Status != stepFailed {
		t.Fatalf("after the repeats: %s, rollback of two %+v", run.Status, run.Steps[1].Rollback)
	}
	if !run.CanPassOver || run.CanRollback {
		t.Errorf("can pass over %v, can roll back %v", run.CanPassOver, run.CanRollback)
	}

	// A stale pass-over is refused too; the current one is audited as such.
	if _, err := h.rb.PassOver(t.Context(), policy.ActorWeb, "10.0.0.9", id, version); !errors.Is(err, ErrRunbookState) {
		t.Errorf("stale pass-over = %v, want ErrRunbookState", err)
	}
	if _, err := h.rb.PassOver(t.Context(), policy.ActorWeb, "10.0.0.9", id, runVersion(t, h, id)); err != nil {
		t.Fatal(err)
	}
	h.await(id, RunbookRolledBack)
	var ok int
	for _, e := range h.audited(policy.RunbookPassOver) {
		if e.ActorID == "10.0.0.9" && e.Result == "ok" {
			ok++
		}
	}
	if ok != 1 {
		t.Errorf("%d successful pass-overs audited, want 1", ok)
	}
}

func TestRunbookStaleRetryIsRefused(t *testing.T) {
	h := newRBHarness(t, threeSteps, policy.Config{})
	h.script.failNext("three", 2)
	h.run(h.rb)
	id := h.start("rb")
	h.await(id, RunbookFailed)
	stale := runVersion(t, h, id)
	h.retry(id)
	eventually(t, "the second failure", func() bool { return h.get(id).Steps[2].Attempts == 2 && h.get(id).Status == RunbookFailed })
	if _, err := h.rb.Retry(t.Context(), policy.ActorWeb, "10.0.0.9", id, stale); !errors.Is(err, ErrRunbookState) {
		t.Errorf("stale retry = %v, want ErrRunbookState", err)
	}
	if n := h.script.count("three"); n != 2 {
		t.Errorf("step three ran %d times, want 2", n)
	}
}

func TestRunbookStoppedRunForgetsItsSecrets(t *testing.T) {
	const first, second = "first-secret-value", "second-secret-value"
	var failing atomic.Bool
	failing.Store(true)
	bodies := make(chan string, 4)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b := make([]byte, 128)
		n, _ := r.Body.Read(b)
		bodies <- string(b[:n])
		if failing.Load() {
			w.WriteHeader(http.StatusBadGateway)
		}
	}))
	defer srv.Close()
	h := newRBHarness(t, fmt.Sprintf(`id: rb
steps:
  - id: token
    type: prompt
    message: The token?
    secret: true
  - id: use
    type: action
    action: {type: webhook, url: %s/hook, body: "t={{ .Input.token }}"}
`, srv.URL), policy.Config{})
	h.run(h.rb)
	id := h.start("rb")
	h.await(id, RunbookWaiting)
	h.answer(id, "token", first)
	h.await(id, RunbookFailed)
	<-bodies
	if got := h.rb.secretsOf(id); len(got) != 0 {
		t.Fatalf("the stopped run still holds %d secret answers", len(got))
	}

	failing.Store(false)
	h.retry(id)
	eventually(t, "the secret asked for again", func() bool { return h.get(id).Awaiting == "token" })
	h.answer(id, "token", second)
	h.await(id, RunbookSucceeded)
	if got := <-bodies; got != "t="+second {
		t.Errorf("webhook got %q", got)
	}
}

// staleRuns answers Get with an old copy of one run while stale is set, as a
// second request that read the run before the first was saved would see it.
type staleRuns struct {
	RunbookStore
	mu    sync.Mutex
	stale *store.RunbookRun
}

func (s *staleRuns) Get(ctx context.Context, id string) (store.RunbookRun, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stale != nil && s.stale.ID == id {
		return *s.stale, nil
	}
	return s.RunbookStore.Get(ctx, id)
}

func TestRunbookDuplicateSecretKeepsTheAcceptedAnswer(t *testing.T) {
	const accepted, duplicate = "accepted-secret", "duplicate-secret"
	h := newRBHarness(t, `id: rb
steps:
  - id: token
    type: prompt
    message: The token?
    secret: true
  - id: pause
    type: prompt
    prompt: confirm
    message: Carry on?
`, policy.Config{})
	runs := &staleRuns{RunbookStore: h.st.RunbookRuns()}
	h.rb = h.engineOver(runs, 5*time.Millisecond)
	h.run(h.rb)
	id := h.start("rb")
	h.await(id, RunbookWaiting)
	before, err := h.st.RunbookRuns().Get(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	h.answer(id, "token", accepted)
	eventually(t, "the second prompt", func() bool { return h.get(id).Awaiting == "pause" })

	runs.mu.Lock()
	runs.stale = &before
	runs.mu.Unlock()
	_, err = h.rb.Answer(t.Context(), policy.ActorWeb, "10.0.0.9", id, "token", duplicate)
	runs.mu.Lock()
	runs.stale = nil
	runs.mu.Unlock()
	if !errors.Is(err, store.ErrRunbookRunConflict) {
		t.Fatalf("duplicate answer = %v, want a conflict", err)
	}
	if got := h.rb.secretsOf(id)["token"]; got != accepted {
		t.Errorf("the secret held is %q, want the accepted answer", got)
	}
}

func TestRunbookCheckStepGoesThroughPolicy(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	defer srv.Close()
	yaml := fmt.Sprintf(`id: rb
steps:
  - id: healthy
    type: check
    check: {type: http, url: %s/health}
`, srv.URL)
	const action = policy.Action("runbook.check")

	t.Run("allowed: one decision and one audit entry", func(t *testing.T) {
		h := newRBHarness(t, yaml, policy.Config{})
		h.run(h.rb)
		h.await(h.start("rb"), RunbookSucceeded)
		got := h.audited(action)
		if len(got) != 1 || got[0].Decision != policy.Allow || got[0].ActorID != RunbookActor("rb") || got[0].Result != "ok" {
			t.Errorf("audit = %+v", got)
		}
		plan, err := h.rb.Plan(t.Context(), "rb")
		if err != nil {
			t.Fatal(err)
		}
		if s := plan.Steps[0]; s.Action != string(action) || s.Class != string(policy.Read) || s.Decision != policy.Allow {
			t.Errorf("plan = %+v", s)
		}
	})

	t.Run("denied: nothing reaches the network", func(t *testing.T) {
		hits.Store(0)
		cfg := policy.Config{Actors: map[string]map[policy.Class]policy.Mode{policy.ActorAutomation: {policy.Read: policy.ModeDeny}}}
		h := newRBHarness(t, yaml, cfg)
		h.run(h.rb)
		run := h.await(h.start("rb"), RunbookFailed)
		if run.Steps[0].Status != stepDenied {
			t.Errorf("step = %+v", run.Steps[0])
		}
		if n := hits.Load(); n != 0 {
			t.Errorf("the denied check reached the network %d times", n)
		}
		if got := h.audited(action); len(got) != 1 || got[0].Decision != policy.Deny {
			t.Errorf("audit = %+v", got)
		}
	})
}

// outcomeServers are webhooks that end a request in the ways that matter.
func outcomeServers(t *testing.T) map[string]string {
	t.Helper()
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/hang":
			select {
			case <-release:
			case <-r.Context().Done():
			}
		case "/drop":
			c, _, err := w.(http.Hijacker).Hijack() //nolint:forcetypeassert // the test server's writer hijacks
			if err == nil {
				_ = c.Close()
			}
		case "/refuse":
			w.WriteHeader(http.StatusBadGateway)
		}
	}))
	t.Cleanup(func() {
		close(release)
		srv.Close()
	})
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := "http://" + ln.Addr().String()
	_ = ln.Close()
	return map[string]string{
		"hang": srv.URL + "/hang", "drop": srv.URL + "/drop", "refuse": srv.URL + "/refuse", "closed": closed + "/x", "ok": srv.URL + "/ok",
	}
}

func TestRunbookUncertainOutcomeIsLeftToTheOperator(t *testing.T) {
	urls := outcomeServers(t)
	for _, tc := range []struct {
		name, url, status, step string
	}{
		{"a timeout", urls["hang"], RunbookUnknown, stepUnknown},
		{"a connection lost after sending", urls["drop"], RunbookUnknown, stepUnknown},
		{"a refusal by the target", urls["refuse"], RunbookFailed, stepFailed},
		{"a target that cannot be reached", urls["closed"], RunbookFailed, stepFailed},
	} {
		t.Run("step: "+tc.name, func(t *testing.T) {
			h := newRBHarness(t, fmt.Sprintf(`id: rb
steps:
  - id: call
    type: action
    action: {type: webhook, url: %s, timeout: 100ms}
`, tc.url), policy.Config{})
			h.run(h.rb)
			run := h.await(h.start("rb"), tc.status)
			if run.Steps[0].Status != tc.step {
				t.Errorf("step = %+v, want %s", run.Steps[0], tc.step)
			}
			if !run.CanRetry || !run.CanRollback {
				t.Errorf("the operator cannot decide: %+v", run)
			}
		})
		t.Run("rollback: "+tc.name, func(t *testing.T) {
			h := newRBHarness(t, fmt.Sprintf(`id: rb
steps:
  - id: call
    type: action
    action: {type: webhook, url: %s}
    rollback: {type: webhook, url: %s, timeout: 100ms}
  - id: bad
    type: action
    action: {type: script, name: bad}
`, urls["ok"], tc.url), policy.Config{})
			h.script.failNext("bad", 1)
			h.run(h.rb)
			id := h.start("rb")
			h.await(id, RunbookFailed)
			h.rollback(id)
			want := RunbookRollbackFailed
			if tc.status == RunbookUnknown {
				want = RunbookUnknown
			}
			run := h.await(id, want)
			if got := run.Steps[0].Rollback.Status; got != tc.step {
				t.Errorf("rollback = %s, want %s", got, tc.step)
			}
		})
	}
}

// TestRunbookCheckTimeoutIsAFailure: a check changes nothing, so a timeout
// leaves nothing uncertain.
func TestRunbookCheckTimeoutIsAFailure(t *testing.T) {
	urls := outcomeServers(t)
	h := newRBHarness(t, fmt.Sprintf(`id: rb
steps:
  - id: healthy
    type: check
    check: {type: http, url: %s, timeout: 50ms}
`, urls["hang"]), policy.Config{})
	h.run(h.rb)
	h.await(h.start("rb"), RunbookFailed)
}

// scriptedAgents answers every request the same way.
type scriptedAgents struct {
	res *agentv1.ExecResult
	err error
}

func (a scriptedAgents) Exec(context.Context, string, *agentv1.ExecRequest) (*agentv1.ExecResult, error) {
	return a.res, a.err
}

// TestRunbookDeviceCommandOutcome: an agent reports a command it had to stop
// as text, and that command may have done part of its work.
func TestRunbookDeviceCommandOutcome(t *testing.T) {
	const yaml = `id: rb
steps:
  - id: run
    type: action
    action: {type: exec, device: pi, command: [/usr/bin/true]}
`
	for _, tc := range []struct {
		name      string
		agents    scriptedAgents
		uncertain bool
	}{
		{"stopped at its timeout", scriptedAgents{res: &agentv1.ExecResult{ExitCode: -1, Error: "context deadline exceeded after 30s: half done"}}, true},
		{"stopped as the agent shut down", scriptedAgents{res: &agentv1.ExecResult{ExitCode: -1, Error: "context canceled after 30s"}}, true},
		{"the agent went away", scriptedAgents{err: fmt.Errorf("device pi: %w", ErrOutcomeUnknown)}, true},
		{"no answer in time", scriptedAgents{err: context.DeadlineExceeded}, true},
		{"a command that failed", scriptedAgents{res: &agentv1.ExecResult{ExitCode: 1, Error: "exit status 1: context deadline exceeded after a while"}}, false},
		{"refused by the agent", scriptedAgents{res: &agentv1.ExecResult{Denied: true, Error: "beyond the ceiling"}}, false},
		{"never sent", scriptedAgents{err: errors.New("agent not connected")}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rb, err := ParseRunbook("rb.yaml", []byte(yaml), actionKinds(ActionDeps{Agents: tc.agents}))
			if err != nil {
				t.Fatal(err)
			}
			runErr := rb.Steps[0].Action.Impl.Run(t.Context(), Event{})
			if runErr == nil {
				t.Fatal("the action succeeded")
			}
			if got := outcomeUncertain(runErr); got != tc.uncertain {
				t.Errorf("outcomeUncertain(%v) = %v, want %v", runErr, got, tc.uncertain)
			}
		})
	}
}

// TestRunbookUncertainOutcomeSurvivesSecretScrubbing: taking a secret out of an
// error's text must not lose what kind of error it was.
func TestRunbookUncertainOutcomeSurvivesSecretScrubbing(t *testing.T) {
	const secret = "the-secret-answer"
	urls := outcomeServers(t)
	h := newRBHarness(t, fmt.Sprintf(`id: rb
steps:
  - id: token
    type: prompt
    message: The token?
    secret: true
  - id: call
    type: action
    action: {type: webhook, url: %s, body: "t={{ .Input.token }}", timeout: 100ms}
`, urls["hang"]), policy.Config{})
	h.run(h.rb)
	id := h.start("rb")
	h.await(id, RunbookWaiting)
	h.answer(id, "token", secret)
	run := h.await(id, RunbookUnknown)
	if run.Steps[1].Status != stepUnknown || strings.Contains(run.Steps[1].Error, secret) {
		t.Errorf("step = %+v", run.Steps[1])
	}
}
