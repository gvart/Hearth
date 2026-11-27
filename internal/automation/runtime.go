// SPDX-License-Identifier: AGPL-3.0-only

package automation

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

// Run statuses, as recorded in run history.
const (
	StatusSucceeded = "succeeded"
	// StatusSkipped is a run whose conditions were not met.
	StatusSkipped   = "skipped"
	StatusFailed    = "failed"
	StatusDenied    = "denied"
	StatusCancelled = "cancelled"
)

// DefaultReloadEvery is how often the runtime checks its directory for
// changed files.
const DefaultReloadEvery = 2 * time.Second

// writeTimeout bounds the history write of a run, which goes on after the
// run itself is cancelled.
const writeTimeout = 10 * time.Second

// ErrNotRunning is returned by Fire for an automation this runtime does not
// run: unknown, invalid, or this hub is not the cluster leader.
var ErrNotRunning = errors.New("automation is not running on this hub")

// Policy decides on every action a run takes: *policy.Engine.
type Policy interface {
	Do(ctx context.Context, req policy.Request, fn func(context.Context) error) error
}

// RunRecorder keeps the run history: store.AutomationRuns.
type RunRecorder interface {
	Record(ctx context.Context, run store.AutomationRun) error
}

// Config holds a Runtime's dependencies.
type Config struct {
	// Dir holds the automation files, when Source is nil.
	Dir string
	// Source holds the automations as documents: the hub's store. It
	// replaces Dir.
	Source DocSource
	Kinds  Kinds
	Policy Policy
	Runs   RunRecorder
	Log    *slog.Logger
	// Builtin are automations the hub runs without a file, such as
	// NewDeviceAlerts. A file in Dir with the same id replaces one.
	Builtin []*Automation
	// ReloadEvery is how often Dir is checked for changes. Default
	// DefaultReloadEvery.
	ReloadEvery time.Duration
	// Now is the clock; default time.Now.
	Now func() time.Time
	// DryRun sends every action to policy as a dry run: each decision is
	// audited, and no action runs.
	DryRun bool
	// Owns, when set, says whether this hub owns automation id: in an AP
	// cluster, each master watches every trigger of the automations it owns
	// on the ring of masters (schedules, checks, metrics), and the local
	// triggers (device and network events, manual fires) of all of them
	// (localTrigger). Owned, when set, signals that what Owns says may have
	// changed.
	Owns  func(id string) bool
	Owned <-chan struct{}
}

// Runtime runs the automations in a directory.
type Runtime struct {
	cfg Config

	mu   sync.Mutex
	live map[string]*instance
}

// New returns a runtime. Run starts it.
func New(cfg Config) *Runtime {
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.DiscardHandler)
	}
	if cfg.ReloadEvery <= 0 {
		cfg.ReloadEvery = DefaultReloadEvery
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Runtime{cfg: cfg}
}

// Run loads the automations in the directory and runs them until ctx is
// done, reloading whenever its files change. A reload that finds an invalid
// file is logged and changes nothing: the automations already running carry
// on. An automation whose file did not change keeps running across a
// reload; one that changed is stopped, its run in progress cancelled, and
// started again. When Run returns, every run has ended.
func (r *Runtime) Run(ctx context.Context) error {
	defer r.reconcile(ctx, nil)
	tick := time.NewTicker(r.cfg.ReloadEvery)
	defer tick.Stop()
	last := "\x00" // never a fingerprint: the first check always loads
	var loaded []*Automation
	for {
		if fp, load, err := r.check(ctx); err != nil {
			r.cfg.Log.ErrorContext(ctx, "automations not reloaded", "dir", r.cfg.Dir, "err", err)
		} else if fp != last {
			last = fp
			set, err := load()
			if err != nil {
				r.cfg.Log.ErrorContext(ctx, "automations not reloaded: invalid files", "dir", r.cfg.Dir, "err", err)
			} else {
				r.warn(ctx, set)
				loaded = withBuiltin(set, r.cfg.Builtin)
				r.reconcile(ctx, loaded)
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
		case <-r.cfg.Owned:
			r.reconcile(ctx, loaded)
		}
	}
}

// owns reports whether this hub owns automation id (Config.Owns).
func (r *Runtime) owns(id string) bool { return r.cfg.Owns == nil || r.cfg.Owns(id) }

// localTrigger is a trigger fed by events of this hub only: a device going
// online or offline here, a host its own network scan found, a manual
// fire made here. Each such event happens on exactly one hub, so with
// Config.Owns set every hub watches these triggers of every automation,
// and an automation fires once, where the event happened. Events of rows
// merged from other members are never published, so they fire nothing.
type localTrigger interface{ firesLocally() }

func (*deviceTrigger) firesLocally()  {}
func (*networkTrigger) firesLocally() {}
func (manualTrigger) firesLocally()   {}

// watched reports whether this hub watches trigger t of an automation it
// owns or not: an owner watches all; another hub only the local ones.
func watched(owned bool, t Trigger) bool {
	if owned {
		return true
	}
	_, ok := t.(localTrigger)
	return ok
}

// check returns the fingerprint of the automations, which changes whenever
// one is added, removed or changed, and the function that loads them.
func (r *Runtime) check(ctx context.Context) (string, func() ([]*Automation, error), error) {
	if r.cfg.Source == nil {
		fp, err := fingerprint(r.cfg.Dir)
		return fp, func() ([]*Automation, error) { return LoadDir(r.cfg.Dir, r.cfg.Kinds) }, err
	}
	docs, err := r.cfg.Source.Docs(ctx)
	if err != nil {
		return "", nil, err
	}
	return docsFingerprint(docs), func() ([]*Automation, error) { return LoadDocs(docs, r.cfg.Kinds) }, nil
}

// warn logs what loaded but will fail when it runs.
func (r *Runtime) warn(ctx context.Context, set []*Automation) {
	for _, a := range set {
		for _, w := range a.Warnings {
			r.cfg.Log.WarnContext(ctx, "automation loaded, but runs reaching this template will fail",
				"file", a.File, "line", w.Line, "problem", w.Message)
		}
	}
}

// withBuiltin adds to set each built-in automation no file in it replaces.
func withBuiltin(set, builtin []*Automation) []*Automation {
	ids := map[string]bool{}
	for _, a := range set {
		ids[a.ID] = true
	}
	for _, a := range builtin {
		if !ids[a.ID] {
			set = append(set, a)
		}
	}
	return set
}

// fingerprint changes whenever an automation file in dir is added, removed
// or written.
func fingerprint(dir string) (string, error) {
	files, err := automationFiles(dir)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	for _, f := range files {
		info, err := os.Stat(f)
		if err != nil {
			return "", fmt.Errorf("stat automation file: %w", err)
		}
		fmt.Fprintf(&b, "%s\x00%d\x00%d\n", f, info.Size(), info.ModTime().UnixNano())
	}
	return b.String(), nil
}

// reconcile makes set the running automations. A nil set stops them all.
func (r *Runtime) reconcile(ctx context.Context, set []*Automation) {
	r.mu.Lock()
	defer r.mu.Unlock()
	next := map[string]*instance{}
	var start []*Automation
	for _, a := range set {
		if in, ok := r.live[a.ID]; ok && in.a.sum == a.sum && in.owned == r.owns(a.ID) {
			next[a.ID] = in
			delete(r.live, a.ID)
			continue
		}
		start = append(start, a)
	}
	// Stop what changed or went away before starting its replacement, so
	// two versions of one automation never run at once.
	for id, in := range r.live {
		in.close()
		r.cfg.Log.InfoContext(ctx, "automation stopped", "automation", id)
	}
	for _, a := range start {
		next[a.ID] = r.start(ctx, a)
		r.cfg.Log.InfoContext(ctx, "automation started", "automation", a.ID, "file", a.File, "mode", a.Mode)
	}
	r.live = next
}

// Fire fires the manual trigger triggerID of automation automationID.
func (r *Runtime) Fire(automationID, triggerID string) error {
	r.mu.Lock()
	in := r.live[automationID]
	r.mu.Unlock()
	if in == nil {
		return fmt.Errorf("fire %s: %w", automationID, ErrNotRunning)
	}
	for _, t := range in.a.Triggers {
		if _, ok := t.Impl.(manualTrigger); ok && t.ID == triggerID {
			in.fire(t, map[string]any{})
			return nil
		}
	}
	return fmt.Errorf("fire %s: no manual trigger %q", automationID, triggerID)
}

// instance is one running automation: its triggers' watchers and the worker
// that executes its runs one at a time.
type instance struct {
	a *Automation
	r *Runtime
	// owned is whether this hub owned the automation when it started it:
	// it then watches every trigger, else only the local ones.
	owned bool
	stop  context.CancelFunc
	wg    sync.WaitGroup
	wake  chan struct{}

	mu        sync.Mutex
	pending   []Event
	running   bool
	cancelRun context.CancelFunc
}

func (r *Runtime) start(ctx context.Context, a *Automation) *instance {
	ictx, cancel := context.WithCancel(ctx)
	in := &instance{a: a, r: r, owned: r.owns(a.ID), stop: cancel, wake: make(chan struct{}, 1)}
	in.wg.Go(func() { in.work(ictx) })
	for _, t := range a.Triggers {
		// A local automation's device watches its checks: the hub
		// never does, so its actions are never taken twice.
		if a.Local || !watched(in.owned, t.Impl) {
			continue
		}
		in.wg.Go(func() {
			if err := t.Impl.Watch(withTrigger(ictx, a.ID, t.ID), func(data map[string]any) { in.fire(t, data) }); err != nil && ictx.Err() == nil {
				r.cfg.Log.ErrorContext(ictx, "automation trigger stopped", "automation", a.ID, "trigger", t.ID, "err", err)
			}
		})
	}
	return in
}

// close stops the triggers, cancels the run in progress and waits for both.
func (in *instance) close() {
	in.stop()
	in.wg.Wait()
}

// fire starts a run, or not, as the automation's mode says.
func (in *instance) fire(t Step[Trigger], data map[string]any) {
	ev := Event{TriggerID: t.ID, TriggerType: t.Type, At: in.r.cfg.Now(), Data: data}
	log := in.r.cfg.Log.With("automation", in.a.ID, "trigger", t.ID)
	in.mu.Lock()
	switch in.a.Mode {
	case ModeSingle:
		if in.running || len(in.pending) > 0 {
			in.mu.Unlock()
			log.Info("automation already running; trigger ignored")
			return
		}
	case ModeQueued:
		if len(in.pending) >= MaxQueued {
			in.mu.Unlock()
			log.Warn("automation queue full; trigger dropped", "max_queued", MaxQueued)
			return
		}
	case ModeRestart:
		if in.cancelRun != nil {
			in.cancelRun()
		}
		in.pending = in.pending[:0]
	}
	in.pending = append(in.pending, ev)
	in.mu.Unlock()
	select {
	case in.wake <- struct{}{}:
	default:
	}
}

// work executes pending runs one at a time until ctx is done.
func (in *instance) work(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-in.wake:
		}
		for ctx.Err() == nil {
			in.mu.Lock()
			if len(in.pending) == 0 {
				in.mu.Unlock()
				break
			}
			ev := in.pending[0]
			in.pending = in.pending[1:]
			rctx, cancel := context.WithCancel(ctx)
			in.running, in.cancelRun = true, cancel
			in.mu.Unlock()

			in.r.execute(rctx, in.a, ev)

			cancel()
			in.mu.Lock()
			in.running, in.cancelRun = false, nil
			in.mu.Unlock()
		}
	}
}

// StepResult is one step of a run, as recorded in run history. The first
// is the trigger that fired, with status fired and the data it passed to
// the actions.
type StepResult struct {
	ID     string         `json:"id"`
	Type   string         `json:"type"`
	Status string         `json:"status"`
	Error  string         `json:"error,omitempty"`
	Data   map[string]any `json:"data,omitempty"`
	// Plan is what an action that can tell (a kube_* action) would have
	// done, in a dry run.
	Plan string `json:"plan,omitempty"`
	// RanOn, on the first step of a run a local automation's device
	// reported, is that device's id; HubUnreachable says the device had no
	// hub stream when the run started.
	RanOn          string `json:"ran_on,omitempty"`
	HubUnreachable bool   `json:"hub_unreachable,omitempty"`
}

// Step statuses.
const (
	stepFired     = "fired"
	stepOK        = "ok"
	stepNotMet    = "not_met"
	stepFailed    = "failed"
	stepDenied    = "denied"
	stepCancelled = "cancelled"
)

// execute runs a once: its conditions, then its actions through policy, and
// records the outcome. It returns the run's status.
func (r *Runtime) execute(ctx context.Context, a *Automation, ev Event) string {
	run := store.AutomationRun{
		ID: strings.ToLower(rand.Text()), AutomationID: a.ID, TriggerID: ev.TriggerID,
		StartedAt: r.cfg.Now(), Status: StatusSucceeded,
	}
	steps := []StepResult{{ID: ev.TriggerID, Type: ev.TriggerType, Status: stepFired, Data: ev.Data}}
	fail := func(status string, step StepResult, err error) {
		run.Status, run.Error = status, fmt.Sprintf("%s: %v", step.ID, err)
		step.Status, step.Error = status, err.Error()
		steps = append(steps, step)
	}
	cancelled := func(step StepResult) bool {
		if ctx.Err() == nil {
			return false
		}
		fail(StatusCancelled, step, context.Cause(ctx))
		return true
	}

	for _, c := range a.Conditions {
		step := StepResult{ID: c.ID, Type: c.Type}
		if cancelled(step) {
			break
		}
		ok, err := c.Impl.Check(ctx, ev)
		if err != nil {
			fail(StatusFailed, step, err)
			break
		}
		if !ok {
			step.Status = stepNotMet
			steps = append(steps, step)
			run.Status = StatusSkipped
			break
		}
		step.Status = stepOK
		steps = append(steps, step)
	}

	if run.Status == StatusSucceeded {
		for _, s := range a.Actions {
			step := StepResult{ID: s.ID, Type: s.Type}
			if cancelled(step) {
				break
			}
			plan, err := r.act(ctx, a, s, run.ID, ev)
			step.Plan = plan
			switch {
			case err == nil:
				step.Status = stepOK
				steps = append(steps, step)
				continue
			case errors.Is(err, policy.ErrDenied):
				fail(StatusDenied, step, err)
			case ctx.Err() != nil:
				fail(StatusCancelled, step, err)
			default:
				fail(StatusFailed, step, err)
			}
			break
		}
	}

	run.FinishedAt = r.cfg.Now()
	log := r.cfg.Log.With("automation", a.ID, "run", run.ID, "trigger", ev.TriggerID, "status", run.Status)
	if run.Error != "" {
		log = log.With("err", run.Error)
	}
	log.InfoContext(ctx, "automation run finished")
	if b, err := json.Marshal(steps); err == nil {
		run.Steps = b
	}
	wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), writeTimeout)
	defer cancel()
	if err := r.cfg.Runs.Record(wctx, run); err != nil {
		log.WarnContext(ctx, "automation run not recorded in history", "record_err", err)
	}
	return run.Status
}

// act executes one action through policy, as the automation. The audit entry
// is written even when the run is cancelled while the action executes (the
// store bounds the write itself), so only the action sees ctx, with the
// grant policy gave it. In a dry run, an action policy would allow that can
// plan says what it would do.
func (r *Runtime) act(ctx context.Context, a *Automation, s Step[Action], runID string, ev Event) (string, error) {
	target, err := s.Impl.Target().Render(ctx, ev)
	if err != nil {
		return "", err
	}
	req := policy.Request{
		ActorKind: policy.ActorAutomation,
		ActorID:   a.ID,
		Action:    s.Impl.Policy(),
		Target:    target,
		Detail:    map[string]any{"run": runID, "step": s.ID, "trigger": ev.TriggerID},
		DryRun:    r.cfg.DryRun,
	}
	// A script action calls policy itself, as the automation of this run.
	runCtx := withCaller(ctx, caller{policy: r.cfg.Policy, req: req})
	err = doAction(context.WithoutCancel(ctx), runCtx, r.cfg.Policy, req, s.Impl, ev, s.Impl.Run)
	p, ok := s.Impl.(planner)
	if err != nil || !r.cfg.DryRun || !ok {
		return "", err
	}
	plan, err := p.Plan(ctx, ev)
	if err != nil {
		return "", fmt.Errorf("dry run: %w", err)
	}
	r.cfg.Log.InfoContext(ctx, "automation dry run", "automation", a.ID, "run", runID, "step", s.ID, "plan", plan)
	return plan, nil
}

// doAction runs one action through policy: run is called only if policy
// allows it, in ctx with the grant policy gave it, while policy itself works
// in decideCtx, so that its audit entry is written even if ctx ends meanwhile.
func doAction(decideCtx, ctx context.Context, p Policy, req policy.Request, impl Action, ev Event,
	run func(context.Context, Event) error,
) error {
	if c, ok := impl.(prechecker); ok {
		req.Precheck = func(ctx context.Context) error { return c.Precheck(ctx, ev) }
	}
	return p.Do(decideCtx, req, func(granted context.Context) error {
		return run(policy.WithGrant(ctx, granted), ev)
	})
}

// planner is an action that can tell what it would do now without doing
// it, reading only, for a dry run.
type planner interface {
	Plan(ctx context.Context, ev Event) (string, error)
}

// prechecker is an action that can tell, before policy decides, that it
// would be refused: policy.Request.Precheck.
type prechecker interface {
	Precheck(ctx context.Context, ev Event) error
}
