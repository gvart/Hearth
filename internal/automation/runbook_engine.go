// SPDX-License-Identifier: AGPL-3.0-only

package automation

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gvart/hearth/internal/integrations/kubernetes"
	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

// defaultRunbookPoll is how often the engine looks for runs to carry on: runs
// are started and answered on any hub of a cluster, through the store.
const defaultRunbookPoll = time.Second

// maxPromptAnswer bounds the answer to a prompt.
const maxPromptAnswer = 4 << 10

// Errors of the operations on runbook runs.
var (
	// ErrRunbookState refuses an operation the run's state does not allow.
	ErrRunbookState = errors.New("the run is not in a state that allows this")
	// ErrRunbookAnswer refuses the answer to a prompt.
	ErrRunbookAnswer = errors.New("invalid answer")
	// ErrRunbookNotLeading refuses a secret answer on a hub that is not
	// running the engine: it must never travel through the replicated store.
	ErrRunbookNotLeading = errors.New("a secret answer must be given on the cluster's leader")
	// ErrOutcomeUnknown marks an action that was handed over and never
	// answered: it may or may not have happened.
	ErrOutcomeUnknown = errors.New("its outcome is not known")
)

// RunbookActor is the policy actor id of a runbook's action steps. The prefix
// keeps a grant to an automation from applying to a runbook of the same id.
func RunbookActor(id string) string { return "runbook/" + id }

// RunbookPolicy decides on the steps of runs: *policy.Engine.
type RunbookPolicy interface {
	Policy
	// Check is the decision Do would make, with no audit entry.
	Check(req policy.Request) (decision, reason string)
}

// RunbookStore keeps runs: store.RunbookRuns.
type RunbookStore interface {
	Create(ctx context.Context, run store.RunbookRun) error
	Save(ctx context.Context, run store.RunbookRun) (int64, error)
	Get(ctx context.Context, id string) (store.RunbookRun, error)
	List(ctx context.Context, runbookID string, limit int) ([]store.RunbookRun, error)
	Open(ctx context.Context) ([]store.RunbookRun, error)
}

// RunbookSealer encrypts the copy of the runbook file a run keeps, which may
// hold webhook URLs with tokens in them.
type RunbookSealer interface {
	Seal(id string, plaintext []byte) ([]byte, error)
	Open(id string, sealed []byte) ([]byte, error)
}

// RunbooksConfig holds the dependencies of Runbooks.
type RunbooksConfig struct {
	// Dir holds the runbook files, when Source is nil.
	Dir string
	// Source holds the runbooks as documents: the hub's store. It replaces
	// Dir.
	Source DocSource
	Kinds  Kinds
	Policy RunbookPolicy
	Runs   RunbookStore
	Sealer RunbookSealer
	// Probers run the check steps that name a device in from. Without
	// them, such a step fails.
	Probers Probers
	// KubeNodes runs the kube_node check steps. Without it, such a step
	// fails.
	KubeNodes KubeNodes
	// TalosNodes runs the talos_node check steps. Without it, such a step
	// fails.
	TalosNodes TalosNodes
	Log        *slog.Logger
	// Poll is how often the engine looks for work. Default 1s.
	Poll time.Duration
	// Now is the clock; default time.Now.
	Now func() time.Time
	// DryRun sends every action step to policy as a dry run: nothing runs.
	DryRun bool
	// Owns, when set, says whether this hub carries out run id: in an AP
	// cluster, each master carries out the runs it owns on the ring of
	// masters.
	Owns func(runID string) bool
}

// Runbooks runs runbooks. The operations (Start, Answer, Retry, Rollback) work
// on any hub and only change the stored run; Run, on the leader, carries runs
// out. Every step that does something is first recorded as running, through
// the store, and a run found with such a step that this engine is not running
// stops for an operator: the step is never repeated on its own.
type Runbooks struct {
	cfg  RunbooksConfig
	wake chan struct{}

	mu sync.Mutex
	// leading is true while Run runs.
	leading bool
	// secrets are the answers to secret prompts, by run and step. They live
	// here only, while the run goes on: a run that stops, a restart or a new
	// leader asks for them again.
	secrets map[string]map[string]string
	// answering is held while an answer is saved and remembered, so that the
	// engine never finds a saved answer it does not hold yet.
	answering sync.RWMutex
}

// NewRunbooks returns the engine. Run starts it.
func NewRunbooks(cfg RunbooksConfig) *Runbooks {
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.DiscardHandler)
	}
	if cfg.Poll <= 0 {
		cfg.Poll = defaultRunbookPoll
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Runbooks{cfg: cfg, wake: make(chan struct{}, 1), secrets: map[string]map[string]string{}}
}

// List loads the runbooks. The errors are the files left out.
func (r *Runbooks) List(ctx context.Context) ([]*Runbook, []error) {
	if r.cfg.Source == nil {
		return LoadRunbooks(r.cfg.Dir, r.cfg.Kinds)
	}
	docs, err := r.cfg.Source.Docs(ctx)
	if err != nil {
		return nil, []error{err}
	}
	return LoadRunbookDocs(docs, r.cfg.Kinds)
}

// find returns the runbook id, or an error wrapping store.ErrNotFound.
func (r *Runbooks) find(ctx context.Context, id string) (*Runbook, error) {
	all, _ := r.List(ctx)
	for _, rb := range all {
		if rb.ID == id {
			return rb, nil
		}
	}
	return nil, fmt.Errorf("runbook %s: %w", id, store.ErrNotFound)
}

// RunbookPlanStep is what one step of a run would do.
type RunbookPlanStep struct {
	ID          string `json:"id"`
	Type        string `json:"type"`
	What        string `json:"what"`
	Description string `json:"description,omitempty"`
	// Target is what an action acts on, as written: it may hold templates.
	Target string `json:"target,omitempty"`
	// Action, Class and Decision are the policy action of an action step, its
	// class, and what policy would decide now: allow, confirm or deny. Reason
	// says why it would be denied.
	Action   string `json:"action,omitempty"`
	Class    string `json:"class,omitempty"`
	Decision string `json:"decision,omitempty"`
	Reason   string `json:"reason,omitempty"`
	// Rollback is the step that would undo this one.
	Rollback *RunbookPlanStep `json:"rollback,omitempty"`
}

// RunbookPlan is what a run of a runbook would do. Making it runs nothing.
type RunbookPlan struct {
	ID          string            `json:"id"`
	Description string            `json:"description,omitempty"`
	Steps       []RunbookPlanStep `json:"steps"`
}

// Plan says what a run of the runbook id would do and what policy would decide
// on each action step, including whether the device's capability ceiling
// allows it. Nothing is executed or audited.
func (r *Runbooks) Plan(ctx context.Context, id string) (*RunbookPlan, error) {
	rb, err := r.find(ctx, id)
	if err != nil {
		return nil, err
	}
	plan := &RunbookPlan{ID: rb.ID, Description: rb.Description, Steps: make([]RunbookPlanStep, len(rb.Steps))}
	for i := range rb.Steps {
		s := &rb.Steps[i]
		p := RunbookPlanStep{ID: s.ID, Type: s.Type, What: s.What(), Description: s.Description}
		if s.Action != nil {
			r.planAction(ctx, rb, s.Action, &p)
		}
		if s.Check != nil {
			r.planCheck(ctx, rb, s.Check, &p)
		}
		if s.Rollback != nil {
			rp := RunbookPlanStep{ID: s.ID, Type: RunbookStepAction, What: s.Rollback.Impl.Describe()}
			r.planAction(ctx, rb, s.Rollback, &rp)
			p.Rollback = &rp
		}
		plan.Steps[i] = p
	}
	return plan, nil
}

// planCheck fills in what policy would decide on the check c.
func (r *Runbooks) planCheck(ctx context.Context, rb *Runbook, c *checkTrigger, p *RunbookPlanStep) {
	action, target := checkAction(c)
	class, _ := policy.ClassOf(action)
	p.Target, p.Action, p.Class = target, string(action), string(class)
	p.Decision, p.Reason = r.cfg.Policy.Check(policy.Request{
		ActorKind: policy.ActorAutomation, ActorID: RunbookActor(rb.ID), Action: action, Target: target,
	})
	if c.from != "" && p.Decision != policy.Deny {
		// Only a refusal counts: an agent that is offline now may be back.
		if err := r.checkProbe(ctx, c.from); errors.Is(err, policy.ErrDenied) {
			p.Decision, p.Reason = policy.Deny, err.Error()
		}
	}
}

// checkAction is the policy action and target of the check c: a check from a
// device is that device's probe, one from the hub reads the check's target.
func checkAction(c *checkTrigger) (policy.Action, string) {
	if c.from != "" {
		return policy.AutomationProbe, c.from
	}
	if c.kubeNode != nil {
		return policy.KubeNodeReady, c.target
	}
	if c.talosNode != nil {
		return policy.TalosRead, c.target
	}
	return policy.RunbookCheck, c.what
}

// checkProbe reports whether a probe would be sent to device: an error
// wrapping policy.ErrBeyondCeiling when its agent's ceiling refuses probes.
func (r *Runbooks) checkProbe(ctx context.Context, device string) error {
	if r.cfg.Probers == nil {
		return errNoProbers
	}
	return r.cfg.Probers.CheckProbe(ctx, device)
}

// errNoProbers fails a check from a device on a hub that cannot run one.
var errNoProbers = errors.New("this hub does not run checks from devices")

// planAction fills in what policy would decide on a.
func (r *Runbooks) planAction(ctx context.Context, rb *Runbook, a *Step[Action], p *RunbookPlanStep) {
	p.Target = a.Impl.Target().String()
	p.Action = string(a.Impl.Policy())
	class, _ := policy.ClassOf(a.Impl.Policy())
	p.Class = string(class)
	p.Decision, p.Reason = r.cfg.Policy.Check(policy.Request{
		ActorKind: policy.ActorAutomation, ActorID: RunbookActor(rb.ID), Action: a.Impl.Policy(), Target: p.Target,
	})
	if c, ok := a.Impl.(prechecker); ok && p.Decision != policy.Deny {
		// Only a refusal counts: an agent that is offline now may be back.
		ev := runbookEvent(rb.ID, r.cfg.Now(), inputFor(a.Impl, nil, nil))
		if err := c.Precheck(ctx, ev); errors.Is(err, policy.ErrDenied) {
			p.Decision, p.Reason = policy.Deny, err.Error()
		}
	}
}

// Start begins a run of the runbook id, as actorKind/actorID, and returns it.
func (r *Runbooks) Start(ctx context.Context, actorKind, actorID, id string) (RunbookRunJSON, error) {
	rb, err := r.find(ctx, id)
	if err != nil {
		return RunbookRunJSON{}, err
	}
	runID := strings.ToLower(rand.Text())
	var out RunbookRunJSON
	saved := false
	err = r.cfg.Policy.Do(ctx, policy.Request{
		ActorKind: actorKind, ActorID: actorID, Action: policy.RunbookStart, Target: rb.ID,
		Detail: map[string]any{"run": runID},
	}, func(ctx context.Context) error {
		sealed, err := r.cfg.Sealer.Seal(RunbookSealID(runID), rb.source)
		if err != nil {
			return err
		}
		now := r.cfg.Now()
		st := newRunbookState(rb)
		st.log(now, "", actorKind+"/"+actorID, "started the run")
		b, err := json.Marshal(st)
		if err != nil {
			return fmt.Errorf("encode run state: %w", err)
		}
		run := store.RunbookRun{
			ID: runID, RunbookID: rb.ID, Status: RunbookRunning, Version: 1, StartedBy: actorKind + "/" + actorID,
			StartedAt: now, UpdatedAt: now, Source: sealed, State: b,
		}
		if err := r.cfg.Runs.Create(ctx, run); err != nil {
			return err
		}
		out, saved = runbookRunJSON(run, st), true
		return nil
	})
	err = r.savedDespite(ctx, err, saved, "started", runID)
	if err != nil {
		return RunbookRunJSON{}, err
	}
	r.poke()
	return out, nil
}

// savedDespite is err of a change to a run, without ErrOutcomeNotRecorded if
// the change was saved: the run is what it was made, the audit log shows the
// change as started, and an operator who is told it failed would make it twice.
func (r *Runbooks) savedDespite(ctx context.Context, err error, saved bool, what, runID string) error {
	if saved && errors.Is(err, policy.ErrOutcomeNotRecorded) {
		r.cfg.Log.WarnContext(ctx, "runbook run "+what+", but its audit outcome was not recorded", "run", runID, "err", err)
		return nil
	}
	return err
}

// RunbookSealID binds a run's sealed file to the run.
func RunbookSealID(runID string) string { return "runbook-run/" + runID }

// Runs lists runs, newest first: of runbookID, or of every runbook if empty.
func (r *Runbooks) Runs(ctx context.Context, runbookID string, limit int) ([]RunbookRunJSON, error) {
	runs, err := r.cfg.Runs.List(ctx, runbookID, limit)
	if err != nil {
		return nil, err
	}
	out := make([]RunbookRunJSON, 0, len(runs))
	for _, run := range runs {
		st, err := decodeRunbookState(run)
		if err != nil {
			return nil, err
		}
		out = append(out, runbookRunJSON(run, st))
	}
	return out, nil
}

// GetRun returns one run.
func (r *Runbooks) GetRun(ctx context.Context, id string) (RunbookRunJSON, error) {
	run, err := r.cfg.Runs.Get(ctx, id)
	if err != nil {
		return RunbookRunJSON{}, err
	}
	st, err := decodeRunbookState(run)
	if err != nil {
		return RunbookRunJSON{}, err
	}
	return runbookRunJSON(run, st), nil
}

// operate changes a stored run on behalf of an operator: audited through
// policy, and saved only if nothing else changed the run meanwhile.
func (r *Runbooks) operate(ctx context.Context, actorKind, actorID string, action policy.Action, runID string,
	detail map[string]any, change func(run *store.RunbookRun, st *RunbookState, actor string) error,
) (RunbookRunJSON, error) {
	var out RunbookRunJSON
	saved := false
	detail["run"] = runID
	err := r.cfg.Policy.Do(ctx, policy.Request{
		ActorKind: actorKind, ActorID: actorID, Action: action, Target: runID, Detail: detail,
	}, func(ctx context.Context) error {
		run, err := r.cfg.Runs.Get(ctx, runID)
		if err != nil {
			return err
		}
		st, err := decodeRunbookState(run)
		if err != nil {
			return err
		}
		if err := change(&run, st, actorKind+"/"+actorID); err != nil {
			return err
		}
		if err := r.save(ctx, &run, st); err != nil {
			return err
		}
		out, saved = runbookRunJSON(run, st), true
		return nil
	})
	err = r.savedDespite(ctx, err, saved, "changed", runID)
	if err != nil {
		return RunbookRunJSON{}, err
	}
	r.poke()
	return out, nil
}

// Answer answers the prompt step of a run. The answer is never audited, and a
// secret one stays in this hub's memory, once the run has accepted it.
func (r *Runbooks) Answer(ctx context.Context, actorKind, actorID, runID, step, value string) (RunbookRunJSON, error) {
	r.answering.Lock()
	defer r.answering.Unlock()
	secret := false
	out, err := r.operate(ctx, actorKind, actorID, policy.RunbookAnswer, runID, map[string]any{"step": step},
		func(run *store.RunbookRun, st *RunbookState, actor string) error {
			ps := st.step(step)
			if run.Status != RunbookWaiting || st.Awaiting != step || ps == nil || ps.Prompt == nil {
				return fmt.Errorf("%w: it is not waiting for an answer to %s", ErrRunbookState, step)
			}
			if err := checkAnswer(ps.Prompt, value); err != nil {
				return err
			}
			now := r.cfg.Now()
			if ps.Prompt.Secret {
				// The answer stays in the memory of the hub driving the run.
				if !r.isLeading() || (r.cfg.Owns != nil && !r.cfg.Owns(runID)) {
					return ErrRunbookNotLeading
				}
				secret = true
				st.log(now, step, actor, "answered (secret)")
			} else {
				st.log(now, step, actor, "answered: %s", value)
			}
			st.Awaiting, st.Deadline = "", nil
			// A secret asked for again: the run goes back to where it was.
			if ps.Status != stepWaiting {
				run.Status = RunbookRunning
				if st.Phase == phaseRollback {
					run.Status = RunbookRollingBack
				}
				return nil
			}
			ps.FinishedAt = &now
			if ps.Prompt.Kind == PromptConfirm && value == ConfirmNo {
				ps.Status, ps.Error = stepFailed, "declined by "+actor
				run.Status = RunbookFailed
				return nil
			}
			ps.Status = stepOK
			if !ps.Prompt.Secret {
				if st.Inputs == nil {
					st.Inputs = map[string]string{}
				}
				st.Inputs[step] = value
			}
			st.Cursor++
			run.Status = RunbookRunning
			return nil
		})
	if err == nil && secret {
		r.remember(runID, step, value)
	}
	return out, err
}

// checkAnswer validates an answer. Its errors never hold the answer.
func checkAnswer(p *RunbookPromptJSON, value string) error {
	if len(value) > maxPromptAnswer {
		return fmt.Errorf("%w: at most %d bytes", ErrRunbookAnswer, maxPromptAnswer)
	}
	if p.Kind == PromptConfirm && value != ConfirmYes && value != ConfirmNo {
		return fmt.Errorf("%w: a confirmation is yes or no", ErrRunbookAnswer)
	}
	if p.Kind == PromptInput && value == "" {
		return fmt.Errorf("%w: an answer is required", ErrRunbookAnswer)
	}
	return nil
}

// decidable refuses an operator's decision on a run that has not stopped, or
// that changed since the operator saw it at version.
func decidable(run *store.RunbookRun, version int64) error {
	if !runbookStopped(run.Status) {
		return fmt.Errorf("%w: it has not stopped at a step", ErrRunbookState)
	}
	if run.Version != version {
		return fmt.Errorf("%w: it changed since version %d", ErrRunbookState, version)
	}
	return nil
}

// Retry runs the step a run stopped at again, if the run is still at version.
func (r *Runbooks) Retry(ctx context.Context, actorKind, actorID, runID string, version int64) (RunbookRunJSON, error) {
	return r.operate(ctx, actorKind, actorID, policy.RunbookRetry, runID, map[string]any{"version": version},
		func(run *store.RunbookRun, st *RunbookState, actor string) error {
			if err := decidable(run, version); err != nil {
				return err
			}
			now := r.cfg.Now()
			st.Error = ""
			if st.Phase == phaseRollback {
				if rs := st.stoppedRollback(); rs != nil {
					rs.Status, rs.Error = stepPending, ""
				}
				st.log(now, "", actor, "retried the rollback step")
				run.Status = RunbookRollingBack
				return nil
			}
			s := st.current()
			if s != nil && (s.Status == stepFailed || s.Status == stepDenied || s.Status == stepUnknown) {
				s.Status, s.Error, s.FinishedAt = stepPending, "", nil
				st.log(now, s.ID, actor, "retried the step")
			}
			run.Status = RunbookRunning
			return nil
		})
}

// Rollback rolls a stopped run back through the rollback steps of the steps
// that happened, the latest first, if the run is still at version. A run
// already rolling back is not rolled back again: see Retry and PassOver.
func (r *Runbooks) Rollback(ctx context.Context, actorKind, actorID, runID string, version int64) (RunbookRunJSON, error) {
	return r.operate(ctx, actorKind, actorID, policy.RunbookRollback, runID, map[string]any{"version": version},
		func(run *store.RunbookRun, st *RunbookState, actor string) error {
			if err := decidable(run, version); err != nil {
				return err
			}
			if st.Phase == phaseRollback {
				return fmt.Errorf("%w: it is already rolling back", ErrRunbookState)
			}
			st.Error = ""
			st.Phase = phaseRollback
			st.log(r.cfg.Now(), "", actor, "started the rollback")
			run.Status = RunbookRollingBack
			return nil
		})
}

// PassOver gives up on the rollback of step, which must be the one the run
// stopped at, if the run is still at version, and goes on with the other
// rollback steps.
func (r *Runbooks) PassOver(ctx context.Context, actorKind, actorID, runID, step string, version int64) (RunbookRunJSON, error) {
	return r.operate(ctx, actorKind, actorID, policy.RunbookPassOver, runID, map[string]any{"version": version, "step": step},
		func(run *store.RunbookRun, st *RunbookState, actor string) error {
			if err := decidable(run, version); err != nil {
				return err
			}
			rs := st.stoppedRollback()
			if st.Phase != phaseRollback || rs == nil {
				return fmt.Errorf("%w: it has not stopped at a rollback step", ErrRunbookState)
			}
			if st.stoppedRollbackStep() != step {
				return fmt.Errorf("%w: its rollback did not stop at step %s", ErrRunbookState, step)
			}
			st.Error = ""
			rs.Status = stepSkipped
			st.log(r.cfg.Now(), step, actor, "passed over the rollback step that stopped the run")
			run.Status = RunbookRollingBack
			return nil
		})
}

// save writes the run if it is unchanged since it was read.
func (r *Runbooks) save(ctx context.Context, run *store.RunbookRun, st *RunbookState) error {
	b, err := json.Marshal(st)
	if err != nil {
		return fmt.Errorf("encode run state: %w", err)
	}
	run.State, run.UpdatedAt = b, r.cfg.Now()
	if runbookFinished(run.Status) {
		run.FinishedAt = run.UpdatedAt
	}
	v, err := r.cfg.Runs.Save(ctx, *run)
	if err != nil {
		return err
	}
	run.Version = v
	if runbookFinished(run.Status) || runbookStopped(run.Status) {
		r.forgetRun(run.ID)
	}
	return nil
}

func (r *Runbooks) poke() {
	select {
	case r.wake <- struct{}{}:
	default:
	}
}

// isLeading reports whether this hub is running the engine.
func (r *Runbooks) isLeading() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.leading
}

// remember keeps a secret answer, on the hub running the engine only. If this
// hub just lost the lead, the new leader asks for the answer again.
func (r *Runbooks) remember(runID, step, value string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.leading {
		return
	}
	if r.secrets[runID] == nil {
		r.secrets[runID] = map[string]string{}
	}
	r.secrets[runID][step] = value
}

// keepSecretsOf drops the secret answers of every run but those in open. A run
// can stop on another hub, which holds no secrets to drop.
func (r *Runbooks) keepSecretsOf(open []store.RunbookRun) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for id := range r.secrets {
		if !slices.ContainsFunc(open, func(run store.RunbookRun) bool { return run.ID == id }) {
			delete(r.secrets, id)
		}
	}
}

func (r *Runbooks) forgetRun(runID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.secrets, runID)
}

// secretsOf is a copy of the secret answers kept for a run.
func (r *Runbooks) secretsOf(runID string) map[string]string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make(map[string]string, len(r.secrets[runID]))
	for k, v := range r.secrets[runID] {
		out[k] = v
	}
	return out
}

func (r *Runbooks) setLeading(leading bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.leading = leading
	if !leading {
		r.secrets = map[string]map[string]string{}
	}
}

// Run carries out runs until ctx is done. In a cluster it runs on the leader
// only. When it returns, nothing of a run is executing.
func (r *Runbooks) Run(ctx context.Context) error {
	r.setLeading(true)
	defer r.setLeading(false)
	var (
		wg     sync.WaitGroup
		mu     sync.Mutex
		active = map[string]bool{}
	)
	defer wg.Wait()
	tick := time.NewTicker(r.cfg.Poll)
	defer tick.Stop()
	for {
		// Held so that an answer being saved is either in runs or not yet kept.
		r.answering.RLock()
		runs, err := r.cfg.Runs.Open(ctx)
		if err == nil {
			r.keepSecretsOf(runs)
		}
		r.answering.RUnlock()
		if err != nil && ctx.Err() == nil {
			r.cfg.Log.WarnContext(ctx, "runbook runs not read", "err", err)
		}
		for _, run := range runs {
			if r.cfg.Owns != nil && !r.cfg.Owns(run.ID) {
				continue
			}
			switch run.Status {
			case RunbookWaiting:
				r.expirePrompt(ctx, run)
			case RunbookRunning, RunbookRollingBack:
				mu.Lock()
				busy := active[run.ID]
				active[run.ID] = true
				mu.Unlock()
				if busy {
					continue
				}
				wg.Go(func() {
					progressed := r.drive(ctx, run.ID)
					mu.Lock()
					delete(active, run.ID)
					mu.Unlock()
					// A run that got nowhere waits for the next tick.
					if progressed {
						r.poke()
					}
				})
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
		case <-r.wake:
		}
	}
}

// expirePrompt fails the step of a run whose prompt ran out of time.
func (r *Runbooks) expirePrompt(ctx context.Context, run store.RunbookRun) {
	st, err := decodeRunbookState(run)
	if err != nil {
		r.cfg.Log.ErrorContext(ctx, "runbook run not readable", "run", run.ID, "err", err)
		return
	}
	now := r.cfg.Now()
	if st.Deadline == nil || now.Before(*st.Deadline) {
		return
	}
	ps := st.step(st.Awaiting)
	if ps == nil {
		return
	}
	msg := fmt.Sprintf("no answer to prompt %s in time", st.Awaiting)
	switch {
	case ps.Status == stepWaiting:
		ps.Status, ps.Error, ps.FinishedAt = stepFailed, msg, &now
		run.Status = RunbookFailed
	case st.Phase == phaseRollback:
		if i := st.nextRollback(); i >= 0 {
			st.Steps[i].Rollback.Status, st.Steps[i].Rollback.Error = stepFailed, msg
		}
		run.Status = RunbookRollbackFailed
	default:
		if s := st.current(); s != nil {
			s.Status, s.Error, s.FinishedAt = stepFailed, msg, &now
		}
		run.Status = RunbookFailed
	}
	st.log(now, st.Awaiting, "", "%s", msg)
	st.Awaiting, st.Deadline = "", nil
	if err := r.save(ctx, &run, st); err != nil && !errors.Is(err, store.ErrRunbookRunConflict) && ctx.Err() == nil {
		r.cfg.Log.WarnContext(ctx, "runbook prompt timeout not saved", "run", run.ID, "err", err)
	}
}

// drive carries a run forward until it stops, finishes, or ctx is done. It
// reports whether the run got anywhere.
func (r *Runbooks) drive(ctx context.Context, runID string) (progressed bool) {
	log := r.cfg.Log.With("run", runID)
	var rb *Runbook
	for ctx.Err() == nil {
		run, err := r.cfg.Runs.Get(ctx, runID)
		if err != nil {
			log.WarnContext(ctx, "runbook run not read", "err", err)
			return progressed
		}
		st, err := decodeRunbookState(run)
		if err != nil {
			log.ErrorContext(ctx, "runbook run not readable", "err", err)
			return progressed
		}
		if run.Status != RunbookRunning && run.Status != RunbookRollingBack {
			return progressed
		}
		if rb == nil {
			if rb, err = r.definition(run); err != nil {
				r.stopUnreadable(ctx, &run, st, err)
				return progressed
			}
		}
		var again bool
		if run.Status == RunbookRunning {
			again, err = r.stepForward(ctx, rb, &run, st)
		} else {
			again, err = r.stepRollback(ctx, rb, &run, st)
		}
		if err != nil {
			// Not saved: the run stays as stored. A step recorded as running
			// then counts as unknown, which is what it is.
			if ctx.Err() == nil && !errors.Is(err, store.ErrRunbookRunConflict) {
				log.WarnContext(ctx, "runbook run not saved", "err", err)
			}
			return progressed
		}
		progressed = true
		if !again {
			return progressed
		}
	}
	return progressed
}

// definition reads the runbook file a run started from.
func (r *Runbooks) definition(run store.RunbookRun) (*Runbook, error) {
	src, err := r.cfg.Sealer.Open(RunbookSealID(run.ID), run.Source)
	if err != nil {
		return nil, fmt.Errorf("open the run's copy of its runbook: %w", err)
	}
	return ParseRunbook(run.RunbookID, src, r.cfg.Kinds)
}

// stopUnreadable stops a run whose definition cannot be read on this hub.
func (r *Runbooks) stopUnreadable(ctx context.Context, run *store.RunbookRun, st *RunbookState, err error) {
	now := r.cfg.Now()
	msg := truncateError(fmt.Sprintf("the runbook cannot be loaded on this hub: %v", err))
	st.Error = msg
	st.log(now, "", "", "%s", msg)
	run.Status = RunbookFailed
	if st.Phase == phaseRollback {
		run.Status = RunbookRollbackFailed
		if i := st.nextRollback(); i >= 0 && st.Steps[i].Rollback.Status == stepRunning {
			st.Steps[i].Rollback.Status, run.Status = stepUnknown, RunbookUnknown
		}
	} else if s := st.current(); s != nil && s.Status == stepRunning {
		s.Status, run.Status = stepUnknown, RunbookUnknown
	}
	if err := r.save(ctx, run, st); err != nil && ctx.Err() == nil {
		r.cfg.Log.WarnContext(ctx, "runbook run not saved", "run", run.ID, "err", err)
	}
}

// stepForward takes one step of a run going forward. again says whether the
// run goes on at once.
func (r *Runbooks) stepForward(ctx context.Context, rb *Runbook, run *store.RunbookRun, st *RunbookState) (again bool, err error) {
	now := r.cfg.Now()
	s := st.current()
	if s == nil {
		run.Status = RunbookSucceeded
		st.log(now, "", "", "the run succeeded")
		return false, r.save(ctx, run, st)
	}
	d := &rb.Steps[st.Cursor]
	if s.Status == stepRunning && d.Type != RunbookStepWait {
		// Recorded as running, and this engine is not running it.
		s.Status, s.Error = stepUnknown, unknownOutcome
		run.Status = RunbookUnknown
		st.log(now, s.ID, "", "%s", unknownOutcome)
		return false, r.save(ctx, run, st)
	}
	if s.Status == stepPending {
		if d.Type == RunbookStepPrompt {
			deadline := now.Add(d.Prompt.Timeout)
			s.Status, s.StartedAt, s.Deadline = stepWaiting, &now, &deadline
			s.Attempts++
			st.Awaiting, st.Deadline = s.ID, &deadline
			run.Status = RunbookWaiting
			st.log(now, s.ID, "", "waiting for an answer")
			return false, r.save(ctx, run, st)
		}
		if missing := r.missingSecret(run.ID, d.needs); missing != "" {
			return false, r.askAgain(ctx, rb, run, st, missing)
		}
		s.Status, s.StartedAt = stepRunning, &now
		s.Attempts++
		if d.Type == RunbookStepWait {
			deadline := now.Add(d.Wait)
			s.Deadline = &deadline
		}
		st.log(now, s.ID, "", "started (attempt %d)", s.Attempts)
		// Recorded before anything happens: if this write fails, nothing runs.
		if err := r.save(ctx, run, st); err != nil {
			return false, err
		}
	}

	stepErr := r.execute(ctx, rb, run, st, d)
	if ctx.Err() != nil {
		return false, nil // the next leader finds the step running
	}
	wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), writeTimeout)
	defer cancel()
	done := r.cfg.Now()
	s.FinishedAt = &done
	if stepErr == nil {
		s.Status = stepOK
		st.Cursor++
		st.log(done, s.ID, "", "succeeded")
		return true, r.save(wctx, run, st)
	}
	s.Status, s.Error = failedStatus(stepErr), truncateError(stepErr.Error())
	run.Status = RunbookFailed
	if d.Type == RunbookStepAction && outcomeUncertain(stepErr) {
		s.Status, run.Status = stepUnknown, RunbookUnknown
	}
	st.log(done, s.ID, "", "%s: %s", s.Status, s.Error)
	return false, r.save(wctx, run, st)
}

// unknownOutcome is the error of a step the hub died in the middle of.
const unknownOutcome = "the hub stopped while this step was running: it may or may not have completed"

// failedStatus is the state of a step that ended with err.
func failedStatus(err error) string {
	if errors.Is(err, policy.ErrDenied) {
		return stepDenied
	}
	return stepFailed
}

// definiteFailure is the error of an action known not to have happened,
// whatever the error it wraps would otherwise suggest.
type definiteFailure struct{ error }

func (e definiteFailure) Unwrap() error { return e.error }

// outcomeUncertain reports whether an action that ended with err may have
// happened all the same, in whole or in part: it was handed over and the answer
// never came, or nobody could record how it ended. A refusal, or a target that
// could not be reached at all, is a definite failure.
func outcomeUncertain(err error) bool {
	if errors.Is(err, policy.ErrOutcomeNotRecorded) {
		return true
	}
	var definite definiteFailure
	if errors.As(err, &definite) || errors.Is(err, policy.ErrDenied) {
		return false
	}
	if errors.Is(err, ErrOutcomeUnknown) || errors.Is(err, kubernetes.ErrDrainIncomplete) ||
		errors.Is(err, kubernetes.ErrWriteOutcomeUnknown) {
		return true
	}
	var op *net.OpError
	if errors.As(err, &op) && op.Op == "dial" {
		return false
	}
	var dns *net.DNSError
	if errors.As(err, &dns) {
		return false
	}
	for _, target := range []error{
		context.DeadlineExceeded, context.Canceled, os.ErrDeadlineExceeded,
		io.EOF, io.ErrUnexpectedEOF, net.ErrClosed, syscall.ECONNRESET, syscall.ECONNABORTED, syscall.EPIPE,
	} {
		if errors.Is(err, target) {
			return true
		}
	}
	var timeout net.Error
	return errors.As(err, &timeout) && timeout.Timeout()
}

// stepRollback takes one step of a run rolling back.
func (r *Runbooks) stepRollback(ctx context.Context, rb *Runbook, run *store.RunbookRun, st *RunbookState) (again bool, err error) {
	now := r.cfg.Now()
	i := st.nextRollback()
	if i < 0 {
		run.Status = RunbookRolledBack
		st.log(now, "", "", "the rollback finished")
		return false, r.save(ctx, run, st)
	}
	s, d := &st.Steps[i], &rb.Steps[i]
	rs := s.Rollback
	if rs.Status == stepRunning {
		rs.Status, rs.Error = stepUnknown, unknownOutcome
		run.Status = RunbookUnknown
		st.log(now, s.ID, "", "rollback: %s", unknownOutcome)
		return false, r.save(ctx, run, st)
	}
	if missing := r.missingSecret(run.ID, d.rollbackNeeds); missing != "" {
		return false, r.askAgain(ctx, rb, run, st, missing)
	}
	rs.Status = stepRunning
	rs.Attempts++
	st.log(now, s.ID, "", "rollback started (attempt %d)", rs.Attempts)
	if err := r.save(ctx, run, st); err != nil {
		return false, err
	}

	stepErr := r.runAction(ctx, rb, run, st, d.Rollback, phaseRollback, rs.Attempts)
	if ctx.Err() != nil {
		return false, nil
	}
	wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), writeTimeout)
	defer cancel()
	done := r.cfg.Now()
	if stepErr == nil {
		rs.Status = stepOK
		st.log(done, s.ID, "", "rollback succeeded")
		return true, r.save(wctx, run, st)
	}
	rs.Status, rs.Error = failedStatus(stepErr), truncateError(stepErr.Error())
	run.Status = RunbookRollbackFailed
	if outcomeUncertain(stepErr) {
		rs.Status, run.Status = stepUnknown, RunbookUnknown
	}
	st.log(done, s.ID, "", "rollback %s: %s", rs.Status, rs.Error)
	return false, r.save(wctx, run, st)
}

// missingSecret is the first of needs this hub does not hold an answer to.
func (r *Runbooks) missingSecret(runID string, needs []string) string {
	r.answering.RLock()
	defer r.answering.RUnlock()
	have := r.secretsOf(runID)
	for _, id := range needs {
		if _, ok := have[id]; !ok {
			return id
		}
	}
	return ""
}

// askAgain stops the run for the secret answer a restart lost.
func (r *Runbooks) askAgain(ctx context.Context, rb *Runbook, run *store.RunbookRun, st *RunbookState, id string) error {
	now := r.cfg.Now()
	timeout := defaultPromptTimeout
	for i := range rb.Steps {
		if rb.Steps[i].ID == id && rb.Steps[i].Prompt != nil {
			timeout = rb.Steps[i].Prompt.Timeout
		}
	}
	deadline := now.Add(timeout)
	st.Awaiting, st.Deadline = id, &deadline
	run.Status = RunbookWaiting
	st.log(now, id, "", "this secret answer is needed again: secret answers are not kept once a run stops or the hub restarts")
	return r.save(ctx, run, st)
}

// execute runs the step d, which is recorded as running.
func (r *Runbooks) execute(ctx context.Context, rb *Runbook, run *store.RunbookRun, st *RunbookState, d *RunbookStep) error {
	switch d.Type {
	case RunbookStepAction:
		return r.runAction(ctx, rb, run, st, d.Action, phaseForward, st.step(d.ID).Attempts)
	case RunbookStepCheck:
		return r.policedCheck(ctx, rb, run, d, st.step(d.ID).Attempts)
	case RunbookStepWait:
		deadline := st.step(d.ID).Deadline
		if deadline == nil {
			return nil
		}
		t := time.NewTimer(deadline.Sub(r.cfg.Now()))
		defer t.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			return nil
		}
	}
	return fmt.Errorf("step %s of type %s cannot run", d.ID, d.Type)
}

// policedCheck takes a check step through policy, as the runbook: one decision
// and one audit entry for each attempt at the step, however often it polls. A
// check from a device is decided as that device's probe, and is denied when
// the device's capability ceiling does not allow probes.
func (r *Runbooks) policedCheck(ctx context.Context, rb *Runbook, run *store.RunbookRun, d *RunbookStep, attempt int) error {
	decideCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	defer cancel()
	action, target := checkAction(d.Check)
	req := policy.Request{
		ActorKind: policy.ActorAutomation, ActorID: RunbookActor(rb.ID), Action: action, Target: target,
		Detail: map[string]any{"run": run.ID, "step": d.ID, "attempt": attempt, "started_by": run.StartedBy},
		DryRun: r.cfg.DryRun,
		OnHold: func(string, time.Time) { context.AfterFunc(ctx, cancel) },
	}
	if d.Check.from != "" {
		req.Detail["check"] = d.Check.what
		req.Precheck = func(ctx context.Context) error { return r.checkProbe(ctx, d.Check.from) }
	}
	return r.cfg.Policy.Do(decideCtx, req, func(granted context.Context) error { return r.runCheck(policy.WithGrant(ctx, granted), d) })
}

// runCheck repeats a check until it passes or its time is up. A check from a
// device that cannot run at all (the device is unknown, its agent offline or
// refusing probes) fails at once: it never falls back to the hub. So does a
// kube_node check on a cluster the hub has not adopted, and a talos_node
// check on a hub without a talosconfig.
func (r *Runbooks) runCheck(ctx context.Context, d *RunbookStep) error {
	c := *d.Check
	if c.from != "" {
		if r.cfg.Probers == nil {
			return errNoProbers
		}
		c.probers = r.cfg.Probers
	}
	deadline := r.cfg.Now().Add(d.Within)
	once := c.run
	cannot := "the check cannot run from its device"
	if c.kubeNode != nil {
		if r.cfg.KubeNodes == nil {
			return errNoKubeNodes
		}
		once = func(ctx context.Context) (bool, error) { return c.kubeNode.run(ctx, r.cfg.KubeNodes) }
		cannot = "the check cannot run"
		// Right after the hub starts, every cluster is unknown until the
		// clusters are loaded: wait for that, out of the step's within.
		wctx, cancel := context.WithTimeout(ctx, d.Within)
		err := r.cfg.KubeNodes.WaitLoaded(wctx)
		cancel()
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil {
			return fmt.Errorf("%s: the Kubernetes clusters did not load within %s", cannot, d.Within)
		}
	}
	if c.talosNode != nil {
		if r.cfg.TalosNodes == nil {
			return errNoTalos
		}
		once = func(ctx context.Context) (bool, error) { return true, c.talosNode.run(ctx, r.cfg.TalosNodes) }
	}
	for {
		ran, err := once(ctx)
		if ctx.Err() != nil {
			return err
		}
		if !ran {
			return fmt.Errorf("%s: %w", cannot, err)
		}
		if err == nil || ctx.Err() != nil {
			return err
		}
		if r.cfg.Now().Add(d.Every).After(deadline) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(d.Every):
		}
	}
}

// runAction takes one action through policy, as the runbook. It has its own
// decision and audit entry on every attempt, rollbacks included.
func (r *Runbooks) runAction(ctx context.Context, rb *Runbook, run *store.RunbookRun, st *RunbookState, a *Step[Action],
	phase string, attempt int,
) error {
	secrets := r.secretsOf(run.ID)
	ev := runbookEvent(rb.ID, run.StartedAt, inputFor(a.Impl, st.Inputs, secrets))
	target, err := a.Impl.Target().Render(ctx, ev)
	if err != nil {
		return scrubSecrets(err, secrets)
	}
	// Policy works on outside ctx, so its audit entry is written whatever
	// happens to ctx, except while it holds the action for approval: a hub
	// stopping must not wait for an operator.
	decideCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	defer cancel()
	req := policy.Request{
		ActorKind: policy.ActorAutomation, ActorID: RunbookActor(rb.ID), Action: a.Impl.Policy(), Target: target,
		Detail: map[string]any{
			"run": run.ID, "step": a.ID, "phase": phase, "attempt": attempt, "started_by": run.StartedBy,
		},
		DryRun: r.cfg.DryRun,
		OnHold: func(string, time.Time) { context.AfterFunc(ctx, cancel) },
	}
	ran := false
	err = doAction(decideCtx, ctx, r.cfg.Policy, req, a.Impl, ev, func(ctx context.Context, ev Event) error {
		ran = true
		return scrubSecrets(a.Impl.Run(ctx, ev), secrets)
	})
	if err != nil && !ran {
		// Policy refused it, or could not write the entry that comes first.
		return definiteFailure{err}
	}
	return err
}

// scrubbedError is an error whose text had secret answers taken out.
type scrubbedError struct {
	msg string
	err error
}

func (e *scrubbedError) Error() string { return e.msg }
func (e *scrubbedError) Unwrap() error { return e.err }

// scrubSecrets takes secret answers out of err's text, which goes into the
// audit log and the run's log.
func scrubSecrets(err error, secrets map[string]string) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	values := make([]string, 0, len(secrets))
	for _, v := range secrets {
		values = append(values, v)
	}
	// Longest first: one secret may contain another.
	slices.SortFunc(values, func(a, b string) int { return len(b) - len(a) })
	for _, v := range values {
		if v != "" {
			msg = strings.ReplaceAll(msg, v, "[secret]")
		}
	}
	if msg == err.Error() {
		return err
	}
	return &scrubbedError{msg: msg, err: err}
}
