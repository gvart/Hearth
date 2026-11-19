// SPDX-License-Identifier: AGPL-3.0-only

package automation

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/gvart/hearth/internal/store"
)

// The states of a runbook run.
const (
	// RunbookRunning runs its steps forward.
	RunbookRunning = "running"
	// RunbookWaiting waits for the answer to a prompt.
	RunbookWaiting = "waiting"
	// RunbookFailed stopped at a step that failed or was denied: an operator
	// retries it or rolls the run back.
	RunbookFailed = "failed"
	// RunbookUnknown stopped at a step whose outcome nobody knows, because the
	// hub running it went away or the answer to it never came: it may or may
	// not have happened. Only an operator can say what to do next.
	RunbookUnknown = "unknown"
	// RunbookRollingBack runs the rollback steps, last completed step first.
	RunbookRollingBack = "rolling_back"
	// RunbookRollbackFailed stopped at a rollback step that failed or was
	// denied: an operator retries it or passes over it.
	RunbookRollbackFailed = "rollback_failed"
	// RunbookSucceeded finished every step.
	RunbookSucceeded = "succeeded"
	// RunbookRolledBack finished rolling back.
	RunbookRolledBack = "rolled_back"
)

// The phases of a run.
const (
	phaseForward  = "forward"
	phaseRollback = "rollback"
)

// Step states, besides those of automation runs.
const (
	stepPending = "pending"
	stepRunning = "running"
	stepWaiting = "waiting"
	stepUnknown = "unknown"
	stepSkipped = "skipped"
)

const (
	// maxRunbookLog is how many log entries a run keeps, the newest.
	maxRunbookLog = 300
	// maxRunbookError bounds an error kept in a run's state.
	maxRunbookError = 1024
)

// RunbookState is the replicated state of a run. It never holds the answer to
// a secret prompt.
type RunbookState struct {
	Phase string `json:"phase"`
	// Cursor is the index of the step the run is at; len(Steps) once all ran.
	Cursor int `json:"cursor"`
	// Awaiting is the prompt step waiting for an answer: the step at the
	// cursor, or a secret prompt answered earlier whose answer was lost when
	// the hub restarted.
	Awaiting string     `json:"awaiting,omitempty"`
	Deadline *time.Time `json:"deadline,omitempty"`
	// Error is why the run could not go on, when no step says so.
	Error string             `json:"error,omitempty"`
	Steps []RunbookStepState `json:"steps"`
	// Inputs are the answers to the prompts that are not secret, by step id.
	Inputs map[string]string `json:"inputs,omitempty"`
	Log    []RunbookLogEntry `json:"log"`
}

// RunbookStepState is the state of one step of a run.
type RunbookStepState struct {
	ID          string             `json:"id"`
	Type        string             `json:"type"`
	What        string             `json:"what"`
	Description string             `json:"description,omitempty"`
	Status      string             `json:"status"`
	Attempts    int                `json:"attempts"`
	Error       string             `json:"error,omitempty"`
	StartedAt   *time.Time         `json:"started_at,omitempty"`
	FinishedAt  *time.Time         `json:"finished_at,omitempty"`
	Deadline    *time.Time         `json:"deadline,omitempty"`
	Prompt      *RunbookPromptJSON `json:"prompt,omitempty"`
	// Rollback is set on a step that declares a rollback.
	Rollback *RunbookRollbackState `json:"rollback,omitempty"`
}

// RunbookPromptJSON is what a prompt step shows the operator.
type RunbookPromptJSON struct {
	Kind    string `json:"kind"`
	Message string `json:"message"`
	Secret  bool   `json:"secret"`
	// TimeoutMS is how long the prompt waits for its answer.
	TimeoutMS int64 `json:"timeout_ms"`
}

// RunbookRollbackState is the state of a step's rollback.
type RunbookRollbackState struct {
	What     string `json:"what"`
	Status   string `json:"status"`
	Attempts int    `json:"attempts"`
	Error    string `json:"error,omitempty"`
}

// RunbookLogEntry is one line of a run's log.
type RunbookLogEntry struct {
	At time.Time `json:"at"`
	// Step is the step it is about, if any.
	Step string `json:"step,omitempty"`
	// Actor is who did it, when a person did.
	Actor   string `json:"actor,omitempty"`
	Message string `json:"message"`
}

// newRunbookState is the state of a run of rb that has not started a step.
func newRunbookState(rb *Runbook) *RunbookState {
	st := &RunbookState{Phase: phaseForward, Steps: make([]RunbookStepState, len(rb.Steps)), Log: []RunbookLogEntry{}}
	for i := range rb.Steps {
		s := &rb.Steps[i]
		st.Steps[i] = RunbookStepState{
			ID: s.ID, Type: s.Type, What: s.What(), Description: s.Description, Status: stepPending,
		}
		if s.Prompt != nil {
			st.Steps[i].Prompt = &RunbookPromptJSON{
				Kind: s.Prompt.Kind, Message: s.Prompt.Message, Secret: s.Prompt.Secret,
				TimeoutMS: s.Prompt.Timeout.Milliseconds(),
			}
		}
		if s.Rollback != nil {
			st.Steps[i].Rollback = &RunbookRollbackState{What: s.Rollback.Impl.Describe(), Status: stepPending}
		}
	}
	return st
}

// decodeRunbookState reads the state of a stored run.
func decodeRunbookState(run store.RunbookRun) (*RunbookState, error) {
	st := &RunbookState{}
	if err := json.Unmarshal(run.State, st); err != nil {
		return nil, fmt.Errorf("decode state of runbook run %s: %w", run.ID, err)
	}
	return st, nil
}

// log adds an entry to the run's log, keeping the newest maxRunbookLog.
func (st *RunbookState) log(at time.Time, step, actor, format string, args ...any) {
	st.Log = append(st.Log, RunbookLogEntry{At: at, Step: step, Actor: actor, Message: fmt.Sprintf(format, args...)})
	if over := len(st.Log) - maxRunbookLog; over > 0 {
		st.Log = append([]RunbookLogEntry(nil), st.Log[over:]...)
	}
}

// step returns the state of the step id, or nil.
func (st *RunbookState) step(id string) *RunbookStepState {
	for i := range st.Steps {
		if st.Steps[i].ID == id {
			return &st.Steps[i]
		}
	}
	return nil
}

// current is the step at the cursor, or nil past the last one.
func (st *RunbookState) current() *RunbookStepState {
	if st.Cursor < 0 || st.Cursor >= len(st.Steps) {
		return nil
	}
	return &st.Steps[st.Cursor]
}

// nextRollback is the index of the rollback step to run: of the steps that
// happened, or may have, the latest whose rollback has not run. It is -1 when
// none is left.
func (st *RunbookState) nextRollback() int {
	for i := min(st.Cursor, len(st.Steps)-1); i >= 0; i-- {
		s := &st.Steps[i]
		if s.Rollback == nil || (s.Status != stepOK && s.Status != stepUnknown) {
			continue
		}
		if s.Rollback.Status == stepPending || s.Rollback.Status == stepRunning {
			return i
		}
	}
	return -1
}

// stoppedRollback is the rollback step the run stopped at, or nil.
func (st *RunbookState) stoppedRollback() *RunbookRollbackState {
	for i := len(st.Steps) - 1; i >= 0; i-- {
		r := st.Steps[i].Rollback
		if r != nil && (r.Status == stepFailed || r.Status == stepDenied || r.Status == stepUnknown) {
			return r
		}
	}
	return nil
}

// runbookFinished reports whether a run in status has ended for good.
func runbookFinished(status string) bool {
	return status == RunbookSucceeded || status == RunbookRolledBack
}

// runbookStopped reports whether a run in status waits for an operator to
// retry or roll back.
func runbookStopped(status string) bool {
	return status == RunbookFailed || status == RunbookUnknown || status == RunbookRollbackFailed
}

// RunbookRunJSON is a run as the API serves it.
type RunbookRunJSON struct {
	ID        string `json:"id"`
	RunbookID string `json:"runbook_id"`
	Status    string `json:"status"`
	// Version is what an operator's decision names, so that it applies to the
	// run as they saw it and to nothing that happened since.
	Version    int64      `json:"version"`
	StartedBy  string     `json:"started_by"`
	StartedAt  time.Time  `json:"started_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
	// CanRetry, CanRollback and CanPassOver say what an operator may do now.
	CanRetry    bool `json:"can_retry"`
	CanRollback bool `json:"can_rollback"`
	CanPassOver bool `json:"can_pass_over"`
	RunbookState
}

// runbookRunJSON is run with its decoded state.
func runbookRunJSON(run store.RunbookRun, st *RunbookState) RunbookRunJSON {
	out := RunbookRunJSON{
		ID: run.ID, RunbookID: run.RunbookID, Status: run.Status, Version: run.Version, StartedBy: run.StartedBy,
		StartedAt: run.StartedAt, UpdatedAt: run.UpdatedAt, RunbookState: *st,
		CanRetry: runbookStopped(run.Status),
	}
	if runbookStopped(run.Status) {
		out.CanRollback = st.Phase != phaseRollback
		out.CanPassOver = st.Phase == phaseRollback && st.stoppedRollback() != nil
	}
	if !run.FinishedAt.IsZero() {
		out.FinishedAt = &run.FinishedAt
	}
	return out
}

// truncateError bounds an error kept in a run's state.
func truncateError(msg string) string {
	if len(msg) <= maxRunbookError {
		return msg
	}
	return strings.ToValidUTF8(msg[:maxRunbookError], "") + "…"
}
