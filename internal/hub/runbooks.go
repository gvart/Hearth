// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/gvart/hearth/internal/automation"
	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

const (
	// runbookRunsListed is how many runs GET /api/v1/runbook-runs returns by
	// default, and maxRunbookRunsListed the most it returns.
	runbookRunsListed    = 50
	maxRunbookRunsListed = 200
	// maxRunbookAnswerBody bounds the body of a prompt's answer.
	maxRunbookAnswerBody = 16 << 10
)

// runbookRoutes serves the runbooks. Every route needs a signed-in session.
func (a *api) runbookRoutes(mux *http.ServeMux) {
	if a.runbooks == nil {
		return
	}
	mux.Handle("GET /api/v1/runbooks", a.auth(a.listRunbooks))
	mux.Handle("GET /api/v1/runbooks/{id}/plan", a.auth(a.planRunbook))
	mux.Handle("POST /api/v1/runbooks/{id}/runs", a.auth(a.startRunbook))
	mux.Handle("GET /api/v1/runbook-runs", a.auth(a.listRunbookRuns))
	mux.Handle("GET /api/v1/runbook-runs/{id}", a.auth(a.getRunbookRun))
	mux.Handle("POST /api/v1/runbook-runs/{id}/answer", a.auth(a.answerRunbookRun))
	mux.Handle("POST /api/v1/runbook-runs/{id}/retry", a.auth(a.retryRunbookRun))
	mux.Handle("POST /api/v1/runbook-runs/{id}/rollback", a.auth(a.rollbackRunbookRun))
	mux.Handle("POST /api/v1/runbook-runs/{id}/pass-over", a.auth(a.passOverRunbookRun))
}

// RunbookJSON is a runbook in the list.
type RunbookJSON struct {
	ID          string `json:"id"`
	Description string `json:"description,omitempty"`
	Steps       int    `json:"steps"`
}

// listRunbooks serves the valid runbooks, and what is wrong with the others.
func (a *api) listRunbooks(w http.ResponseWriter, r *http.Request) {
	all, errs := a.runbooks.List(r.Context())
	out := struct {
		Runbooks []RunbookJSON `json:"runbooks"`
		Errors   []string      `json:"errors"`
	}{Runbooks: make([]RunbookJSON, 0, len(all)), Errors: make([]string, 0, len(errs))}
	for _, rb := range all {
		out.Runbooks = append(out.Runbooks, RunbookJSON{ID: rb.ID, Description: rb.Description, Steps: len(rb.Steps)})
	}
	for _, err := range errs {
		out.Errors = append(out.Errors, err.Error())
	}
	writeJSON(w, http.StatusOK, out)
}

// planRunbook serves what a run would do. It runs nothing.
func (a *api) planRunbook(w http.ResponseWriter, r *http.Request) {
	plan, err := a.runbooks.Plan(r.Context(), r.PathValue("id"))
	if err != nil {
		a.writeRunbookError(w, r, "plan runbook", err)
		return
	}
	writeJSON(w, http.StatusOK, plan)
}

func (a *api) startRunbook(w http.ResponseWriter, r *http.Request) {
	run, err := a.runbooks.Start(r.Context(), policy.ActorWeb, remoteHost(r), r.PathValue("id"))
	if err != nil {
		a.writeRunbookError(w, r, "start runbook", err)
		return
	}
	writeJSON(w, http.StatusCreated, run)
}

// listRunbookRuns serves the newest runs, of ?runbook= if given.
func (a *api) listRunbookRuns(w http.ResponseWriter, r *http.Request) {
	limit := runbookRunsListed
	if q := r.URL.Query().Get("limit"); q != "" {
		n, err := strconv.Atoi(q)
		if err != nil || n <= 0 || n > maxRunbookRunsListed {
			writeError(w, http.StatusBadRequest, "bad_request", "limit must be between 1 and 200")
			return
		}
		limit = n
	}
	runs, err := a.runbooks.Runs(r.Context(), r.URL.Query().Get("runbook"), limit)
	if err != nil {
		a.writeRunbookError(w, r, "list runbook runs", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"runs": runs})
}

func (a *api) getRunbookRun(w http.ResponseWriter, r *http.Request) {
	run, err := a.runbooks.GetRun(r.Context(), r.PathValue("id"))
	if err != nil {
		a.writeRunbookError(w, r, "get runbook run", err)
		return
	}
	writeJSON(w, http.StatusOK, run)
}

// answerRunbookRun answers a prompt. The answer is never logged or echoed.
func (a *api) answerRunbookRun(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Step  string `json:"step"`
		Value string `json:"value"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRunbookAnswerBody)).Decode(&body); err != nil || body.Step == "" {
		writeError(w, http.StatusBadRequest, "bad_request", `body must be {"step": "...", "value": "..."}`)
		return
	}
	run, err := a.runbooks.Answer(r.Context(), policy.ActorWeb, remoteHost(r), r.PathValue("id"), body.Step, body.Value)
	if err != nil {
		a.writeRunbookError(w, r, "answer runbook prompt", err)
		return
	}
	writeJSON(w, http.StatusOK, run)
}

// decideRunbookRun serves an operator's decision on a stopped run. The body
// names the version of the run it was made on, so that a repeated or late
// request never applies to what the run has become since.
func (a *api) decideRunbookRun(w http.ResponseWriter, r *http.Request, what string,
	decide func(ctx context.Context, actorKind, actorID, runID string, version int64) (automation.RunbookRunJSON, error),
) {
	var body struct {
		Version int64 `json:"version"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRunbookAnswerBody)).Decode(&body); err != nil || body.Version <= 0 {
		writeError(w, http.StatusBadRequest, "bad_request", `body must be {"version": <the run's version>}`)
		return
	}
	run, err := decide(r.Context(), policy.ActorWeb, remoteHost(r), r.PathValue("id"), body.Version)
	if err != nil {
		a.writeRunbookError(w, r, what, err)
		return
	}
	writeJSON(w, http.StatusOK, run)
}

func (a *api) retryRunbookRun(w http.ResponseWriter, r *http.Request) {
	a.decideRunbookRun(w, r, "retry runbook step", a.runbooks.Retry)
}

func (a *api) rollbackRunbookRun(w http.ResponseWriter, r *http.Request) {
	a.decideRunbookRun(w, r, "roll back runbook run", a.runbooks.Rollback)
}

func (a *api) passOverRunbookRun(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Version int64  `json:"version"`
		Step    string `json:"step"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRunbookAnswerBody)).Decode(&body); err != nil ||
		body.Version <= 0 || body.Step == "" {
		writeError(w, http.StatusBadRequest, "bad_request", `body must be {"version": <the run's version>, "step": <the step passed over>}`)
		return
	}
	run, err := a.runbooks.PassOver(r.Context(), policy.ActorWeb, remoteHost(r), r.PathValue("id"), body.Step, body.Version)
	if err != nil {
		a.writeRunbookError(w, r, "pass over runbook rollback step", err)
		return
	}
	writeJSON(w, http.StatusOK, run)
}

// writeRunbookError answers a failed runbook request.
func (a *api) writeRunbookError(w http.ResponseWriter, r *http.Request, what string, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "no such runbook or run")
	case errors.Is(err, automation.ErrRunbookAnswer):
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
	case errors.Is(err, automation.ErrRunbookNotLeading):
		msg := "a secret answer is kept in the leader's memory only: answer on the leading hub"
		if u := a.leadership.LeaderAgentURL(); u != "" {
			msg += " (" + u + ")"
		}
		if a.masters != nil {
			owner := a.masters.OwnerOf(r.PathValue("id"))
			msg = "a secret answer is kept in the memory of the hub running the run only: answer on hub " + owner
			if u := a.masters.AgentURLOf(r.Context(), owner); u != "" {
				msg += " (" + u + ")"
			}
		}
		writeError(w, http.StatusConflict, "not_leader", msg)
	case errors.Is(err, automation.ErrRunbookState), errors.Is(err, store.ErrRunbookRunConflict):
		writeError(w, http.StatusConflict, "conflict", "the run has moved on: reload it and try again")
	case errors.Is(err, store.ErrRunbookRunsUnresolved):
		writeError(w, http.StatusConflict, "runs_unresolved", fmt.Sprintf(
			"this runbook has %d runs of unknown outcome or with a stopped rollback: retry them, roll them back or pass over their rollback step before starting another",
			store.RunbookRunsKept))
	case errors.Is(err, store.ErrSchemaTooOld):
		writeError(w, http.StatusConflict, "schema_too_old", "run `hearth cluster migrate` to use runbooks on this cluster")
	case errors.Is(err, policy.ErrDenied):
		writeError(w, http.StatusForbidden, "forbidden", "denied by policy")
	case errors.Is(err, store.ErrUnavailable):
		writeUnavailable(w)
	default:
		a.log.ErrorContext(r.Context(), what, "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "cannot "+what)
	}
}
