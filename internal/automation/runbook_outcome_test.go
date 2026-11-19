// SPDX-License-Identifier: AGPL-3.0-only

package automation

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

// failingSealer refuses to seal, so a run is never saved.
type failingSealer struct{ xorSealer }

func (failingSealer) Seal(string, []byte) ([]byte, error) {
	return nil, errors.New("the sealer is broken")
}

// outcomeOf refuses the audit entries that report how action ended.
func outcomeOf(action policy.Action) func(store.AuditEntry) error {
	return func(e store.AuditEntry) error {
		if e.Action == string(action) && e.Result != policy.Started {
			return errors.New("the audit log is unavailable")
		}
		return nil
	}
}

const outcomeRunbook = `id: rb
steps:
  - id: step
    type: action
    action: {type: script, name: flaky}
`

// TestRunbookStartWhoseOutcomeWasNotRecorded: a run that was saved exists, so
// Start reports it and an operator does not start a second one. A start that
// never saved its run is still an error.
func TestRunbookStartWhoseOutcomeWasNotRecorded(t *testing.T) {
	for _, tc := range []struct {
		name    string
		sealer  RunbookSealer
		fail    func(store.AuditEntry) error
		wantRun bool
	}{
		{"the run was saved, its outcome was not recorded", xorSealer{}, outcomeOf(policy.RunbookStart), true},
		{"the run was not saved, its outcome was not recorded either", failingSealer{}, outcomeOf(policy.RunbookStart), false},
		{"the first audit entry could not be written", xorSealer{}, func(e store.AuditEntry) error {
			if e.Action == string(policy.RunbookStart) && e.Result == policy.Started {
				return store.ErrUnavailable
			}
			return nil
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newRBHarness(t, outcomeRunbook, policy.Config{})
			h.rb = NewRunbooks(RunbooksConfig{
				Dir: h.dir, Kinds: h.kinds, Runs: h.st.RunbookRuns(), Sealer: tc.sealer, Poll: 5 * time.Millisecond,
				Policy: policy.NewWithConfig(&failingAudit{fail: tc.fail}, nil, h.cfg),
			})
			run, err := h.rb.Start(t.Context(), policy.ActorWeb, "10.0.0.9", "rb")
			runs, lerr := h.st.RunbookRuns().List(t.Context(), "rb", 10)
			if lerr != nil {
				t.Fatal(lerr)
			}
			if !tc.wantRun {
				if err == nil {
					t.Fatalf("Start = %+v, want an error", run)
				}
				if len(runs) != 0 {
					t.Errorf("stored runs = %d, want none", len(runs))
				}
				return
			}
			if err != nil || run.ID == "" || run.Status != RunbookRunning {
				t.Fatalf("Start = %+v, %v, want the run that exists", run, err)
			}
			if len(runs) != 1 || runs[0].ID != run.ID {
				t.Errorf("stored runs = %d, want the one reported", len(runs))
			}
		})
	}
}

// TestRunbookRetryWhoseOutcomeWasNotRecorded: a retry that was saved is
// reported, and one that was refused is an error.
func TestRunbookRetryWhoseOutcomeWasNotRecorded(t *testing.T) {
	for _, tc := range []struct {
		name  string
		stale bool
	}{
		{"the retry was saved, its outcome was not recorded", false},
		{"the run had moved on, the outcome was not recorded either", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newRBHarness(t, outcomeRunbook, policy.Config{})
			h.script.failNext("flaky", 1)
			stop := h.run(h.rb)
			id := h.start("rb")
			h.await(id, RunbookFailed)
			stop()
			version := runVersion(t, h, id)
			if tc.stale {
				version++
			}
			failing := h.engineAuditingTo(&failingAudit{fail: outcomeOf(policy.RunbookRetry)})
			run, err := failing.Retry(t.Context(), policy.ActorWeb, "10.0.0.9", id, version)
			if tc.stale {
				if err == nil {
					t.Fatalf("Retry = %+v, want an error", run)
				}
				if got := h.get(id).Status; got != RunbookFailed {
					t.Errorf("run is %s, want it left failed", got)
				}
				return
			}
			if err != nil || run.ID != id || run.Status != RunbookRunning {
				t.Fatalf("Retry = %+v, %v, want the retried run", run, err)
			}
		})
	}
}

// TestWebhookWriteOutcome: a write answered with a gateway timeout may still
// complete. A definite refusal, and a read, did nothing.
func TestWebhookWriteOutcome(t *testing.T) {
	for _, tc := range []struct {
		method    string
		code      int
		uncertain bool
	}{
		{http.MethodPost, http.StatusGatewayTimeout, true},
		{http.MethodPut, http.StatusGatewayTimeout, true},
		{http.MethodPatch, http.StatusGatewayTimeout, true},
		{http.MethodDelete, http.StatusGatewayTimeout, true},
		{http.MethodGet, http.StatusGatewayTimeout, false},
		{http.MethodPost, http.StatusBadRequest, false},
		{http.MethodPost, http.StatusForbidden, false},
		{http.MethodPut, http.StatusNotFound, false},
		{http.MethodPatch, http.StatusConflict, false},
		{http.MethodPost, http.StatusUnprocessableEntity, false},
		{http.MethodPost, http.StatusBadGateway, false},
	} {
		t.Run(tc.method+" "+strconv.Itoa(tc.code), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(tc.code) }))
			t.Cleanup(srv.Close)
			a := &webhookAction{client: srv.Client(), method: tc.method, url: srv.URL, timeout: time.Second, site: srv.URL}
			err := a.Run(t.Context(), Event{})
			if err == nil {
				t.Fatal("the request succeeded")
			}
			if got := errors.Is(err, ErrOutcomeUnknown); got != tc.uncertain {
				t.Errorf("Run = %v: unknown %v, want %v", err, got, tc.uncertain)
			}
			if got := outcomeUncertain(err); got != tc.uncertain {
				t.Errorf("outcomeUncertain = %v, want %v", got, tc.uncertain)
			}
		})
	}
}
