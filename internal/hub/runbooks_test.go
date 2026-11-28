// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/automation"
	"github.com/gvart/hearth/internal/integrations/kubernetes"
	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

// runbookFixture is an API over a real engine, with a webhook to act on that
// fails while fail is set.
type runbookFixture struct {
	*apiFixture
	cookie *http.Cookie
	hits   atomic.Int64
	fail   atomic.Bool
	bodies chan string
	url    string
}

func newRunbookFixture(t *testing.T, yaml func(url string) string) *runbookFixture {
	t.Helper()
	f := &runbookFixture{bodies: make(chan string, 16)}
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.hits.Add(1)
		b := make([]byte, 256)
		n, _ := r.Body.Read(b)
		f.bodies <- string(b[:n])
		if f.fail.Load() {
			w.WriteHeader(http.StatusBadGateway)
		}
	}))
	t.Cleanup(hook.Close)
	f.url = hook.URL

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "rb.yaml"), []byte(yaml(hook.URL)), 0o600); err != nil {
		t.Fatal(err)
	}
	sealer, err := kubernetes.NewSealer([]byte("test secret"))
	if err != nil {
		t.Fatal(err)
	}
	var engine *automation.Runbooks
	f.apiFixture = newAPIFixture(t, true, func(c *Config) {
		kinds := automation.Builtin(slog.New(slog.DiscardHandler))
		for k, v := range automation.Actions(automation.ActionDeps{}) {
			kinds.Actions[k] = v
		}
		engine = automation.NewRunbooks(automation.RunbooksConfig{
			Dir: dir, Kinds: kinds, Policy: c.Policy, Runs: c.Store.RunbookRuns(), Sealer: sealer, Poll: 5 * time.Millisecond,
		})
		c.Runbooks = engine
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = engine.Run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	f.cookie = sessionCookie(t, f.login(t, testPassword))
	return f
}

func (f *runbookFixture) start(t *testing.T) automation.RunbookRunJSON {
	t.Helper()
	resp := f.do(t, http.MethodPost, "/api/v1/runbooks/rb/runs", "", f.cookie)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("start = %d %s", resp.StatusCode, resp.body)
	}
	return decode[automation.RunbookRunJSON](t, resp)
}

// await waits for the run to reach status.
func (f *runbookFixture) await(t *testing.T, id, status string) automation.RunbookRunJSON {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		resp := f.do(t, http.MethodGet, "/api/v1/runbook-runs/"+id, "", f.cookie)
		run := decode[automation.RunbookRunJSON](t, resp)
		if resp.StatusCode == http.StatusOK && run.Status == status {
			return run
		}
		if time.Now().After(deadline) {
			t.Fatalf("run is %q (%d), want %q", run.Status, resp.StatusCode, status)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func (f *runbookFixture) audited(t *testing.T, action policy.Action) []store.AuditEntry {
	t.Helper()
	all, err := f.st.Audit().Query(t.Context(), store.AuditFilter{Actions: []string{string(action)}}, 100)
	if err != nil {
		t.Fatal(err)
	}
	return all
}

// versionBody is the body of an operator's decision on a run at version.
func versionBody(version int64) string {
	return fmt.Sprintf(`{"version":%d}`, version)
}

func retryYAML(url string) string {
	return `id: rb
description: Calls a webhook.
steps:
  - id: call
    type: action
    action: {type: webhook, url: ` + url + `/hook, body: hello}
    rollback: {type: webhook, url: ` + url + `/undo, body: undo}
`
}

func TestRunbookAPINeedsASession(t *testing.T) {
	f := newRunbookFixture(t, retryYAML)
	run := f.start(t)
	f.await(t, run.ID, automation.RunbookSucceeded)
	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/api/v1/runbooks"},
		{http.MethodGet, "/api/v1/runbooks/rb/plan"},
		{http.MethodPost, "/api/v1/runbooks/rb/runs"},
		{http.MethodGet, "/api/v1/runbook-runs"},
		{http.MethodGet, "/api/v1/runbook-runs/" + run.ID},
		{http.MethodPost, "/api/v1/runbook-runs/" + run.ID + "/answer"},
		{http.MethodPost, "/api/v1/runbook-runs/" + run.ID + "/retry"},
		{http.MethodPost, "/api/v1/runbook-runs/" + run.ID + "/rollback"},
		{http.MethodPost, "/api/v1/runbook-runs/" + run.ID + "/pass-over"},
	} {
		if resp := f.do(t, tc.method, tc.path, "", nil); resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s %s without a session = %d, want 401", tc.method, tc.path, resp.StatusCode)
		}
	}
	if resp := f.do(t, http.MethodPost, "/api/v1/runbooks/rb/runs", "", testCookie("forged")); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("start with a forged session = %d, want 401", resp.StatusCode)
	}
	if n := f.hits.Load(); n != 1 {
		t.Errorf("the webhook was called %d times, want 1", n)
	}
}

func TestRunbookAPIListAndPlan(t *testing.T) {
	f := newRunbookFixture(t, retryYAML)
	resp := f.do(t, http.MethodGet, "/api/v1/runbooks", "", f.cookie)
	list := decode[struct {
		Runbooks []RunbookJSON `json:"runbooks"`
		Errors   []string      `json:"errors"`
	}](t, resp)
	if len(list.Runbooks) != 1 || list.Runbooks[0].ID != "rb" || list.Runbooks[0].Steps != 1 || len(list.Errors) != 0 {
		t.Fatalf("list = %+v", list)
	}
	plan := decode[automation.RunbookPlan](t, f.do(t, http.MethodGet, "/api/v1/runbooks/rb/plan", "", f.cookie))
	if len(plan.Steps) != 1 || plan.Steps[0].Decision != policy.Allow || plan.Steps[0].Rollback == nil {
		t.Fatalf("plan = %+v", plan)
	}
	if n := f.hits.Load(); n != 0 {
		t.Errorf("planning called the webhook %d times", n)
	}
	if resp := f.do(t, http.MethodGet, "/api/v1/runbooks/none/plan", "", f.cookie); resp.StatusCode != http.StatusNotFound {
		t.Errorf("plan of an unknown runbook = %d", resp.StatusCode)
	}
	if resp := f.do(t, http.MethodPost, "/api/v1/runbooks/none/runs", "", f.cookie); resp.StatusCode != http.StatusNotFound {
		t.Errorf("start of an unknown runbook = %d", resp.StatusCode)
	}
}

func TestRunbookAPIRetryAndRollback(t *testing.T) {
	f := newRunbookFixture(t, retryYAML)
	f.fail.Store(true)
	run := f.start(t)
	got := f.await(t, run.ID, automation.RunbookFailed)
	if !got.CanRetry || !got.CanRollback || got.Steps[0].Error == "" {
		t.Fatalf("failed run = %+v", got)
	}

	f.fail.Store(false)
	path := "/api/v1/runbook-runs/" + run.ID
	// A decision has to name the version of the run it was made on.
	for _, tc := range []struct {
		op, body string
		want     int
	}{
		{"/retry", "", http.StatusBadRequest},
		{"/rollback", "{}", http.StatusBadRequest},
		{"/pass-over", "", http.StatusBadRequest},
		{"/pass-over", versionBody(got.Version), http.StatusBadRequest}, // it names no step
		{"/retry", versionBody(got.Version - 1), http.StatusConflict},
		{"/rollback", versionBody(got.Version + 1), http.StatusConflict},
		{"/pass-over", fmt.Sprintf(`{"version":%d,"step":"call"}`, got.Version), http.StatusConflict}, // it is not rolling back
	} {
		if resp := f.do(t, http.MethodPost, path+tc.op, tc.body, f.cookie); resp.StatusCode != tc.want {
			t.Errorf("%s with %q = %d, want %d", tc.op, tc.body, resp.StatusCode, tc.want)
		}
	}
	if n := f.hits.Load(); n != 1 {
		t.Fatalf("refused decisions called the webhook: %d calls, want 1", n)
	}
	if resp := f.do(t, http.MethodPost, path+"/retry", versionBody(got.Version), f.cookie); resp.StatusCode != http.StatusOK {
		t.Fatalf("retry = %d %s", resp.StatusCode, resp.body)
	}
	done := f.await(t, run.ID, automation.RunbookSucceeded)
	if n := f.hits.Load(); n != 2 {
		t.Errorf("webhook called %d times, want 2", n)
	}
	// Nothing to retry or roll back any more.
	for _, op := range []string{"/retry", "/rollback"} {
		if resp := f.do(t, http.MethodPost, path+op, versionBody(done.Version), f.cookie); resp.StatusCode != http.StatusConflict {
			t.Errorf("%s of a finished run = %d, want 409", op, resp.StatusCode)
		}
	}
	entries := f.audited(t, policy.RunbookRetry)
	var ok int
	for _, e := range entries {
		if e.ActorKind == policy.ActorWeb && e.ActorID == "127.0.0.1" && e.Result == "ok" {
			ok++
		}
	}
	if ok != 1 {
		t.Errorf("retry audit = %+v", entries)
	}
	if len(f.audited(t, policy.RunbookStart)) != 1 {
		t.Error("the start was not audited")
	}

	// A second run fails and is rolled back from the API.
	f.fail.Store(true)
	second := f.start(t)
	stopped := f.await(t, second.ID, automation.RunbookFailed)
	if resp := f.do(t, http.MethodPost, "/api/v1/runbook-runs/"+second.ID+"/rollback", versionBody(stopped.Version), f.cookie); resp.StatusCode != http.StatusOK {
		t.Fatalf("rollback = %d %s", resp.StatusCode, resp.body)
	}
	f.await(t, second.ID, automation.RunbookRolledBack)
	if len(f.audited(t, policy.RunbookRollback)) == 0 {
		t.Error("the rollback was not audited")
	}
	list := decode[struct {
		Runs []automation.RunbookRunJSON `json:"runs"`
	}](t, f.do(t, http.MethodGet, "/api/v1/runbook-runs?runbook=rb", "", f.cookie))
	if len(list.Runs) != 2 || list.Runs[0].ID != second.ID {
		t.Errorf("runs = %+v", list.Runs)
	}
	if resp := f.do(t, http.MethodGet, "/api/v1/runbook-runs?limit=0", "", f.cookie); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("limit=0 = %d", resp.StatusCode)
	}
	if resp := f.do(t, http.MethodGet, "/api/v1/runbook-runs/none", "", f.cookie); resp.StatusCode != http.StatusNotFound {
		t.Errorf("unknown run = %d", resp.StatusCode)
	}
}

func TestRunbookAPIRefusesAStartOverTooManyUnresolvedRuns(t *testing.T) {
	f := newRunbookFixture(t, retryYAML)
	now := time.Now()
	for i := range store.RunbookRunsKept {
		if err := f.st.RunbookRuns().Create(t.Context(), store.RunbookRun{
			ID: fmt.Sprintf("r%03d", i), RunbookID: "rb", Status: automation.RunbookUnknown, StartedBy: "web/x",
			StartedAt: now, UpdatedAt: now, Source: []byte("x"), State: []byte(`{}`),
		}); err != nil {
			t.Fatal(err)
		}
	}
	resp := f.do(t, http.MethodPost, "/api/v1/runbooks/rb/runs", "", f.cookie)
	if resp.StatusCode != http.StatusConflict || !strings.Contains(string(resp.body), "retry them, roll them back") {
		t.Errorf("start = %d %s, want a refusal that says what to do", resp.StatusCode, resp.body)
	}
	if n := f.hits.Load(); n != 0 {
		t.Errorf("the refused run called the webhook %d times", n)
	}
}

func TestRunbookAPISecretAnswerStaysOut(t *testing.T) {
	const secret = "correct-horse-battery"
	f := newRunbookFixture(t, func(url string) string {
		return `id: rb
steps:
  - id: token
    type: prompt
    message: The token?
    secret: true
  - id: note
    type: prompt
    prompt: confirm
    message: Sure?
  - id: send
    type: action
    action: {type: webhook, url: ` + url + `/hook, body: "t={{ .Input.token }}"}
`
	})
	run := f.start(t)
	f.await(t, run.ID, automation.RunbookWaiting)
	path := "/api/v1/runbook-runs/" + run.ID + "/answer"

	for _, tc := range []struct {
		name, body string
		want       int
	}{
		{"not json", "nope", http.StatusBadRequest},
		{"no step", `{"value":"x"}`, http.StatusBadRequest},
		{"the wrong step", `{"step":"note","value":"yes"}`, http.StatusConflict},
		{"an empty answer", `{"step":"token","value":""}`, http.StatusBadRequest},
	} {
		if resp := f.do(t, http.MethodPost, path, tc.body, f.cookie); resp.StatusCode != tc.want {
			t.Errorf("%s = %d %s, want %d", tc.name, resp.StatusCode, resp.body, tc.want)
		}
	}

	b, _ := json.Marshal(map[string]string{"step": "token", "value": secret})
	resp := f.do(t, http.MethodPost, path, string(b), f.cookie)
	if resp.StatusCode != http.StatusOK || strings.Contains(string(resp.body), secret) {
		t.Fatalf("answer = %d %s", resp.StatusCode, resp.body)
	}
	f.await(t, run.ID, automation.RunbookWaiting)
	if resp := f.do(t, http.MethodPost, path, `{"step":"note","value":"maybe"}`, f.cookie); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("a confirmation that is neither yes nor no = %d", resp.StatusCode)
	}
	if resp := f.do(t, http.MethodPost, path, `{"step":"note","value":"yes"}`, f.cookie); resp.StatusCode != http.StatusOK {
		t.Fatalf("confirm = %d %s", resp.StatusCode, resp.body)
	}
	f.await(t, run.ID, automation.RunbookSucceeded)
	if got := <-f.bodies; got != "t="+secret {
		t.Errorf("webhook body = %q", got)
	}

	shown := f.do(t, http.MethodGet, "/api/v1/runbook-runs/"+run.ID, "", f.cookie)
	stored, err := f.st.RunbookRuns().Get(t.Context(), run.ID)
	if err != nil {
		t.Fatal(err)
	}
	audit, err := f.st.Audit().List(t.Context(), 100)
	if err != nil {
		t.Fatal(err)
	}
	auditJSON, _ := json.Marshal(audit)
	for what, s := range map[string]string{
		"the API": string(shown.body), "the stored state": string(stored.State), "the audit log": string(auditJSON),
		"the hub log": f.logs.String(),
	} {
		if strings.Contains(s, secret) {
			t.Errorf("the secret is in %s", what)
		}
	}
	if strings.Contains(string(stored.Source), "The token?") {
		t.Error("the stored copy of the runbook file is not sealed")
	}
}

func TestRunbookAPISecretOnAFollowerIsRefused(t *testing.T) {
	st := newTestStore(t)
	sealer, err := kubernetes.NewSealer([]byte("test secret"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "rb.yaml"), []byte(`id: rb
steps:
  - id: token
    type: prompt
    message: The token
    secret: true
`), 0o600); err != nil {
		t.Fatal(err)
	}
	// This engine never runs: the hub serving the API is a follower.
	follower := automation.NewRunbooks(automation.RunbooksConfig{
		Dir: dir, Kinds: automation.Builtin(slog.New(slog.DiscardHandler)), Policy: policy.New(st.Audit()),
		Runs: st.RunbookRuns(), Sealer: sealer,
	})
	leader := automation.NewRunbooks(automation.RunbooksConfig{
		Dir: dir, Kinds: automation.Builtin(slog.New(slog.DiscardHandler)), Policy: policy.New(st.Audit()),
		Runs: st.RunbookRuns(), Sealer: sealer, Poll: 5 * time.Millisecond,
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = leader.Run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	run, err := leader.Start(ctx, policy.ActorWeb, "x", "rb")
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		r, err := leader.GetRun(ctx, run.ID)
		if err == nil && r.Status == automation.RunbookWaiting {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the run never reached its prompt")
		}
		time.Sleep(5 * time.Millisecond)
	}
	_, err = follower.Answer(ctx, policy.ActorWeb, "x", run.ID, "token", "s3cret")
	if !errors.Is(err, automation.ErrRunbookNotLeading) {
		t.Fatalf("err = %v", err)
	}
	a := &api{log: slog.New(slog.DiscardHandler), leadership: soloLeadership{}}
	rec := httptest.NewRecorder()
	a.writeRunbookError(rec, httptest.NewRequest(http.MethodPost, "/", nil), "answer", err)
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "not_leader") {
		t.Errorf("answered %d %s", rec.Code, rec.Body)
	}
}

// A runbook save refused on the minority side of a split answers its own
// reason, not the generic cluster_unavailable one (#307).
func TestRunbookErrorClusterSplit(t *testing.T) {
	a := &api{log: slog.New(slog.DiscardHandler), leadership: soloLeadership{}}
	rec := httptest.NewRecorder()
	err := fmt.Errorf("save runbook run r1: apply save_runbook_run: 1 of 3 replicas of its key reachable, 2 needed: %w", store.ErrNoMajority)
	a.writeRunbookError(rec, httptest.NewRequest(http.MethodPost, "/", nil), "retry runbook run", err)
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), `"cluster_split"`) ||
		!strings.Contains(rec.Body.String(), "runbook steps need a majority of masters; retry when the cluster heals") {
		t.Errorf("answered %d %s", rec.Code, rec.Body)
	}
}
