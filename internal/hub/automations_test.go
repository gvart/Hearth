// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/automation"
	"github.com/gvart/hearth/internal/policy"
	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
	"github.com/gvart/hearth/internal/store"
)

// spyAgents counts what reaches a device. ceiling, when set, is what its
// Check answers.
type spyAgents struct {
	execs   atomic.Int32
	ceiling error
}

func (s *spyAgents) Exec(context.Context, string, *agentv1.ExecRequest) (*agentv1.ExecResult, error) {
	s.execs.Add(1)
	return &agentv1.ExecResult{}, nil
}

func (s *spyAgents) Check(context.Context, string, *agentv1.ExecRequest) error { return s.ceiling }

// spyNotifier knows one channel and counts what is sent to it.
type spyNotifier struct{ sends atomic.Int32 }

func (*spyNotifier) Has(channel string) bool { return channel == "phone" }

func (s *spyNotifier) Send(context.Context, string, string, string) error {
	s.sends.Add(1)
	return nil
}

type automationFixture struct {
	*apiFixture
	dir      string
	cookie   *http.Cookie
	agents   *spyAgents
	notifier *spyNotifier
	hooks    *atomic.Int32
	hookURL  string
}

func newAutomationFixture(t *testing.T, cfg policy.Config) *automationFixture {
	t.Helper()
	st := newTestStore(t)
	log := slog.New(slog.DiscardHandler)
	hooks := &atomic.Int32{}
	hook := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hooks.Add(1) }))
	t.Cleanup(hook.Close)
	agents, notifier := &spyAgents{}, &spyNotifier{}
	kinds := automation.Builtin(log)
	maps.Copy(kinds.Triggers, automation.Triggers(automation.TriggerDeps{}))
	maps.Copy(kinds.Actions, automation.Actions(automation.ActionDeps{Agents: agents, Notifier: notifier}))
	dir := filepath.Join(t.TempDir(), "automations")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	pol := policy.NewWithConfig(st.Audit(), st.Approvals(), cfg)
	a := newAPI(Config{
		Store: st, Policy: pol, Log: log, Registry: NewRegistry(RegistryConfig{Store: st, Log: log}),
		AutomationsDir: dir, AutomationKinds: kinds,
	})
	srv := httptest.NewServer(a.routes())
	t.Cleanup(srv.Close)
	if err := st.Admin().CreateSession(t.Context(), "auto-session", time.Now(), time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	return &automationFixture{
		apiFixture: &apiFixture{api: a, srv: srv, st: st}, dir: dir, cookie: testCookie("auto-session"),
		agents: agents, notifier: notifier, hooks: hooks, hookURL: hook.URL,
	}
}

func saveBody(t *testing.T, yaml, revision string) string {
	t.Helper()
	b, err := json.Marshal(map[string]string{"yaml": yaml, "revision": revision})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func (f *automationFixture) files(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(f.dir)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

func (f *automationFixture) write(t *testing.T, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(f.dir, name), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func (f *automationFixture) read(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(f.dir, name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// applyAudit returns the audit entries of saves.
func (f *automationFixture) applyAudit(t *testing.T) []store.AuditEntry {
	t.Helper()
	entries, err := f.st.Audit().Query(t.Context(), store.AuditFilter{Actions: []string{string(policy.AutomationApply)}}, 50)
	if err != nil {
		t.Fatal(err)
	}
	return entries
}

const helloYAML = `# keep this comment
id: hello   # and this one
triggers:
  - type: manual
actions:
  - type: log
    message: hi
`

func TestAutomationAPIRequiresSession(t *testing.T) {
	f := newAutomationFixture(t, policy.Config{})
	f.write(t, "hello.yaml", helloYAML)
	body := saveBody(t, strings.Replace(helloYAML, "hi", "changed", 1), automation.Revision([]byte(helloYAML)))
	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/api/v1/automations"},
		{http.MethodGet, "/api/v1/automations/hello"},
		{http.MethodPost, "/api/v1/automations"},
		{http.MethodPost, "/api/v1/automations/dry-run"},
		{http.MethodPut, "/api/v1/automations/hello"},
	} {
		for name, cookie := range map[string]*http.Cookie{"no cookie": nil, "unknown session": testCookie("forged")} {
			if resp := f.do(t, tc.method, tc.path, body, cookie); resp.StatusCode != http.StatusUnauthorized {
				t.Errorf("%s %s with %s: status %d, want 401", tc.method, tc.path, name, resp.StatusCode)
			}
		}
	}
	if got := f.read(t, "hello.yaml"); got != helloYAML {
		t.Errorf("file changed without a session:\n%s", got)
	}
	if got := f.applyAudit(t); len(got) != 0 {
		t.Errorf("unauthenticated requests reached policy: %+v", got)
	}
}

func TestAutomationSaveWritesExactBytesAndAudits(t *testing.T) {
	f := newAutomationFixture(t, policy.Config{})
	hookURL := "https://hooks.example/s3cr3t-token"
	yaml := helloYAML + "  - type: webhook\n    url: " + hookURL + "\n"
	resp := f.do(t, http.MethodPost, "/api/v1/automations", saveBody(t, yaml, ""), f.cookie)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create: status %d: %s", resp.StatusCode, resp.body)
	}
	if got := f.read(t, "hello.yaml"); got != yaml {
		t.Errorf("file is not what was sent:\n%s", got)
	}

	var src AutomationSourceJSON
	got := f.do(t, http.MethodGet, "/api/v1/automations/hello", "", f.cookie)
	if err := json.Unmarshal(got.body, &src); err != nil {
		t.Fatal(err)
	}
	if src.YAML != yaml || src.Revision != automation.Revision([]byte(yaml)) {
		t.Errorf("get answered %+v", src)
	}

	edited := strings.Replace(yaml, "message: hi", "message: bye", 1)
	if resp := f.do(t, http.MethodPut, "/api/v1/automations/hello", saveBody(t, edited, src.Revision), f.cookie); resp.StatusCode != http.StatusOK {
		t.Fatalf("update: status %d: %s", resp.StatusCode, resp.body)
	}
	if got := f.read(t, "hello.yaml"); got != edited {
		t.Errorf("file is not the edit:\n%s", got)
	}

	audit := f.applyAudit(t)
	if len(audit) != 2 {
		t.Fatalf("got %d audit entries, want one per save: %+v", len(audit), audit)
	}
	for _, e := range audit {
		if e.ActorKind != policy.ActorWeb || e.Decision != policy.Allow || e.Result != "ok" || e.Target != "hello" {
			t.Errorf("audit entry %+v", e)
		}
		if strings.Contains(string(e.Detail), "s3cr3t") {
			t.Errorf("audit detail holds the webhook's secret: %s", e.Detail)
		}
	}
}

func TestAutomationSaveDeniedByPolicy(t *testing.T) {
	f := newAutomationFixture(t, policy.Config{
		Actors: map[string]map[policy.Class]policy.Mode{policy.ActorWeb: {policy.Dangerous: policy.ModeDeny}},
	})
	if resp := f.do(t, http.MethodPost, "/api/v1/automations", saveBody(t, helloYAML, ""), f.cookie); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("create: status %d, want 403: %s", resp.StatusCode, resp.body)
	}
	if got := f.files(t); len(got) != 0 {
		t.Errorf("a denied save wrote %v", got)
	}

	f.write(t, "hello.yaml", helloYAML)
	edited := strings.Replace(helloYAML, "hi", "bye", 1)
	body := saveBody(t, edited, automation.Revision([]byte(helloYAML)))
	if resp := f.do(t, http.MethodPut, "/api/v1/automations/hello", body, f.cookie); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("update: status %d, want 403: %s", resp.StatusCode, resp.body)
	}
	if got := f.read(t, "hello.yaml"); got != helloYAML {
		t.Errorf("a denied save changed the file:\n%s", got)
	}
	audit := f.applyAudit(t)
	if len(audit) != 2 {
		t.Fatalf("got %d audit entries, want 2: %+v", len(audit), audit)
	}
	for _, e := range audit {
		if e.Decision != policy.Deny {
			t.Errorf("audit entry %+v, want a denial", e)
		}
	}
}

// heldSave starts a save that policy holds, and returns its approval's id and
// the channel of its answer.
func heldSave(t *testing.T, f *automationFixture, method, path, body string) (string, <-chan apiResp) {
	t.Helper()
	done := make(chan apiResp, 1)
	go func() { done <- f.do(t, method, path, body, f.cookie) }()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		pending, err := f.st.Approvals().List(t.Context(), store.ApprovalPending, 10)
		if err != nil {
			t.Fatal(err)
		}
		if len(pending) == 1 {
			return pending[0].ID, done
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("the save was not held for approval")
	return "", nil
}

func TestAutomationSaveHeldForApproval(t *testing.T) {
	confirm := policy.Config{Actors: map[string]map[policy.Class]policy.Mode{policy.ActorWeb: {policy.Dangerous: policy.ModeConfirm}}}
	revision := automation.Revision([]byte(helloYAML))
	edited := strings.Replace(helloYAML, "hi", "bye", 1)

	t.Run("approved", func(t *testing.T) {
		f := newAutomationFixture(t, confirm)
		f.write(t, "hello.yaml", helloYAML)
		id, done := heldSave(t, f, http.MethodPut, "/api/v1/automations/hello", saveBody(t, edited, revision))
		if got := f.read(t, "hello.yaml"); got != helloYAML {
			t.Fatalf("written before approval:\n%s", got)
		}
		if err := f.api.policy.Decide(t.Context(), policy.ActorAdmin, "op", id, true); err != nil {
			t.Fatal(err)
		}
		if resp := <-done; resp.StatusCode != http.StatusOK {
			t.Fatalf("status %d: %s", resp.StatusCode, resp.body)
		}
		if got := f.read(t, "hello.yaml"); got != edited {
			t.Errorf("not written after approval:\n%s", got)
		}
	})

	t.Run("denied", func(t *testing.T) {
		f := newAutomationFixture(t, confirm)
		f.write(t, "hello.yaml", helloYAML)
		id, done := heldSave(t, f, http.MethodPut, "/api/v1/automations/hello", saveBody(t, edited, revision))
		if err := f.api.policy.Decide(t.Context(), policy.ActorAdmin, "op", id, false); err != nil {
			t.Fatal(err)
		}
		if resp := <-done; resp.StatusCode != http.StatusForbidden {
			t.Fatalf("status %d, want 403: %s", resp.StatusCode, resp.body)
		}
		if got := f.read(t, "hello.yaml"); got != helloYAML {
			t.Errorf("written after a denial:\n%s", got)
		}
	})

	t.Run("file changed while held", func(t *testing.T) {
		f := newAutomationFixture(t, confirm)
		f.write(t, "hello.yaml", helloYAML)
		id, done := heldSave(t, f, http.MethodPut, "/api/v1/automations/hello", saveBody(t, edited, revision))
		theirs := strings.Replace(helloYAML, "hi", "theirs", 1)
		f.write(t, "hello.yaml", theirs)
		if err := f.api.policy.Decide(t.Context(), policy.ActorAdmin, "op", id, true); err != nil {
			t.Fatal(err)
		}
		if resp := <-done; resp.StatusCode != http.StatusConflict {
			t.Fatalf("status %d, want 409: %s", resp.StatusCode, resp.body)
		}
		if got := f.read(t, "hello.yaml"); got != theirs {
			t.Errorf("overwrote a newer file:\n%s", got)
		}
	})
}

func TestAutomationIDPathTraversal(t *testing.T) {
	f := newAutomationFixture(t, policy.Config{})
	outside := filepath.Join(filepath.Dir(f.dir), "outside.yaml")
	if err := os.WriteFile(outside, []byte(helloYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{
		"..%2Foutside",
		"..%2f..%2f..%2fetc%2fpasswd",
		"%2e%2e%2foutside",
		"..%5Coutside",
		"a%2Fb",
		"%2Fetc%2Fpasswd",
		"outside.yaml",
		"hello.yaml",
		"Hello",
		".hidden",
		"-dash",
		"hello%00",
		strings.Repeat("a", 65),
	} {
		t.Run(id, func(t *testing.T) {
			for _, method := range []string{http.MethodGet, http.MethodPut} {
				resp := f.do(t, method, "/api/v1/automations/"+id, saveBody(t, helloYAML, ""), f.cookie)
				if resp.StatusCode != http.StatusBadRequest {
					t.Errorf("%s: status %d, want 400: %s", method, resp.StatusCode, resp.body)
				}
			}
		})
	}
	for _, id := range []string{"../outside", "../../etc/passwd", "/etc/passwd", `..\outside`, "a/b", "hello.yaml"} {
		t.Run("in the file: "+id, func(t *testing.T) {
			yaml := fmt.Sprintf("id: %q\ntriggers: [{type: manual}]\nactions: [{type: log, message: hi}]\n", id)
			resp := f.do(t, http.MethodPost, "/api/v1/automations", saveBody(t, yaml, ""), f.cookie)
			if resp.StatusCode != http.StatusUnprocessableEntity {
				t.Errorf("status %d, want 422: %s", resp.StatusCode, resp.body)
			}
		})
	}
	if got := f.files(t); len(got) != 0 {
		t.Errorf("wrote into the directory: %v", got)
	}
	if b, err := os.ReadFile(outside); err != nil || string(b) != helloYAML {
		t.Errorf("the file outside the directory changed: %q, %v", b, err)
	}
	entries, err := os.ReadDir(filepath.Dir(f.dir))
	if err != nil || len(entries) != 2 {
		t.Errorf("files appeared next to the directory: %v, %v", entries, err)
	}
}

func TestAutomationSaveRefused(t *testing.T) {
	revision := automation.Revision([]byte(helloYAML))
	other := strings.ReplaceAll(helloYAML, "hello", "other")
	for _, tc := range []struct {
		name        string
		setup       func(t *testing.T, f *automationFixture)
		method      string
		path        string
		body        string
		revision    string
		contentType string
		status      int
		code        string
	}{
		{
			name: "invalid yaml", method: http.MethodPost, path: "/api/v1/automations",
			body: "id: [", status: http.StatusUnprocessableEntity, code: "invalid",
		},
		{
			name: "unknown step field", method: http.MethodPost, path: "/api/v1/automations",
			body:   strings.Replace(helloYAML, "message: hi", "mesage: hi", 1),
			status: http.StatusUnprocessableEntity, code: "invalid",
		},
		{
			// Only the hub's real kinds know its channels: the file would
			// otherwise stop every automation from reloading.
			name: "notification channel the hub lacks", method: http.MethodPost, path: "/api/v1/automations",
			body:   "id: a\ntriggers: [{type: manual}]\nactions: [{type: notify, channel: nope, message: hi}]\n",
			status: http.StatusUnprocessableEntity, code: "invalid",
		},
		{
			name:   "id changed",
			setup:  func(t *testing.T, f *automationFixture) { f.write(t, "hello.yaml", helloYAML) },
			method: http.MethodPut, path: "/api/v1/automations/hello", body: other, revision: revision,
			status: http.StatusBadRequest, code: "id_mismatch",
		},
		{
			name:   "stale revision",
			setup:  func(t *testing.T, f *automationFixture) { f.write(t, "hello.yaml", helloYAML) },
			method: http.MethodPut, path: "/api/v1/automations/hello", body: helloYAML, revision: "stale",
			status: http.StatusConflict, code: "revision_conflict",
		},
		{
			name: "update of nothing", method: http.MethodPut, path: "/api/v1/automations/hello", body: helloYAML,
			status: http.StatusNotFound, code: "not_found",
		},
		{
			name:   "create over an id in use",
			setup:  func(t *testing.T, f *automationFixture) { f.write(t, "custom-name.yaml", helloYAML) },
			method: http.MethodPost, path: "/api/v1/automations", body: helloYAML,
			status: http.StatusConflict, code: "exists",
		},
		{
			name:   "create over a file named after the id",
			setup:  func(t *testing.T, f *automationFixture) { f.write(t, "hello.yaml", other) },
			method: http.MethodPost, path: "/api/v1/automations", body: helloYAML,
			status: http.StatusConflict, code: "exists",
		},
		{
			name:   "another file is invalid",
			setup:  func(t *testing.T, f *automationFixture) { f.write(t, "broken.yaml", "id: broken\n") },
			method: http.MethodPost, path: "/api/v1/automations", body: helloYAML,
			status: http.StatusConflict, code: "directory_invalid",
		},
		{
			name: "symlink",
			setup: func(t *testing.T, f *automationFixture) {
				target := filepath.Join(t.TempDir(), "elsewhere.yaml")
				if err := os.WriteFile(target, []byte(helloYAML), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, filepath.Join(f.dir, "hello.yaml")); err != nil {
					t.Fatal(err)
				}
			},
			method: http.MethodPut, path: "/api/v1/automations/hello", body: helloYAML, revision: revision,
			status: http.StatusConflict, code: "not_regular",
		},
		{
			name: "too large", method: http.MethodPost, path: "/api/v1/automations",
			body:   helloYAML + "# " + strings.Repeat("x", maxAutomationBytes) + "\n",
			status: http.StatusRequestEntityTooLarge, code: "too_large",
		},
		{
			name: "not json", method: http.MethodPost, path: "/api/v1/automations", body: helloYAML,
			contentType: "text/plain", status: http.StatusUnsupportedMediaType, code: "bad_request",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newAutomationFixture(t, policy.Config{})
			if tc.setup != nil {
				tc.setup(t, f)
			}
			before := f.files(t)
			contentType := tc.contentType
			if contentType == "" {
				contentType = "application/json"
			}
			resp := f.send(t, tc.method, tc.path, contentType, saveBody(t, tc.body, tc.revision), f.cookie)
			if resp.StatusCode != tc.status {
				t.Fatalf("status %d, want %d: %s", resp.StatusCode, tc.status, resp.body)
			}
			var e ErrorJSON
			if err := json.Unmarshal(resp.body, &e); err != nil || e.Code != tc.code {
				t.Errorf("code %q (%v), want %q", e.Code, err, tc.code)
			}
			if after := f.files(t); len(after) != len(before) {
				t.Errorf("files went from %v to %v", before, after)
			}
			if got := f.applyAudit(t); len(got) != 0 {
				t.Errorf("a refused save reached policy: %+v", got)
			}
		})
	}
}

func TestAutomationRepairsItsOwnInvalidFile(t *testing.T) {
	f := newAutomationFixture(t, policy.Config{})
	broken := "id: hello\ntriggers: [{type: nope}]\n"
	f.write(t, "hello.yaml", broken)
	var list struct {
		Automations []AutomationJSON `json:"automations"`
	}
	if err := json.Unmarshal(f.do(t, http.MethodGet, "/api/v1/automations", "", f.cookie).body, &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Automations) != 1 || len(list.Automations[0].Problems) == 0 {
		t.Fatalf("list answered %+v", list)
	}
	body := saveBody(t, helloYAML, automation.Revision([]byte(broken)))
	if resp := f.do(t, http.MethodPut, "/api/v1/automations/hello", body, f.cookie); resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d: %s", resp.StatusCode, resp.body)
	}
}

// everyActionYAML has one action of each kind that reaches outside the hub.
func everyActionYAML(hookURL string) string {
	return `id: everything
triggers:
  - type: manual
actions:
  - id: run-it
    type: exec
    device: pi4
    command: [/usr/bin/touch, /tmp/pwned]
  - id: bounce
    type: restart
    device: pi4
    service: systemd:nginx.service
  - id: call
    type: webhook
    url: ` + hookURL + `
  - id: tell
    type: notify
    channel: phone
    message: hello
  - id: note
    type: log
    message: hello
`
}

func dryRun(t *testing.T, f *automationFixture, yaml string) AutomationDryRunJSON {
	t.Helper()
	resp := f.do(t, http.MethodPost, "/api/v1/automations/dry-run", saveBody(t, yaml, ""), f.cookie)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("dry run: status %d: %s", resp.StatusCode, resp.body)
	}
	var out AutomationDryRunJSON
	if err := json.Unmarshal(resp.body, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// TestAutomationDryRunExecutesNothing grants the automation everything, so
// that only the dry run itself can be what stops its actions.
func TestAutomationDryRunExecutesNothing(t *testing.T) {
	f := newAutomationFixture(t, policy.Config{DangerousAutomations: []string{"everything"}})
	out := dryRun(t, f, everyActionYAML(f.hookURL))
	if !out.Valid || out.Blocked != "" || out.Plan == "" {
		t.Fatalf("dry run answered %+v", out)
	}
	// The id is granted and the file has dangerous actions: a person decides.
	if out.Save == nil || out.Save.Decision != policy.Confirm || out.Save.Class != string(policy.Dangerous) {
		t.Errorf("save decision %+v", out.Save)
	}
	if len(out.Actions) != 5 {
		t.Fatalf("got %d decisions, want 5: %+v", len(out.Actions), out.Actions)
	}
	for _, d := range out.Actions {
		if d.Decision != policy.Allow {
			t.Errorf("step %s: decision %s (%s), want allow", d.Step, d.Decision, d.Reason)
		}
	}

	// Anything started by mistake gets time to arrive.
	time.Sleep(100 * time.Millisecond)
	if n := f.agents.execs.Load(); n != 0 {
		t.Errorf("%d commands reached a device", n)
	}
	if n := f.hooks.Load(); n != 0 {
		t.Errorf("%d webhooks were sent", n)
	}
	if n := f.notifier.sends.Load(); n != 0 {
		t.Errorf("%d notifications were sent", n)
	}
	if got := f.files(t); len(got) != 0 {
		t.Errorf("a dry run wrote %v", got)
	}
	runs, err := f.st.AutomationRuns().List(t.Context(), "", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 0 {
		t.Errorf("a dry run recorded runs: %+v", runs)
	}
	entries, err := f.st.Audit().List(t.Context(), 50)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 6 { // the save and five actions
		t.Errorf("got %d audit entries, want 6: %+v", len(entries), entries)
	}
	for _, e := range entries {
		if !strings.HasPrefix(e.Result, policy.DryRun) {
			t.Errorf("audit entry %s is not a dry run: result %q", e.Action, e.Result)
		}
	}
}

func TestAutomationDryRunReportsRealDecisions(t *testing.T) {
	t.Run("dangerous action not granted", func(t *testing.T) {
		f := newAutomationFixture(t, policy.Config{})
		out := dryRun(t, f, everyActionYAML(f.hookURL))
		if got := out.Actions[0]; got.Decision != policy.Deny || got.Class != string(policy.Dangerous) || got.Reason == "" {
			t.Errorf("exec: %+v, want a denial with its reason", got)
		}
		if got := out.Actions[4]; got.Decision != policy.Allow {
			t.Errorf("log: %+v, want allow", got)
		}
	})
	t.Run("held for approval", func(t *testing.T) {
		f := newAutomationFixture(t, policy.Config{Classes: map[policy.Class]policy.Mode{policy.Dangerous: policy.ModeConfirm}})
		out := dryRun(t, f, everyActionYAML(f.hookURL))
		if out.Save.Decision != policy.Confirm || out.Actions[0].Decision != policy.Confirm {
			t.Errorf("save %+v, exec %+v, want both held", out.Save, out.Actions[0])
		}
		if pending, err := f.st.Approvals().List(t.Context(), store.ApprovalPending, 10); err != nil || len(pending) != 0 {
			t.Errorf("a dry run held approvals: %+v, %v", pending, err)
		}
	})
	t.Run("beyond the device's ceiling", func(t *testing.T) {
		f := newAutomationFixture(t, policy.Config{DangerousAutomations: []string{"everything"}})
		f.agents.ceiling = policy.ErrBeyondCeiling
		out := dryRun(t, f, everyActionYAML(f.hookURL))
		if got := out.Actions[0]; got.Decision != policy.Deny || !strings.Contains(got.Reason, "ceiling") {
			t.Errorf("exec: %+v, want denied by the ceiling", got)
		}
	})
	t.Run("save denied", func(t *testing.T) {
		f := newAutomationFixture(t, policy.Config{
			Actors: map[string]map[policy.Class]policy.Mode{policy.ActorWeb: {policy.Dangerous: policy.ModeDeny}},
		})
		if out := dryRun(t, f, helloYAML); out.Save.Decision != policy.Deny || out.Save.Reason == "" {
			t.Errorf("save %+v, want a denial with its reason", out.Save)
		}
	})
	t.Run("invalid file", func(t *testing.T) {
		f := newAutomationFixture(t, policy.Config{})
		out := dryRun(t, f, "id: hello\ntriggers:\n  - type: nope\nactions:\n  - type: log\n    message: hi\n")
		if out.Valid || len(out.Problems) == 0 || out.Problems[0].Line != 3 {
			t.Errorf("dry run answered %+v, want a problem on line 3", out)
		}
		if got := f.applyAudit(t); len(got) != 0 {
			t.Errorf("an invalid file reached policy: %+v", got)
		}
	})
	t.Run("would be refused", func(t *testing.T) {
		f := newAutomationFixture(t, policy.Config{})
		f.write(t, "hello.yaml", helloYAML)
		if out := dryRun(t, f, helloYAML); out.Blocked == "" {
			t.Errorf("dry run of a new file over an existing id answered %+v", out)
		}
	})
}
