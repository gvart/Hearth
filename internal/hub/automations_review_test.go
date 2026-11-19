// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/automation"
	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

// TestSaveIsHeldWhenPolicyWouldRunItsDangerousAction: whatever lets the
// automation act without a person, a grant or a mode, saving the file is the
// moment a person has to see what it does.
func TestSaveIsHeldWhenPolicyWouldRunItsDangerousAction(t *testing.T) {
	revision := automation.Revision([]byte(nightlyLogYAML))
	allow := map[policy.Class]policy.Mode{policy.Dangerous: policy.ModeAllow}
	for name, cfg := range map[string]policy.Config{
		"a grant":                   grantNightly,
		"the automation actor":      {Actors: map[string]map[policy.Class]policy.Mode{policy.ActorAutomation: allow}},
		"the class for every actor": {Classes: allow},
	} {
		t.Run(name, func(t *testing.T) {
			f := newAutomationFixture(t, cfg)
			f.write(t, "nightly.yaml", nightlyLogYAML)
			id, done := heldSave(t, f, http.MethodPut, "/api/v1/automations/nightly", saveBody(t, nightlyExecYAML, revision))
			if got := f.read(t, "nightly.yaml"); got != nightlyLogYAML {
				t.Fatalf("written before approval:\n%s", got)
			}
			if err := f.api.policy.Decide(t.Context(), policy.ActorAdmin, "op", id, false, nil); err != nil {
				t.Fatal(err)
			}
			if resp := <-done; resp.StatusCode != http.StatusForbidden {
				t.Fatalf("status %d, want 403: %s", resp.StatusCode, resp.body)
			}
			if got := f.read(t, "nightly.yaml"); got != nightlyLogYAML {
				t.Errorf("written after a denial:\n%s", got)
			}
			if out := dryRun(t, f, nightlyExecYAML); out.Save == nil || out.Save.Decision != policy.Confirm {
				t.Errorf("dry run save decision %+v, want confirm", out.Save)
			}
		})
	}

	t.Run("not when each run waits for approval anyway", func(t *testing.T) {
		confirm := map[policy.Class]policy.Mode{policy.Dangerous: policy.ModeConfirm}
		f := newAutomationFixture(t, policy.Config{Actors: map[string]map[policy.Class]policy.Mode{policy.ActorAutomation: confirm}})
		f.write(t, "nightly.yaml", nightlyLogYAML)
		resp := f.do(t, http.MethodPut, "/api/v1/automations/nightly", saveBody(t, nightlyExecYAML, revision), f.cookie)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status %d: %s", resp.StatusCode, resp.body)
		}
	})
}

//nolint:gosec // G101: made-up secrets, which the test looks for.
const secretsYAML = `id: leaky
description: automation-description-s3cret
triggers:
  - id: query
    type: metric
    query: up{token="promql-s3cret"}
    above: 1
actions:
  - id: run-it
    type: exec
    device: pi4
    description: step-description-s3cret
    command: [/usr/bin/curl, argv-s3cret]
  - id: say
    type: log
    message: log-message-s3cret
  - id: tell
    type: notify
    channel: phone
    title: notify-title-s3cret
    message: notify-body-s3cret
`

// TestPlanSecretsStayWithTheApprover: a file's commands and messages may hold
// secrets. The audit log and a notification channel outlive the decision and
// reach further than the person making it.
func TestPlanSecretsStayWithTheApprover(t *testing.T) {
	cfg := policy.Config{Actors: map[string]map[policy.Class]policy.Mode{policy.ActorWeb: {policy.Dangerous: policy.ModeConfirm}}}
	f := newAutomationFixture(t, cfg)

	out := dryRun(t, f, secretsYAML)
	if !out.Valid {
		t.Fatalf("dry run: %+v", out)
	}
	id, done := heldSave(t, f, http.MethodPost, "/api/v1/automations", saveBody(t, secretsYAML, ""))
	held, err := f.st.Approvals().Get(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}

	secret := "link-secret-for-the-test"
	if err := f.st.ApprovalLinks().Create(t.Context(), secret, id, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	link := f.do(t, http.MethodPost, "/api/v1/approval-link", tokenBody(secret), nil)
	if link.StatusCode != http.StatusOK {
		t.Fatalf("approval link: status %d: %s", link.StatusCode, link.body)
	}
	listed := f.do(t, http.MethodGet, "/api/v1/approvals?status=pending", "", f.cookie)
	for _, want := range []string{"argv-s3cret", "log-message-s3cret", "notify-body-s3cret"} {
		if !strings.Contains(string(listed.body), want) {
			t.Errorf("the signed-in approver cannot read %q: %s", want, listed.body)
		}
	}

	if err := f.api.policy.Decide(t.Context(), policy.ActorAdmin, "op", id, true, reauthed); err != nil {
		t.Fatal(err)
	}
	if resp := <-done; resp.StatusCode != http.StatusCreated {
		t.Fatalf("status %d: %s", resp.StatusCode, resp.body)
	}

	entries, err := f.st.Audit().Query(t.Context(), store.AuditFilter{}, 200)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Fatal("no audit entries")
	}
	var audit strings.Builder
	for _, e := range entries {
		audit.WriteString(e.Target + " " + e.Result + " ")
		audit.Write(e.Detail)
		audit.WriteString("\n")
	}
	msg := approvalMessage(held)
	for name, text := range map[string]string{
		"audit log":     audit.String(),
		"notification":  msg.Title + "\n" + msg.Body,
		"approval link": string(link.body),
	} {
		if strings.Contains(text, "s3cret") {
			t.Errorf("the %s holds a secret:\n%s", name, text)
		}
	}
	var page ApprovalJSON
	if err := json.Unmarshal(link.body, &page); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(page.Detail), "plan_withheld") {
		t.Errorf("the link page does not say the plan is withheld: %s", page.Detail)
	}
}

// outcomeAudit fails to record how a save ended, after recording its start.
type outcomeAudit struct{ policy.Auditor }

func (a outcomeAudit) Append(ctx context.Context, e store.AuditEntry) (int64, error) {
	if e.Result == "ok" {
		return 0, errors.New("audit log unavailable")
	}
	return a.Auditor.Append(ctx, e)
}

// TestSaveWhoseOutcomeWasNotRecordedIsSaved: the file is on disk, so saying
// "not saved" would be false and a retry would be told the file changed.
func TestSaveWhoseOutcomeWasNotRecordedIsSaved(t *testing.T) {
	f := newAutomationFixtureWith(t, func(st *store.Store) *policy.Engine {
		return policy.NewWithConfig(outcomeAudit{st.Audit()}, st.Approvals(), policy.Config{})
	})
	resp := f.do(t, http.MethodPost, "/api/v1/automations", saveBody(t, helloYAML, ""), f.cookie)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status %d, want 201: %s", resp.StatusCode, resp.body)
	}
	if got := f.read(t, "hello.yaml"); got != helloYAML {
		t.Errorf("file = %q", got)
	}
	var saved AutomationSavedJSON
	if err := json.Unmarshal(resp.body, &saved); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(saved.Warning, "audit") {
		t.Errorf("warning = %q, want one about the audit log", saved.Warning)
	}
}
