// SPDX-License-Identifier: AGPL-3.0-only

package automation

import (
	"context"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/policy"
	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
)

// fakeAgents answers every request with result, and records the requests.
type fakeAgents struct {
	result *agentv1.ExecResult

	mu   sync.Mutex
	reqs []*agentv1.ExecRequest
	devs []string
}

func (f *fakeAgents) Exec(_ context.Context, device string, req *agentv1.ExecRequest) (*agentv1.ExecResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reqs = append(f.reqs, req)
	f.devs = append(f.devs, device)
	return f.result, nil
}

func (f *fakeAgents) requests() []*agentv1.ExecRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.reqs)
}

func actionKinds(deps ActionDeps) Kinds {
	k := Builtin(slog.New(slog.DiscardHandler))
	maps.Copy(k.Actions, Actions(deps))
	return k
}

// runOnce loads yaml, fires its manual trigger "go" under a policy granting
// dangerous actions to the automations in granted, and returns the
// recorded run and audit log.
func runOnce(t *testing.T, yaml string, deps ActionDeps, granted ...string) (*recorder, *auditLog) {
	t.Helper()
	kinds := actionKinds(deps)
	a, err := Parse("test.yaml", []byte(yaml), kinds)
	if err != nil {
		t.Fatal(err)
	}
	rec, audit := &recorder{}, &auditLog{}
	rt := New(Config{Kinds: kinds, Policy: policy.NewWithConfig(audit, policy.Config{DangerousAutomations: granted}), Runs: rec})
	ctx, cancel := context.WithCancel(context.Background())
	rt.reconcile(ctx, []*Automation{a})
	t.Cleanup(func() {
		cancel()
		rt.reconcile(ctx, nil)
	})
	if err := rt.Fire(a.ID, "go"); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the run recorded", func() bool { return len(rec.all()) == 1 })
	return rec, audit
}

const deviceYAML = `id: fix-pi
triggers:
  - id: go
    type: manual
actions:
  - id: first
    type: %TYPE%
    device: pi
%FIELDS%
  - id: after
    type: log
    message: done
`

func deviceAutomation(typ, fields string) string {
	return strings.NewReplacer("%TYPE%", typ, "%FIELDS%", fields).Replace(deviceYAML)
}

func TestDeviceActions(t *testing.T) {
	ok := &agentv1.ExecResult{ExitCode: 0}
	tests := []struct {
		name    string
		yaml    string
		result  *agentv1.ExecResult
		granted []string
		// want is the run status; wantSent whether the agent got a request.
		want       string
		wantSent   bool
		wantErr    string
		wantAction policy.Action
		wantResult string // the audit entry's result
	}{
		{
			name: "restart runs", yaml: deviceAutomation("restart", "    service: systemd:pihole-FTL.service"),
			result: ok, want: StatusSucceeded, wantSent: true, wantAction: policy.AutomationRestart, wantResult: "ok",
		},
		{
			name: "restart beyond the ceiling is denied", yaml: deviceAutomation("restart", "    service: docker:jellyfin"),
			result: &agentv1.ExecResult{Denied: true, ExitCode: -1, Error: "not allowed"}, want: StatusDenied, wantSent: true,
			wantErr: "beyond the device's capability ceiling", wantAction: policy.AutomationRestart,
			wantResult: "error: restart docker:jellyfin on device pi: beyond the device's capability ceiling: denied by policy",
		},
		{
			name: "failed restart fails the run", yaml: deviceAutomation("restart", "    service: systemd-user:x.service"),
			result: &agentv1.ExecResult{ExitCode: 5, Error: "exit status 5"}, want: StatusFailed, wantSent: true,
			wantErr: "exit status 5", wantAction: policy.AutomationRestart,
			wantResult: "error: restart systemd-user:x.service on device pi: exit status 5",
		},
		{
			name: "exec without a grant is denied before reaching the device", yaml: deviceAutomation("exec", "    command: [/usr/bin/df, -h]"),
			result: ok, want: StatusDenied, wantErr: "dangerous action not granted", wantAction: policy.AutomationExec,
			wantResult: "dangerous action not granted to this automation",
		},
		{
			name: "a grant for another automation does not count", yaml: deviceAutomation("exec", "    command: [/usr/bin/df]"),
			result: ok, granted: []string{"other"}, want: StatusDenied, wantErr: "dangerous action not granted",
			wantAction: policy.AutomationExec, wantResult: "dangerous action not granted to this automation",
		},
		{
			name: "granted exec runs", yaml: deviceAutomation("exec", "    command: [/usr/bin/df, -h]"),
			result: ok, granted: []string{"fix-pi"}, want: StatusSucceeded, wantSent: true,
			wantAction: policy.AutomationExec, wantResult: "ok",
		},
		{
			name: "granted exec beyond the ceiling is denied", yaml: deviceAutomation("exec", "    command: [/usr/bin/df]"),
			result: &agentv1.ExecResult{Denied: true, ExitCode: -1}, granted: []string{"fix-pi"}, want: StatusDenied, wantSent: true,
			wantErr: "capability ceiling", wantAction: policy.AutomationExec,
			wantResult: "error: exec /usr/bin/df on device pi: beyond the device's capability ceiling: denied by policy",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			agents := &fakeAgents{result: tt.result}
			rec, audit := runOnce(t, tt.yaml, ActionDeps{Agents: agents}, tt.granted...)
			run := rec.all()[0]
			if run.Status != tt.want || !strings.Contains(run.Error, tt.wantErr) {
				t.Errorf("run = %s %q, want %s %q", run.Status, run.Error, tt.want, tt.wantErr)
			}
			if sent := len(agents.requests()) == 1; sent != tt.wantSent {
				t.Errorf("request sent = %v, want %v", sent, tt.wantSent)
			}
			// One audit entry per action taken, the automation the actor.
			entries := audit.all()
			wantEntries := 1
			if tt.want == StatusSucceeded {
				wantEntries = 2 // and the log action after it
			}
			if len(entries) != wantEntries {
				t.Fatalf("audit = %+v, want %d entries", entries, wantEntries)
			}
			e := entries[0]
			if e.ActorKind != policy.ActorAutomation || e.ActorID != "fix-pi" || e.Action != string(tt.wantAction) ||
				e.Target != "pi" || e.Result != tt.wantResult {
				t.Errorf("audit entry = %+v", e)
			}
			if tt.wantSent {
				req := agents.requests()[0]
				if req.GetTimeout().AsDuration() != defaultAgentTimeout {
					t.Errorf("timeout = %v, want the default", req.GetTimeout().AsDuration())
				}
			}
		})
	}
}

func TestDeviceActionRequests(t *testing.T) {
	agents := &fakeAgents{result: &agentv1.ExecResult{}}
	runOnce(t, deviceAutomation("restart", "    service: docker:jellyfin\n    timeout: 30s"), ActionDeps{Agents: agents})
	runOnce(t, deviceAutomation("exec", "    command: [/usr/bin/df, -h, /]"), ActionDeps{Agents: agents}, "fix-pi")
	reqs := agents.requests()
	if len(reqs) != 2 {
		t.Fatalf("requests = %v", reqs)
	}
	if r := reqs[0].GetRestart(); r.GetManager() != "docker" || r.GetName() != "jellyfin" ||
		reqs[0].GetTimeout().AsDuration() != 30*time.Second {
		t.Errorf("restart request = %v", reqs[0])
	}
	if argv := reqs[1].GetCommand().GetArgv(); !slices.Equal(argv, []string{"/usr/bin/df", "-h", "/"}) {
		t.Errorf("argv = %q", argv)
	}
}

func TestActionsRejectBadFields(t *testing.T) {
	tests := map[string]string{
		"exec without device":       "  - id: a\n    type: exec\n    command: [ls]\n",
		"exec without command":      "  - id: a\n    type: exec\n    device: pi\n",
		"exec with a shell string":  "  - id: a\n    type: exec\n    device: pi\n    command: ls -l\n",
		"exec timeout too long":     "  - id: a\n    type: exec\n    device: pi\n    command: [ls]\n    timeout: 1h\n",
		"restart unknown manager":   "  - id: a\n    type: restart\n    device: pi\n    service: podman:x\n",
		"restart without name":      "  - id: a\n    type: restart\n    device: pi\n    service: 'systemd:'\n",
		"webhook without url":       "  - id: a\n    type: webhook\n",
		"webhook bad scheme":        "  - id: a\n    type: webhook\n    url: file:///etc/passwd\n",
		"webhook bad method":        "  - id: a\n    type: webhook\n    url: https://x.test\n    method: 'GET /'\n",
		"webhook unknown field":     "  - id: a\n    type: webhook\n    url: https://x.test\n    secret: x\n",
		"webhook timeout too long":  "  - id: a\n    type: webhook\n    url: https://x.test\n    timeout: 2m\n",
		"restart with extra fields": "  - id: a\n    type: restart\n    device: pi\n    service: docker:x\n    command: [ls]\n",
	}
	for name, actions := range tests {
		t.Run(name, func(t *testing.T) {
			y := "id: x\ntriggers:\n  - type: manual\nactions:\n" + actions
			if _, err := Parse("x.yaml", []byte(y), actionKinds(ActionDeps{})); err == nil {
				t.Error("Parse accepted it")
			}
		})
	}
}

const webhookYAML = `id: notify
triggers:
  - id: go
    type: manual
actions:
  - id: hook
    type: webhook
    url: %URL%/hooks/s3cr3t-token?key=hunter2
    headers:
      Authorization: Bearer hunter2
      Content-Type: text/plain
    body: pi is down
`

func TestWebhook(t *testing.T) {
	type got struct {
		method, path, auth, body string
	}
	tests := []struct {
		name    string
		status  int
		want    string
		wantErr string
	}{
		{name: "2xx succeeds", status: http.StatusNoContent, want: StatusSucceeded},
		{name: "5xx fails", status: http.StatusBadGateway, want: StatusFailed, wantErr: "answered 502 Bad Gateway"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reqs := make(chan got, 1)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				b, _ := io.ReadAll(r.Body)
				reqs <- got{r.Method, r.URL.RequestURI(), r.Header.Get("Authorization"), string(b)}
				w.WriteHeader(tt.status)
			}))
			defer srv.Close()
			rec, audit := runOnce(t, strings.ReplaceAll(webhookYAML, "%URL%", srv.URL), ActionDeps{HTTP: srv.Client()})
			run := rec.all()[0]
			if run.Status != tt.want || !strings.Contains(run.Error, tt.wantErr) {
				t.Errorf("run = %s %q, want %s %q", run.Status, run.Error, tt.want, tt.wantErr)
			}
			g := <-reqs
			if g != (got{"POST", "/hooks/s3cr3t-token?key=hunter2", "Bearer hunter2", "pi is down"}) {
				t.Errorf("request = %+v", g)
			}
			e := audit.all()[0]
			if e.ActorID != "notify" || e.Action != string(policy.AutomationWebhook) || e.Target != srv.URL {
				t.Errorf("audit entry = %+v", e)
			}
			assertNoSecret(t, run.Error, e.Result, string(e.Detail), e.Target)
		})
	}
}

// TestWebhookErrorHidesURL checks a failed request reports the site, never
// the secret parts of the URL.
func TestWebhookErrorHidesURL(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close() // connection refused
	rec, audit := runOnce(t, strings.ReplaceAll(webhookYAML, "%URL%", url), ActionDeps{})
	run := rec.all()[0]
	if run.Status != StatusFailed || !strings.Contains(run.Error, url) {
		t.Errorf("run = %s %q, want a failure naming %s", run.Status, run.Error, url)
	}
	assertNoSecret(t, run.Error, audit.all()[0].Result)
}

func assertNoSecret(t *testing.T, texts ...string) {
	t.Helper()
	for _, s := range texts {
		if strings.Contains(s, "s3cr3t") || strings.Contains(s, "hunter2") {
			t.Errorf("secret leaked: %q", s)
		}
	}
}

func TestPlanShowsActionClasses(t *testing.T) {
	y := `id: fix
triggers:
  - type: manual
actions:
  - type: restart
    device: pi
    service: systemd:pihole-FTL.service
  - type: exec
    device: pi
    command: [/usr/bin/df, -h]
  - type: webhook
    url: https://ntfy.example/s3cr3t
`
	a, err := Parse("fix.yaml", []byte(y), actionKinds(ActionDeps{}))
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	if err := Plan(&b, a); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"restart systemd:pihole-FTL.service on pi", "automation.restart (safe)",
		`run ["/usr/bin/df" "-h"] on pi`, "automation.exec (dangerous)",
		"send POST https://ntfy.example/… on https://ntfy.example", "automation.webhook (safe)",
	} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("plan lacks %q:\n%s", want, b.String())
		}
	}
	assertNoSecret(t, b.String())
}
