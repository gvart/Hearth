// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/hubconfig"
	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

// scriptedModel is an OpenAI-compatible server that answers each call with
// the next of its answers, and records what it is sent.
type scriptedModel struct {
	mu      sync.Mutex
	answers []string
	bodies  []string
}

func (m *scriptedModel) start(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		m.mu.Lock()
		answer := ""
		if n := len(m.bodies); n < len(m.answers) {
			answer = m.answers[n]
		}
		m.bodies = append(m.bodies, string(b))
		m.mu.Unlock()
		resp, _ := json.Marshal(map[string]any{
			"model":   "llama3.2",
			"choices": []map[string]any{{"message": map[string]string{"content": answer}, "finish_reason": "stop"}},
			"usage":   map[string]int{"prompt_tokens": 100, "completion_tokens": 20},
		})
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(resp)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func (m *scriptedModel) sent() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.bodies...)
}

const validDraft = `id: dns-watch
description: Tell the hub log when DNS fails. ` + sentinel + `
triggers:
  - id: dns-down
    type: dns
    name: example.com
    server: 192.168.1.2
    every: 10s
    for: 20s
actions:
  - id: say
    type: log
    message: "DNS failed: {{ .Trigger.Error }}"
`

// draftFixture is a hub with AI set up against model, and a device.
func draftFixture(t *testing.T, model *scriptedModel) (*apiFixture, *http.Cookie) {
	t.Helper()
	f := newConfigFixture(t, policy.Config{})
	c := sessionCookie(t, f.login(t, testPassword))
	enrollDevice(t, f.st, "pi4")
	srv := model.start(t)
	setAI(t, f, c, map[string]any{"provider": "openai", "base_url": srv.URL + "/v1", "model": "llama3.2"})
	return f, c
}

func draftBody(text string) string {
	b, _ := json.Marshal(AutomationDraftRequestJSON{Text: text})
	return string(b)
}

// assertNothingSaved checks a draft left the automations alone.
func assertNothingSaved(t *testing.T, f *apiFixture, c *http.Cookie) {
	t.Helper()
	list := f.do(t, http.MethodGet, "/api/v1/automations", "", c)
	if list.StatusCode != http.StatusOK || strings.Contains(string(list.body), "dns-watch") {
		t.Fatalf("automations = %d %s", list.StatusCode, list.body)
	}
	saves, err := f.st.Audit().Query(t.Context(), store.AuditFilter{Actions: []string{string(policy.AutomationApply)}}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(saves) != 0 {
		t.Fatalf("a draft asked to save: %+v", saves)
	}
}

func draftAudit(t *testing.T, f *apiFixture) []store.AuditEntry {
	t.Helper()
	entries, err := f.st.Audit().Query(t.Context(), store.AuditFilter{Actions: []string{string(policy.AIAutomationDraft)}}, 10)
	if err != nil {
		t.Fatal(err)
	}
	return entries
}

func TestDraftAutomation(t *testing.T) {
	for _, tc := range []struct {
		name      string
		answers   []string
		calls     int
		valid     bool
		fedBack   string
		wantError string
	}{
		{name: "valid", answers: []string{"```yaml\n" + validDraft + "```"}, calls: 1, valid: true},
		{
			name:    "invalid then valid",
			answers: []string{strings.Replace(validDraft, "    message:", "    mesage:", 1), validDraft},
			calls:   2, valid: true, fedBack: `unknown field "mesage"`,
		},
		{name: "garbage twice", answers: []string{"I cannot do that: {[", "still: not yaml ["}, calls: 2, valid: false, fedBack: `- yaml: line 1: did not find expected node content`},
		{name: "no answer", answers: []string{"   "}, calls: 1, wantError: "ai_error"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			model := &scriptedModel{answers: tc.answers}
			f, c := draftFixture(t, model)
			text := "tell me in the log when DNS fails 3 times " + sentinel
			resp := f.do(t, http.MethodPost, "/api/v1/automations/draft", draftBody(text), c)
			sent := model.sent()
			if len(sent) != tc.calls {
				t.Fatalf("calls = %d, want %d", len(sent), tc.calls)
			}
			// Grounded in the schema, the request and the hub's names.
			for _, want := range []string{"kube_drain", "(N-1) x E", sentinel, "pi4"} {
				if !strings.Contains(sent[0], want) {
					t.Errorf("the request lacks %q", want)
				}
			}
			if tc.wantError != "" {
				if resp.StatusCode != http.StatusBadGateway || errorCode(t, resp) != tc.wantError {
					t.Fatalf("draft = %d %s", resp.StatusCode, resp.body)
				}
				assertNothingSaved(t, f, c)
				return
			}
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("draft = %d %s", resp.StatusCode, resp.body)
			}
			got := decode[AutomationDraftJSON](t, resp)
			if got.Valid != tc.valid || got.Attempts != tc.calls {
				t.Fatalf("draft = %+v", got)
			}
			if tc.valid {
				if got.YAML != validDraft || len(got.Problems) != 0 || !strings.Contains(got.Plan, "dns-watch") {
					t.Fatalf("draft = %+v", got)
				}
			} else if len(got.Problems) == 0 || got.YAML == "" {
				t.Fatalf("an invalid draft lacks its problems: %+v", got)
			}
			if tc.fedBack != "" {
				var second struct {
					Messages []struct{ Role, Content string }
				}
				if err := json.Unmarshal([]byte(sent[1]), &second); err != nil {
					t.Fatal(err)
				}
				// system, the request, the first answer, its problems.
				if n := len(second.Messages); n != 4 || second.Messages[2].Role != "assistant" ||
					second.Messages[2].Content != strings.TrimSpace(tc.answers[0])+"\n" || !strings.Contains(second.Messages[3].Content, tc.fedBack) {
					t.Fatalf("the second request lacks the problems: %+v", second.Messages)
				}
				if len(got.Sent.Messages) != 3 {
					t.Fatalf("sent = %+v", got.Sent.Messages)
				}
			}
			assertNothingSaved(t, f, c)

			entries := draftAudit(t, f)
			if len(entries) == 0 || entries[0].Decision != policy.Allow {
				t.Fatalf("audit = %+v", entries)
			}
			if strings.Contains(aiAuditText(t, f.st), sentinel) {
				t.Fatal("the request or the draft is in the audit log")
			}
		})
	}
}

// A preview gathers and redacts, and sends nothing.
func TestDraftAutomationPreview(t *testing.T) {
	model := &scriptedModel{}
	f, c := draftFixture(t, model)
	resp := f.do(t, http.MethodPost, "/api/v1/automations/draft", `{"text":"notify me when pi4 goes offline, token=ghp_0123456789abcdefghijABCDEFGHIJ012345","preview":true}`, c)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("preview = %d %s", resp.StatusCode, resp.body)
	}
	got := decode[AutomationDraftJSON](t, resp)
	if !got.Preview || got.YAML != "" || got.Attempts != 0 || got.Redactions == 0 || len(got.Sent.Messages) != 1 {
		t.Fatalf("preview = %+v", got)
	}
	if strings.Contains(got.Sent.Messages[0].Content, "ghp_") {
		t.Fatal("not redacted")
	}
	if len(model.sent()) != 0 {
		t.Fatal("a preview reached the provider")
	}
}

func TestDraftAutomationRefused(t *testing.T) {
	// Off: refused before anything is gathered.
	f := newConfigFixture(t, policy.Config{})
	c := sessionCookie(t, f.login(t, testPassword))
	if resp := f.do(t, http.MethodPost, "/api/v1/automations/draft", draftBody("x"), c); resp.StatusCode != http.StatusConflict || errorCode(t, resp) != "ai_off" {
		t.Fatalf("draft with AI off = %d %s", resp.StatusCode, resp.body)
	}
	if resp := f.do(t, http.MethodPost, "/api/v1/automations/draft", draftBody(""), c); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("empty draft = %d %s", resp.StatusCode, resp.body)
	}
	if resp := f.do(t, http.MethodPost, "/api/v1/automations/draft", draftBody("x"), nil); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("draft without a session = %d", resp.StatusCode)
	}
}

// Denied by policy: refused, audited, and nothing is sent.
func TestDraftAutomationDenied(t *testing.T) {
	f := newConfigFixture(t, policy.Config{Actors: map[string]map[policy.Class]policy.Mode{
		policy.ActorWeb: {policy.Read: policy.ModeDeny},
	}})
	model := &scriptedModel{answers: []string{validDraft}}
	srv := model.start(t)
	cfg := []byte("provider: openai\nbase_url: " + srv.URL + "/v1\nmodel: m\n")
	sealed, err := hubconfig.Seal([]hubconfig.Doc{{Kind: store.ConfigAI, Name: hubconfig.AIFile, Content: cfg}}, testSealer{})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.st.ConfigDocs().Put(t.Context(), "test", sealed, time.Now()); err != nil {
		t.Fatal(err)
	}
	c := sessionCookie(t, f.login(t, testPassword))
	resp := f.do(t, http.MethodPost, "/api/v1/automations/draft", draftBody("log when DNS fails"), c)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("draft = %d %s, want 403", resp.StatusCode, resp.body)
	}
	if len(model.sent()) != 0 {
		t.Fatal("a denied draft reached the provider")
	}
	if entries := draftAudit(t, f); len(entries) != 1 || entries[0].Decision != policy.Deny {
		t.Fatalf("audit = %+v", entries)
	}
}
