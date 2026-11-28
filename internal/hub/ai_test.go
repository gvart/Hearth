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

	"github.com/gvart/hearth/internal/ai"
	"github.com/gvart/hearth/internal/hubconfig"
	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

// sentinel is planted in the key, the question and the evidence: it must
// never reach the provider, the audit log or an answer of the API.
const sentinel = "SENTINEL7c1e"

// fakeModel is an OpenAI-compatible server that records what it is sent.
type fakeModel struct {
	mu     sync.Mutex
	calls  int
	bodies [][]byte
	auth   []string
	status int
}

func (m *fakeModel) start(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		m.mu.Lock()
		m.calls++
		m.bodies = append(m.bodies, b)
		m.auth = append(m.auth, r.Header.Get("Authorization"))
		status := m.status
		m.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if status != 0 {
			w.WriteHeader(status)
			_, _ = io.WriteString(w, `{"error":{"message":"invalid api key"}}`)
			return
		}
		_, _ = io.WriteString(w, `{"model":"llama3.2","choices":[{"message":{"content":"The disk is full [device]."},"finish_reason":"stop"}],"usage":{"prompt_tokens":100,"completion_tokens":7}}`)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func (m *fakeModel) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.calls
}

func aiBody(v map[string]any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// setAI writes ai.yaml through the API with a fresh session.
func setAI(t *testing.T, f *apiFixture, c *http.Cookie, v map[string]any) AIConfigJSON {
	t.Helper()
	cur := decode[AIConfigJSON](t, f.do(t, http.MethodGet, "/api/v1/ai", "", c))
	v["revision"] = cur.Revision
	resp := f.do(t, http.MethodPut, "/api/v1/ai/config", aiBody(v), c)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("save AI settings = %d %s", resp.StatusCode, resp.body)
	}
	return decode[AIConfigJSON](t, resp)
}

// auditText is every audit entry, as text.
func aiAuditText(t *testing.T, st *store.Store) string {
	t.Helper()
	entries, err := st.Audit().List(t.Context(), 500)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(entries)
	return string(b)
}

func TestAIConfigEditor(t *testing.T) {
	f := newConfigFixture(t, policy.Config{})
	c := sessionCookie(t, f.login(t, testPassword))

	got := decode[AIConfigJSON](t, f.do(t, http.MethodGet, "/api/v1/ai", "", c))
	if got.Enabled || got.APIKeySet {
		t.Fatalf("default = %+v, want off", got)
	}

	// Saving takes the password again.
	stale := staleSession(t, f)
	body := aiBody(map[string]any{"provider": "anthropic", "api_key": "sk-ant-" + sentinel, "revision": got.Revision})
	if resp := f.do(t, http.MethodPut, "/api/v1/ai/config", body, stale); errorCode(t, resp) != "reauth_required" {
		t.Fatalf("save without re-auth = %d %s", resp.StatusCode, resp.body)
	}

	got = setAI(t, f, c, map[string]any{"provider": "anthropic", "api_key": "sk-ant-" + sentinel})
	if !got.Enabled || !got.APIKeySet || got.Model != ai.DefaultAnthropicModel || got.BaseURL != ai.DefaultAnthropicURL {
		t.Fatalf("saved = %+v", got)
	}
	resp := f.do(t, http.MethodGet, "/api/v1/ai", "", c)
	if strings.Contains(string(resp.body), sentinel) {
		t.Fatal("the API served the key")
	}
	// Sealed in the store, and never audited.
	doc, err := f.st.ConfigDocs().Get(t.Context(), store.ConfigAI, hubconfig.AIFile)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(doc.Content), sentinel) {
		t.Fatal("ai.yaml stored in clear")
	}
	if strings.Contains(aiAuditText(t, f.st), sentinel) {
		t.Fatal("the key is in the audit log")
	}

	// A stale revision is refused.
	if resp := f.do(t, http.MethodPut, "/api/v1/ai/config", aiBody(map[string]any{"provider": "anthropic", "revision": "x"}), c); resp.StatusCode != http.StatusConflict {
		t.Fatalf("stale revision = %d", resp.StatusCode)
	}
	// An edit without a key keeps it for the same provider and address...
	if got = setAI(t, f, c, map[string]any{"provider": "anthropic", "model": "claude-sonnet-5-5"}); !got.APIKeySet || got.Model != "claude-sonnet-5-5" {
		t.Fatalf("kept key = %+v", got)
	}
	// ...but never carries it to another address.
	got = setAI(t, f, c, map[string]any{"provider": "openai", "base_url": "http://127.0.0.1:11434/v1", "model": "llama3.2"})
	if got.APIKeySet {
		t.Fatal("the key went along to another provider")
	}
	// Invalid settings are refused, with problems.
	if resp := f.do(t, http.MethodPut, "/api/v1/ai/config", aiBody(map[string]any{"provider": "openai", "revision": got.Revision}), c); resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("invalid = %d %s", resp.StatusCode, resp.body)
	}
	// An empty provider turns AI off.
	if got = setAI(t, f, c, map[string]any{"provider": ""}); got.Enabled {
		t.Fatalf("off = %+v", got)
	}
}

func TestExplainDevice(t *testing.T) {
	f := newConfigFixture(t, policy.Config{})
	c := sessionCookie(t, f.login(t, testPassword))
	enrollDevice(t, f.st, "pi")
	model := &fakeModel{}
	srv := model.start(t)

	// Off: refused, and nothing is sent.
	if resp := f.do(t, http.MethodPost, "/api/v1/devices/pi/explain", `{}`, c); errorCode(t, resp) != "ai_off" {
		t.Fatalf("explain while off = %d %s", resp.StatusCode, resp.body)
	}
	setAI(t, f, c, map[string]any{"provider": "openai", "base_url": srv.URL + "/v1", "model": "llama3.2", "api_key": "sk-" + sentinel + "0123456789abcdef"})

	// Evidence that carries a secret: an audit entry about the device.
	if _, err := f.st.Audit().Append(t.Context(), store.AuditEntry{
		TS: time.Now(), ActorKind: "automation", ActorID: "fix", Action: "automation.exec", Target: "pi",
		Decision: "allow", Result: "error: connect postgres://app:" + sentinel + "@db failed",
	}); err != nil {
		t.Fatal(err)
	}
	question := aiBody(map[string]any{"question": "why is it slow? DB_PASSWORD=" + sentinel})

	// A preview sends nothing.
	resp := f.do(t, http.MethodPost, "/api/v1/devices/pi/explain", aiBody(map[string]any{"question": "q", "preview": true}), c)
	if resp.StatusCode != http.StatusOK || model.count() != 0 {
		t.Fatalf("preview = %d %s, provider calls %d", resp.StatusCode, resp.body, model.count())
	}
	if p := decode[ExplainJSON](t, resp); !p.Preview || p.Answer != "" || p.SentBytes == 0 {
		t.Fatalf("preview = %+v", p)
	}

	resp = f.do(t, http.MethodPost, "/api/v1/devices/pi/explain", question, c)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("explain = %d %s", resp.StatusCode, resp.body)
	}
	got := decode[ExplainJSON](t, resp)
	if got.Answer != "The disk is full [device]." || got.Provider != "openai" || got.Model != "llama3.2" || got.Redactions < 2 {
		t.Fatalf("explain = %+v", got)
	}
	if model.count() != 1 {
		t.Fatalf("provider calls = %d", model.count())
	}
	if model.auth[0] != "Bearer sk-"+sentinel+"0123456789abcdef" {
		t.Errorf("the key was not sent: %q", model.auth[0])
	}
	// What the provider got is exactly what the answer says was sent.
	var sent struct {
		Messages []ai.Message `json:"messages"`
	}
	if err := json.Unmarshal(model.bodies[0], &sent); err != nil {
		t.Fatal(err)
	}
	want := append([]ai.Message{{Role: "system", Content: got.Sent.System}}, got.Sent.Messages...)
	if len(sent.Messages) != len(want) {
		t.Fatalf("sent %d messages, says %d", len(sent.Messages), len(want))
	}
	for i := range want {
		if sent.Messages[i] != want[i] {
			t.Errorf("message %d sent %q, says %q", i, sent.Messages[i].Content, want[i].Content)
		}
	}
	user := sent.Messages[1].Content
	for _, s := range []string{"device pi-name", "[device]", "[audit]", "automation.exec", "why is it slow?"} {
		if !strings.Contains(user, s) {
			t.Errorf("the evidence lacks %q", s)
		}
	}
	if strings.Contains(string(model.bodies[0]), sentinel) {
		t.Fatal("a secret reached the provider")
	}
	if strings.Contains(string(resp.body), sentinel) {
		t.Fatal("a secret is in the answer")
	}

	// Audited: who, the provider, the model and the sizes; never the text.
	entries, err := f.st.Audit().Query(t.Context(), store.AuditFilter{Actions: []string{string(policy.AIExplain)}}, 10)
	if err != nil {
		t.Fatal(err)
	}
	var outcome map[string]any
	for _, e := range entries {
		var d map[string]any
		_ = json.Unmarshal(e.Detail, &d)
		if d["preview"] == false && e.Result == "ok" {
			outcome = d
		}
		if e.Target != "pi" || e.ActorKind != policy.ActorWeb {
			t.Errorf("entry = %+v", e)
		}
	}
	if outcome == nil {
		t.Fatalf("no outcome entry: %+v", entries)
	}
	if outcome["provider"] != "openai" || outcome["model"] != "llama3.2" || outcome["sent_bytes"] == nil || outcome["answer_bytes"] != float64(len(got.Answer)) {
		t.Errorf("detail = %v", outcome)
	}
	text := aiAuditText(t, f.st)
	if strings.Contains(text, "why is it slow") || strings.Contains(text, "The disk is full") {
		t.Error("the question or the answer is in the audit log")
	}
	if strings.Count(text, sentinel) != 1 { // only the planted automation entry
		t.Errorf("the secret is in the audit log %d times", strings.Count(text, sentinel))
	}

	// A log asked for while the agent is away is left out, with a note.
	resp = f.do(t, http.MethodPost, "/api/v1/devices/pi/explain", aiBody(map[string]any{"logs": []string{"systemd:nginx.service"}}), c)
	if g := decode[ExplainJSON](t, resp); resp.StatusCode != http.StatusOK || len(g.Notes) == 0 || !strings.Contains(strings.Join(g.Notes, " "), "systemd:nginx.service") {
		t.Fatalf("explain with a log = %d %s", resp.StatusCode, resp.body)
	}
	if resp := f.do(t, http.MethodPost, "/api/v1/devices/pi/explain", aiBody(map[string]any{"logs": []string{"nginx"}}), c); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad log source = %d", resp.StatusCode)
	}
	// The CLI names a device as the user knows it: by its name too.
	if resp := f.do(t, http.MethodPost, "/api/v1/devices/pi-name/explain", aiBody(map[string]any{"preview": true}), c); resp.StatusCode != http.StatusOK {
		t.Fatalf("by name = %d %s", resp.StatusCode, resp.body)
	}
	if resp := f.do(t, http.MethodPost, "/api/v1/devices/nope/explain", `{}`, c); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown device = %d", resp.StatusCode)
	}
}

// A provider's refusal is a 502 naming what failed, never the key.
func TestExplainProviderError(t *testing.T) {
	f := newConfigFixture(t, policy.Config{})
	c := sessionCookie(t, f.login(t, testPassword))
	enrollDevice(t, f.st, "pi")
	model := &fakeModel{status: http.StatusUnauthorized}
	srv := model.start(t)
	setAI(t, f, c, map[string]any{"provider": "openai", "base_url": srv.URL + "/v1", "model": "m", "api_key": sentinel})
	resp := f.do(t, http.MethodPost, "/api/v1/devices/pi/explain", `{}`, c)
	if resp.StatusCode != http.StatusBadGateway || errorCode(t, resp) != "ai_auth" {
		t.Fatalf("explain = %d %s", resp.StatusCode, resp.body)
	}
	if strings.Contains(string(resp.body), sentinel) || strings.Contains(aiAuditText(t, f.st), sentinel) {
		t.Fatal("the key leaked into an error")
	}
}

// Denied by policy: refused, audited, and nothing is gathered or sent.
func TestExplainDenied(t *testing.T) {
	f := newConfigFixture(t, policy.Config{Actors: map[string]map[policy.Class]policy.Mode{
		policy.ActorWeb: {policy.Read: policy.ModeDeny},
	}})
	model := &fakeModel{}
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
	enrollDevice(t, f.st, "pi")
	resp := f.do(t, http.MethodPost, "/api/v1/devices/pi/explain", `{"question":"why"}`, c)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("explain = %d %s, want 403", resp.StatusCode, resp.body)
	}
	if model.count() != 0 {
		t.Fatal("a denied explanation reached the provider")
	}
	entries, err := f.st.Audit().Query(t.Context(), store.AuditFilter{Actions: []string{string(policy.AIExplain)}}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Decision != policy.Deny {
		t.Fatalf("audit = %+v", entries)
	}
}
