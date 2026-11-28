// SPDX-License-Identifier: AGPL-3.0-only

package ai

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const testKey = "sk-test-SENTINEL-key-0123456789"

// recorder is a fake provider: it answers status with body and keeps the
// last request.
type recorder struct {
	status int
	body   string
	path   string
	header http.Header
	got    map[string]any
	calls  int
}

func (rec *recorder) server(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.calls++
		rec.path, rec.header = r.URL.Path, r.Header.Clone()
		b, _ := io.ReadAll(r.Body)
		rec.got = map[string]any{}
		_ = json.Unmarshal(b, &rec.got)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(rec.status)
		_, _ = io.WriteString(w, rec.body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

var testReq = Request{System: "be brief", Messages: []Message{{Role: RoleUser, Content: "why?"}}, MaxTokens: 100}

func TestOpenAIRequestShape(t *testing.T) {
	rec := &recorder{status: 200, body: `{"model":"llama3.2","choices":[{"message":{"role":"assistant","content":"disk full"},"finish_reason":"stop"}],"usage":{"prompt_tokens":12,"completion_tokens":3}}`}
	srv := rec.server(t)
	p := &OpenAI{BaseURL: srv.URL + "/v1/", ModelID: "llama3.2", APIKey: testKey}
	resp, err := p.Complete(context.Background(), testReq)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Text != "disk full" || resp.InputTokens != 12 || resp.OutputTokens != 3 || resp.Model != "llama3.2" {
		t.Fatalf("response = %+v", resp)
	}
	if rec.path != "/v1/chat/completions" {
		t.Errorf("path = %q", rec.path)
	}
	if got := rec.header.Get("Authorization"); got != "Bearer "+testKey {
		t.Errorf("Authorization = %q", got)
	}
	if rec.got["model"] != "llama3.2" || rec.got["stream"] != false || rec.got["max_tokens"] != float64(100) {
		t.Errorf("body = %v", rec.got)
	}
	msgs, _ := rec.got["messages"].([]any)
	if len(msgs) != 2 {
		t.Fatalf("messages = %v", msgs)
	}
	if m := msgs[0].(map[string]any); m["role"] != "system" || m["content"] != "be brief" {
		t.Errorf("system message = %v", m)
	}
	if m := msgs[1].(map[string]any); m["role"] != "user" || m["content"] != "why?" {
		t.Errorf("user message = %v", m)
	}
}

func TestOpenAINoKeyNoHeader(t *testing.T) {
	rec := &recorder{status: 200, body: `{"choices":[{"message":{"content":"ok"}}]}`}
	srv := rec.server(t)
	p := &OpenAI{BaseURL: srv.URL + "/v1", ModelID: "m"}
	if _, err := p.Complete(context.Background(), Request{Messages: []Message{{Role: RoleUser, Content: "x"}}}); err != nil {
		t.Fatal(err)
	}
	if _, ok := rec.header["Authorization"]; ok {
		t.Error("an Authorization header was sent without a key")
	}
	if _, ok := rec.got["max_tokens"]; ok {
		t.Error("max_tokens was sent unset")
	}
}

func TestAnthropicRequestShape(t *testing.T) {
	rec := &recorder{status: 200, body: `{"model":"claude-sonnet-5-5","content":[{"type":"thinking","thinking":""},{"type":"text","text":"the "},{"type":"text","text":"disk"}],"stop_reason":"end_turn","usage":{"input_tokens":20,"output_tokens":4}}`}
	srv := rec.server(t)
	p := &Anthropic{BaseURL: srv.URL, ModelID: "claude-sonnet-5-5", APIKey: testKey}
	resp, err := p.Complete(context.Background(), testReq)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Text != "the disk" || resp.InputTokens != 20 || resp.OutputTokens != 4 || resp.StopReason != "end_turn" {
		t.Fatalf("response = %+v", resp)
	}
	if rec.path != "/v1/messages" {
		t.Errorf("path = %q", rec.path)
	}
	if rec.header.Get("x-api-key") != testKey || rec.header.Get("anthropic-version") != AnthropicVersion {
		t.Errorf("headers = %v", rec.header)
	}
	if rec.header.Get("Authorization") != "" {
		t.Error("the key went out as Authorization too")
	}
	if rec.got["model"] != "claude-sonnet-5-5" || rec.got["system"] != "be brief" || rec.got["max_tokens"] != float64(100) {
		t.Errorf("body = %v", rec.got)
	}
	for _, k := range []string{"temperature", "top_p", "top_k", "thinking"} {
		if _, ok := rec.got[k]; ok {
			t.Errorf("body sends %s", k)
		}
	}
	msgs, _ := rec.got["messages"].([]any)
	if len(msgs) != 1 || msgs[0].(map[string]any)["role"] != "user" {
		t.Errorf("messages = %v", msgs)
	}
}

func TestAnthropicDefaultMaxTokens(t *testing.T) {
	rec := &recorder{status: 200, body: `{"content":[{"type":"text","text":"ok"}],"stop_reason":"end_turn"}`}
	srv := rec.server(t)
	p := &Anthropic{BaseURL: srv.URL, ModelID: "m", APIKey: testKey}
	if _, err := p.Complete(context.Background(), Request{Messages: []Message{{Role: RoleUser, Content: "x"}}}); err != nil {
		t.Fatal(err)
	}
	if rec.got["max_tokens"] != float64(DefaultMaxTokens) {
		t.Errorf("max_tokens = %v", rec.got["max_tokens"])
	}
}

func TestErrorMapping(t *testing.T) {
	cases := []struct {
		status int
		want   error
	}{
		{401, ErrAuth}, {403, ErrAuth}, {404, ErrNotFound}, {429, ErrRateLimited},
		{400, ErrBadRequest}, {422, ErrBadRequest}, {500, ErrUnavailable}, {529, ErrUnavailable},
	}
	for _, c := range cases {
		for _, kind := range []string{ProviderOpenAI, ProviderAnthropic} {
			// The provider echoes the key back: the error must not.
			rec := &recorder{status: c.status, body: `{"type":"error","error":{"type":"x","message":"bad key ` + testKey + `"}}`}
			srv := rec.server(t)
			p, err := New(Config{Provider: kind, BaseURL: srv.URL, Model: "m", APIKey: testKey})
			if err != nil {
				t.Fatal(err)
			}
			_, err = p.Complete(context.Background(), testReq)
			if !errors.Is(err, c.want) {
				t.Errorf("%s %d: err = %v, want %v", kind, c.status, err, c.want)
			}
			var apiErr *APIError
			if !errors.As(err, &apiErr) || apiErr.Status != c.status {
				t.Errorf("%s %d: not an APIError: %v", kind, c.status, err)
			}
			if strings.Contains(err.Error(), "SENTINEL") {
				t.Errorf("%s %d: the error quotes the key: %v", kind, c.status, err)
			}
			if !strings.Contains(err.Error(), "bad key") {
				t.Errorf("%s %d: the provider's message is lost: %v", kind, c.status, err)
			}
		}
	}
}

func TestUnreachable(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close()
	p := &OpenAI{BaseURL: url + "/v1", ModelID: "m", APIKey: testKey}
	_, err := p.Complete(context.Background(), testReq)
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v", err)
	}
	if strings.Contains(err.Error(), url) {
		t.Errorf("the error quotes the URL: %v", err)
	}
}

func TestNoRedirect(t *testing.T) {
	var followed bool
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { followed = true }))
	defer target.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/v1/messages", http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	p, _ := New(Config{Provider: ProviderAnthropic, BaseURL: srv.URL, APIKey: testKey})
	_, err := p.Complete(context.Background(), testReq)
	if err == nil || followed {
		t.Fatalf("redirect followed (%v), err = %v", followed, err)
	}
}

func TestNoAnswer(t *testing.T) {
	for _, c := range []struct{ kind, body string }{
		{ProviderOpenAI, `{"choices":[]}`},
		{ProviderOpenAI, `{"choices":[{"message":{"content":"  "},"finish_reason":"length"}]}`},
		{ProviderAnthropic, `{"content":[],"stop_reason":"refusal"}`},
		{ProviderAnthropic, `{"content":[{"type":"text","text":"partial"}],"stop_reason":"refusal"}`},
		{ProviderAnthropic, `{"content":[{"type":"thinking","thinking":""}],"stop_reason":"max_tokens"}`},
	} {
		rec := &recorder{status: 200, body: c.body}
		srv := rec.server(t)
		p, _ := New(Config{Provider: c.kind, BaseURL: srv.URL, Model: "m", APIKey: testKey})
		if _, err := p.Complete(context.Background(), testReq); !errors.Is(err, ErrNoAnswer) {
			t.Errorf("%s %s: err = %v", c.kind, c.body, err)
		}
	}
}

func TestConfig(t *testing.T) {
	cases := []struct {
		yaml string
		ok   bool
	}{
		{"", true},
		{"provider: openai\nbase_url: http://127.0.0.1:11434/v1\nmodel: llama3.2\n", true},
		{"provider: anthropic\napi_key: k\n", true},
		{"provider: anthropic\n", false},                           // no key
		{"provider: openai\nmodel: m\n", false},                    // no URL
		{"provider: openai\nbase_url: http://h/v1\n", false},       // no model
		{"provider: gemini\n", false},                              // unknown
		{"provider: openai\nbase_url: ftp://h\nmodel: m\n", false}, // scheme
		{"provider: openai\nbase_url: http://u:p@h/v1\nmodel: m\n", false},
		{"provider: openai\nbase_url: http://h/v1\nmodel: m\nmax_tokens: -1\n", false},
		{"provider: openai\nbase_url: http://h/v1\nmodel: m\nmax_context_bytes: 10\n", false},
		{"provider: openai\nbase_url: http://h/v1\nmodel: m\nextra: 1\n", false}, // unknown field
	}
	for _, c := range cases {
		cfg, err := ParseConfig([]byte(c.yaml))
		if (err == nil) != c.ok {
			t.Errorf("%q: err = %v", c.yaml, err)
		}
		if err != nil && strings.Contains(err.Error(), "SENTINEL") {
			t.Errorf("%q: error quotes a value", c.yaml)
		}
		_ = cfg
	}
	c, err := ParseConfig([]byte("provider: anthropic\napi_key: " + testKey + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.URL() != DefaultAnthropicURL || c.ModelName() != DefaultAnthropicModel {
		t.Errorf("defaults = %s %s", c.URL(), c.ModelName())
	}
	b, _ := c.Marshal()
	back, err := ParseConfig(b)
	if err != nil || back != c {
		t.Errorf("round trip = %+v, %v", back, err)
	}
	if _, err := New(Config{}); !errors.Is(err, ErrDisabled) {
		t.Errorf("New(off) = %v", err)
	}
	if _, err := ParseConfig([]byte("provider: [" + testKey)); err == nil || strings.Contains(err.Error(), "SENTINEL") {
		t.Errorf("bad yaml: %v", err)
	}
}
