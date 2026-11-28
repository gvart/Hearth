// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeAIHub answers the AI API as the hub does, recording the bodies it is
// sent by path.
func fakeAIHub(t *testing.T, got map[string]string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/login", func(w http.ResponseWriter, _ *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "ok", HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
		w.WriteHeader(http.StatusNoContent)
	})
	record := func(r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got[r.Method+" "+r.URL.Path] = string(b)
	}
	mux.HandleFunc("POST /api/v1/devices/{id}/explain", func(w http.ResponseWriter, r *http.Request) {
		record(r)
		var req map[string]any
		_ = json.Unmarshal([]byte(got[r.Method+" "+r.URL.Path]), &req)
		answer := "The disk is full [device]."
		if req["preview"] == true {
			answer = ""
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"provider": "openai", "model": "llama3.2", "base_url": "http://ollama:11434/v1", "answer": answer,
			"preview": req["preview"] == true, "sent_bytes": 42, "redactions": 1, "notes": []string{"log x left out"},
			"sent": map[string]any{"system": "SYSTEM PROMPT", "messages": []map[string]string{{"role": "user", "content": "EVIDENCE"}}},
		})
	})
	mux.HandleFunc("GET /api/v1/ai", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"enabled": true, "provider": "anthropic", "base_url": "https://api.anthropic.com",
			"model": "claude-sonnet-5-5", "api_key_set": true, "revision": "rev1",
		})
	})
	mux.HandleFunc("PUT /api/v1/ai/config", func(w http.ResponseWriter, r *http.Request) {
		record(r)
		_ = json.NewEncoder(w).Encode(map[string]any{"enabled": false})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func runAI(t *testing.T, srv *httptest.Server, args ...string) string {
	t.Helper()
	cmd := newAICmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(io.Discard)
	cmd.SetIn(strings.NewReader(""))
	cmd.SetArgs(append(args, "--hub-url", srv.URL))
	if err := cmd.ExecuteContext(t.Context()); err != nil {
		t.Fatalf("%v: %v", args, err)
	}
	return out.String()
}

func TestAIExplainCmd(t *testing.T) {
	t.Setenv("HEARTH_ADMIN_PASSWORD", "pw")
	got := map[string]string{}
	srv := fakeAIHub(t, got)

	out := runAI(t, srv, "explain", "pi", "-q", "why slow?", "--log", "systemd:nginx.service")
	if !strings.Contains(out, "The disk is full [device].") || !strings.Contains(out, "Note: log x left out") ||
		strings.Contains(out, "EVIDENCE") {
		t.Errorf("out = %q", out)
	}
	var req map[string]any
	_ = json.Unmarshal([]byte(got["POST /api/v1/devices/pi/explain"]), &req)
	if req["question"] != "why slow?" || req["preview"] != false {
		t.Errorf("request = %v", req)
	}
	if logs, _ := req["logs"].([]any); len(logs) != 1 || logs[0] != "systemd:nginx.service" {
		t.Errorf("logs = %v", req["logs"])
	}

	out = runAI(t, srv, "explain", "pi", "--preview")
	if !strings.Contains(out, "Would send 42 bytes") || !strings.Contains(out, "SYSTEM PROMPT") || !strings.Contains(out, "EVIDENCE") {
		t.Errorf("preview out = %q", out)
	}
}

func TestAISetCmd(t *testing.T) {
	t.Setenv("HEARTH_ADMIN_PASSWORD", "pw")
	got := map[string]string{}
	srv := fakeAIHub(t, got)

	if out := runAI(t, srv, "status"); !strings.Contains(out, "claude-sonnet-5-5") || !strings.Contains(out, "API key:  set") {
		t.Errorf("status = %q", out)
	}

	keyFile := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(keyFile, []byte("sk-from-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HEARTH_AI_API_KEY", "sk-from-env")
	runAI(t, srv, "set", "--provider", "anthropic", "--api-key-file", keyFile)
	var req map[string]any
	_ = json.Unmarshal([]byte(got["PUT /api/v1/ai/config"]), &req)
	// The flag wins over the environment.
	if req["provider"] != "anthropic" || req["api_key"] != "sk-from-file" || req["revision"] != "rev1" {
		t.Errorf("set = %v", req)
	}
	runAI(t, srv, "set", "--provider", "openai", "--base-url", "http://h/v1", "--model", "m")
	_ = json.Unmarshal([]byte(got["PUT /api/v1/ai/config"]), &req)
	if req["api_key"] != "sk-from-env" || req["base_url"] != "http://h/v1" {
		t.Errorf("set from env = %v", req)
	}
	if out := runAI(t, srv, "set", "--off"); !strings.Contains(out, "AI is off.") {
		t.Errorf("off = %q", out)
	}
	req = map[string]any{}
	_ = json.Unmarshal([]byte(got["PUT /api/v1/ai/config"]), &req)
	if req["provider"] != "" || req["api_key"] != nil {
		t.Errorf("off = %v", req)
	}
}
