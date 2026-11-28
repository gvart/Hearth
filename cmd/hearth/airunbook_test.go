// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAIRunbookCmd(t *testing.T) {
	t.Setenv("HEARTH_ADMIN_PASSWORD", "pw")
	var sent map[string]any
	valid := true
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/login", func(w http.ResponseWriter, _ *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "ok", HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET /api/v1/devices/pi5/recordings", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"recordings":[{"id":"abc123","device":"pi5","started":"2026-11-28T10:00:00Z",`+
			`"ended":"2026-11-28T10:05:00Z","expires":"2026-11-28T11:05:00Z","bytes":2048,"full":false}]}`)
	})
	mux.HandleFunc("POST /api/v1/devices/pi5/recordings/abc123/runbook", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &sent)
		res := map[string]any{
			"provider": "openai", "model": "llama3.2", "base_url": "http://ollama:11434/v1", "attempts": 1,
			"yaml": "id: add-docker\n", "file": "add-docker.yaml", "valid": valid, "preview": sent["preview"] == true, "sent_bytes": 42,
			"sent":     map[string]any{"system": "SYSTEM PROMPT", "messages": []map[string]string{{"role": "user", "content": "TRANSCRIPT"}}},
			"problems": []map[string]any{},
		}
		if !valid {
			res["problems"] = []map[string]any{{"line": 3, "message": "unknown field \"x\""}}
		}
		_ = json.NewEncoder(w).Encode(res)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	run := func(args ...string) (string, string, error) {
		cmd := newAICmd()
		cmd.SilenceUsage = true
		var out, errOut bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetErr(&errOut)
		cmd.SetIn(strings.NewReader(""))
		cmd.SetArgs(append(args, "--hub-url", srv.URL))
		err := cmd.ExecuteContext(t.Context())
		return out.String(), errOut.String(), err
	}

	out, _, err := run("recordings", "pi5")
	if err != nil || !strings.Contains(out, "abc123") || !strings.Contains(out, "2048 bytes") || !strings.Contains(out, "ended, kept until") {
		t.Fatalf("recordings = %q, %v", out, err)
	}

	out, notes, err := run("runbook", "pi5", "abc123", "--notes", "installed docker")
	if err != nil || out != "id: add-docker\n" || !strings.Contains(notes, "Nothing was saved") || !strings.Contains(notes, "add-docker.yaml") {
		t.Fatalf("out = %q, notes = %q, err = %v", out, notes, err)
	}
	if sent["notes"] != "installed docker" || sent["preview"] != false {
		t.Fatalf("request = %v", sent)
	}

	out, _, err = run("runbook", "pi5", "abc123", "--preview")
	if err != nil || !strings.Contains(out, "Would send 42 bytes") || !strings.Contains(out, "TRANSCRIPT") {
		t.Fatalf("preview = %q, %v", out, err)
	}

	valid = false
	out, notes, err = run("runbook", "pi5", "abc123")
	if !errors.Is(err, errDraftInvalid) || out != "id: add-docker\n" || !strings.Contains(notes, `line 3: unknown field "x"`) {
		t.Fatalf("out = %q, notes = %q, err = %v", out, notes, err)
	}
}
