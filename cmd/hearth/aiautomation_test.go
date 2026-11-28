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

func TestAIAutomationCmd(t *testing.T) {
	t.Setenv("HEARTH_ADMIN_PASSWORD", "pw")
	var sent map[string]any
	valid := true
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/login", func(w http.ResponseWriter, _ *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "ok", HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /api/v1/automations/draft", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &sent)
		res := map[string]any{
			"provider": "openai", "model": "llama3.2", "base_url": "http://ollama:11434/v1", "attempts": 2,
			"yaml": "id: dns-watch\n", "valid": valid, "preview": sent["preview"] == true, "sent_bytes": 42,
			"sent":     map[string]any{"system": "SYSTEM PROMPT", "messages": []map[string]string{{"role": "user", "content": "INVENTORY"}}},
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
		cmd.SilenceUsage = true // as the root command does
		var out, errOut bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetErr(&errOut)
		cmd.SetIn(strings.NewReader(""))
		cmd.SetArgs(append(args, "--hub-url", srv.URL))
		err := cmd.ExecuteContext(t.Context())
		return out.String(), errOut.String(), err
	}

	// Only the YAML goes to stdout, to pipe into a file.
	out, notes, err := run("automation", "restart pihole when DNS fails")
	if err != nil || out != "id: dns-watch\n" || !strings.Contains(notes, "2 answer(s)") || !strings.Contains(notes, "Nothing was saved") {
		t.Fatalf("out = %q, notes = %q, err = %v", out, notes, err)
	}
	if sent["text"] != "restart pihole when DNS fails" || sent["preview"] != false {
		t.Fatalf("request = %v", sent)
	}

	out, _, err = run("automation", "x", "--preview")
	if err != nil || !strings.Contains(out, "Would send 42 bytes") || !strings.Contains(out, "INVENTORY") {
		t.Fatalf("preview = %q, %v", out, err)
	}

	// An invalid draft is still printed, its problems said, and the command fails.
	valid = false
	out, notes, err = run("automation", "x")
	if !errors.Is(err, errDraftInvalid) || out != "id: dns-watch\n" || !strings.Contains(notes, `line 3: unknown field "x"`) {
		t.Fatalf("out = %q, notes = %q, err = %v", out, notes, err)
	}
}
