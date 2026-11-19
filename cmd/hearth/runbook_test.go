// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fakeRunbookHub is the part of the hub's API the commands use. It requires
// the session cookie it hands out at login.
func fakeRunbookHub(t *testing.T, answers *[]map[string]string) *httptest.Server {
	t.Helper()
	const run = `{"id":"r1","runbook_id":"rb","status":"failed","can_retry":true,"can_rollback":true,
		"steps":[{"id":"s","type":"action","what":"do it","status":"failed","error":"boom"}],
		"log":[{"at":"2026-01-01T00:00:00Z","step":"s","message":"failed: boom"}]}`
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/login", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Password != "pw" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"wrong password","code":"unauthorized"}`))
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "ok", HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
		w.WriteHeader(http.StatusNoContent)
	})
	authed := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if c, err := r.Cookie("session"); err != nil || c.Value != "ok" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			h(w, r)
		}
	}
	mux.HandleFunc("GET /api/v1/runbooks/rb/plan", authed(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"id":"rb","steps":[{"id":"s","type":"action","what":"do it","action":"automation.exec",
			"class":"dangerous","decision":"deny","reason":"no grant"}]}`))
	}))
	mux.HandleFunc("GET /api/v1/runbook-runs/r1", authed(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(run))
	}))
	mux.HandleFunc("POST /api/v1/runbook-runs/r1/retry", authed(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"error":"the run has moved on: reload it and try again","code":"conflict"}`))
	}))
	mux.HandleFunc("POST /api/v1/runbook-runs/r1/answer", authed(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		*answers = append(*answers, body)
		_, _ = w.Write([]byte(run))
	}))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestRunbookCommands(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		stdin   string
		want    []string
		wantErr string
	}{
		{
			name: "plan shows the decision and runs nothing", args: []string{"plan", "rb"}, stdin: "pw\n",
			want: []string{"automation.exec (dangerous) would be deny: no grant", "nothing was executed"},
		},
		{
			name: "show offers retry and rollback", args: []string{"show", "r1"}, stdin: "pw\n",
			want: []string{"error: boom", "hearth runbook retry r1", "failed: boom"},
		},
		{name: "a refused retry is an error", args: []string{"retry", "r1"}, stdin: "pw\n", wantErr: "the run has moved on"},
		{name: "a wrong password is an error", args: []string{"show", "r1"}, stdin: "nope\n", wantErr: "wrong password"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("HEARTH_ADMIN_PASSWORD", "")
			var answers []map[string]string
			srv := fakeRunbookHub(t, &answers)
			cmd := newRunbookCmd()
			var out bytes.Buffer
			cmd.SetOut(&out)
			cmd.SetErr(&out)
			cmd.SetIn(strings.NewReader(tt.stdin))
			cmd.SetArgs(append(tt.args, "--hub-url", srv.URL))
			err := cmd.ExecuteContext(t.Context())
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			for _, w := range tt.want {
				if !strings.Contains(out.String(), w) {
					t.Errorf("output lacks %q:\n%s", w, out.String())
				}
			}
		})
	}
}

// TestRunbookAnswerFromPipedInput reads the password and then the answer from
// the same input, and never prints the answer.
func TestRunbookAnswerFromPipedInput(t *testing.T) {
	t.Setenv("HEARTH_ADMIN_PASSWORD", "")
	var answers []map[string]string
	srv := fakeRunbookHub(t, &answers)
	cmd := newRunbookCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetIn(strings.NewReader("pw\ns3cret-answer\n"))
	cmd.SetArgs([]string{"answer", "r1", "token", "--hub-url", srv.URL})
	if err := cmd.ExecuteContext(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(answers) != 1 || answers[0]["step"] != "token" || answers[0]["value"] != "s3cret-answer" {
		t.Fatalf("answers = %v", answers)
	}
	if strings.Contains(out.String(), "s3cret-answer") {
		t.Errorf("the answer was printed:\n%s", out.String())
	}
}

func TestRunbookCommandRejectsABadHubURL(t *testing.T) {
	t.Setenv("HEARTH_ADMIN_PASSWORD", "pw")
	cmd := newRunbookCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"list", "--hub-url", "ftp://hub"})
	if err := cmd.ExecuteContext(t.Context()); err == nil || !strings.Contains(err.Error(), "--hub-url") {
		t.Fatalf("err = %v", err)
	}
}
