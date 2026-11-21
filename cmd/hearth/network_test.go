// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fakeScanHub answers POST /api/v1/network/scan with status and, when it
// is 202, sends done on the event stream the command opened first.
func fakeScanHub(t *testing.T, status int, body, done string) *httptest.Server {
	t.Helper()
	started := make(chan struct{}, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/login", func(w http.ResponseWriter, _ *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "ok", HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET /api/v1/events", func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie("session"); err != nil || c.Value != "ok" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = fmt.Fprint(w, ": subscribed\n\n")
		w.(http.Flusher).Flush()
		select {
		case <-started:
		case <-r.Context().Done():
			return
		}
		_, _ = fmt.Fprint(w, "event: device.updated\ndata: {}\n\n")
		_, _ = fmt.Fprintf(w, "event: network.scan.done\ndata: %s\n\n", done)
	})
	mux.HandleFunc("POST /api/v1/network/scan", func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie("session"); err != nil || c.Value != "ok" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
		if status == http.StatusAccepted {
			started <- struct{}{}
		}
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestNetworkScanCommand(t *testing.T) {
	tests := []struct {
		name       string
		status     int
		body, done string
		want       string
		wantErr    string
	}{
		{name: "prints the result", status: http.StatusAccepted, body: `{"status":"started"}`,
			done: `{"type":"network.scan.done","hosts":14,"new":3,"returned":1,"duration_ms":2300}`,
			want: "Found 14 hosts: 3 new, 1 back (2.3s)"},
		{name: "a failed scan is an error", status: http.StatusAccepted, body: `{"status":"started"}`,
			done: `{"type":"network.scan.done","error":"sweep: boom"}`, wantErr: "the scan failed: sweep: boom"},
		{name: "a running scan is an error", status: http.StatusConflict,
			body: `{"error":"a network scan is already running","code":"scan_running"}`, wantErr: "already running"},
		{name: "a denied scan is an error", status: http.StatusForbidden,
			body: `{"error":"denied by policy","code":"forbidden"}`, wantErr: "denied by policy"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("HEARTH_ADMIN_PASSWORD", "pw")
			srv := fakeScanHub(t, tt.status, tt.body, tt.done)
			cmd := newNetworkCmd()
			var out bytes.Buffer
			cmd.SetOut(&out)
			cmd.SetErr(&out)
			cmd.SetArgs([]string{"scan", "--hub-url", srv.URL})
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
			if !strings.Contains(out.String(), tt.want) {
				t.Errorf("output lacks %q:\n%s", tt.want, out.String())
			}
		})
	}
}
