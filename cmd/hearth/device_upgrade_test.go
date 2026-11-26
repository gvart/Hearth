// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// fakeUpgradeHub answers an upgrade with status and body; once upgraded,
// the device reports v1.2.0 from its second read on.
func fakeUpgradeHub(t *testing.T, status int, body string, gotBody *string) *httptest.Server {
	t.Helper()
	var reads atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/login", func(w http.ResponseWriter, _ *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "ok", HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /api/v1/devices/{id}/upgrade", func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie("session"); err != nil || c.Value != "ok" || r.PathValue("id") != "pi" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		b, _ := io.ReadAll(r.Body)
		*gotBody = string(b)
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	})
	mux.HandleFunc("GET /api/v1/devices/{id}", func(w http.ResponseWriter, _ *http.Request) {
		v := "v1.0.0"
		if reads.Add(1) > 1 {
			v = "v1.2.0"
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"id": "pi", "status": "online", "agent_version": map[string]any{"agent": v}})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestDeviceUpgradeCmd(t *testing.T) {
	t.Setenv("HEARTH_ADMIN_PASSWORD", "pw")
	tests := []struct {
		name, body, wantOut, wantErr, wantReq string
		args                                  []string
		status                                int
	}{
		{name: "hub's version", status: http.StatusOK, body: `{"version":"v1.2.0","from":"v1.0.0"}`,
			wantReq: `{}`, wantOut: "Device pi is back on v1.2.0."},
		{name: "explicit version", args: []string{"--version", "v1.2.0"}, status: http.StatusOK,
			body: `{"version":"v1.2.0","from":"v1.0.0"}`, wantReq: `{"version":"v1.2.0"}`, wantOut: "(v1.0.0 → v1.2.0)"},
		{name: "old agent", status: http.StatusConflict,
			body:    `{"error":"the agent is too old to upgrade itself: upgrade it once with the installer","code":"agent_too_old"}`,
			wantReq: `{}`, wantErr: "upgrade pi: the agent is too old"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got string
			srv := fakeUpgradeHub(t, tt.status, tt.body, &got)
			cmd := newDeviceCmd()
			var out bytes.Buffer
			cmd.SetOut(&out)
			cmd.SetErr(io.Discard)
			cmd.SetArgs(append([]string{"upgrade", "pi", "--hub-url", srv.URL}, tt.args...))
			err := cmd.Execute()
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want %q", err, tt.wantErr)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			if strings.TrimSpace(got) != tt.wantReq {
				t.Errorf("request body = %s, want %s", got, tt.wantReq)
			}
			if !strings.Contains(out.String(), tt.wantOut) {
				t.Errorf("output = %q, want %q", out.String(), tt.wantOut)
			}
		})
	}
}
