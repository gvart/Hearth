// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/gvart/hearth/internal/store"
)

// fakeProtocolHub is a hub with one Device Protocol device, kitchen: it
// answers its commands with status and body, and records each request.
type fakeProtocolHub struct {
	mu       sync.Mutex
	requests []string
}

func (f *fakeProtocolHub) record(r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, r.Method+" "+r.URL.Path+" "+string(b))
}

func startFakeProtocolHub(t *testing.T, status int, body string) (*httptest.Server, *fakeProtocolHub) {
	t.Helper()
	f := &fakeProtocolHub{}
	kitchen := store.ProtocolDeviceID("kitchen")
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/login", func(w http.ResponseWriter, _ *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "ok", HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
		w.WriteHeader(http.StatusNoContent)
	})
	answer := func(w http.ResponseWriter, r *http.Request) {
		f.record(r)
		if c, err := r.Cookie("session"); err != nil || c.Value != "ok" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.PathValue("id") != kitchen {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":"no such device protocol device","code":"not_found"}`))
			return
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}
	mux.HandleFunc("POST /api/v1/devices/{id}/commands", answer)
	mux.HandleFunc("DELETE /api/v1/devices/{id}", answer)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, f
}

func TestDeviceCommandCmd(t *testing.T) {
	t.Setenv("HEARTH_ADMIN_PASSWORD", "pw")
	kitchen := store.ProtocolDeviceID("kitchen")
	tests := []struct {
		name, body, wantOut, wantErr string
		args, wantRequests           []string
		status                       int
	}{
		{
			name: "by protocol id, with params", status: http.StatusOK,
			body: `{"id":"c1","command":"relay.set","class":"dangerous","ok":true,"message":"relay on"}`,
			args: []string{"kitchen", "relay.set", "--param", "on=true", "--param", "label=porch", "--param", `level={"a":1}`},
			wantRequests: []string{
				`POST /api/v1/devices/kitchen/commands {"command":"relay.set","params":{"label":"porch","level":{"a":1},"on":true}}`,
				"POST /api/v1/devices/" + kitchen + `/commands {"command":"relay.set","params":{"label":"porch","level":{"a":1},"on":true}}`,
			},
			wantOut: "relay.set on kitchen: ok: relay on",
		},
		{
			name: "by device ID, no params", status: http.StatusOK,
			body:         `{"id":"c1","command":"restart","class":"dangerous","ok":true}`,
			args:         []string{kitchen, "restart"},
			wantRequests: []string{"POST /api/v1/devices/" + kitchen + `/commands {"command":"restart"}`},
			wantOut:      "restart on " + kitchen + ": ok\n",
		},
		{
			name: "the device says it failed", status: http.StatusBadGateway,
			body: `{"id":"c1","command":"restart","ok":false,"message":"busy","error":"the device answered that the command failed: busy","code":"command_failed"}`,
			args: []string{kitchen, "restart"}, wantErr: "restart on " + kitchen + ": the device answered that the command failed: busy",
		},
		{
			name: "needs the password", status: http.StatusForbidden,
			body: `{"error":"denied by policy","code":"forbidden"}`,
			args: []string{kitchen, "restart"}, wantErr: "denied by policy",
		},
		{
			name: "unknown device", args: []string{"garage", "restart"}, wantErr: "no such device protocol device",
			wantRequests: []string{
				`POST /api/v1/devices/garage/commands {"command":"restart"}`,
				"POST /api/v1/devices/" + store.ProtocolDeviceID("garage") + `/commands {"command":"restart"}`,
			},
		},
		{name: "a bad param", args: []string{kitchen, "relay.set", "--param", "on"}, wantErr: `--param "on": want key=value`},
		{name: "a param twice", args: []string{kitchen, "relay.set", "--param", "a=1", "--param", "a=2"}, wantErr: "--param a is given twice"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv, f := startFakeProtocolHub(t, tt.status, tt.body)
			cmd := newDeviceCmd()
			var out bytes.Buffer
			cmd.SetOut(&out)
			cmd.SetErr(io.Discard)
			cmd.SetArgs(append([]string{"command", "--hub-url", srv.URL}, tt.args...))
			err := cmd.Execute()
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want %q", err, tt.wantErr)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(out.String(), tt.wantOut) {
				t.Errorf("output = %q, want %q", out.String(), tt.wantOut)
			}
			if tt.wantRequests != nil && strings.Join(f.requests, "\n") != strings.Join(tt.wantRequests, "\n") {
				t.Errorf("requests:\n%s\nwant:\n%s", strings.Join(f.requests, "\n"), strings.Join(tt.wantRequests, "\n"))
			}
		})
	}
}

func TestDeviceRemoveCmd(t *testing.T) {
	t.Setenv("HEARTH_ADMIN_PASSWORD", "pw")
	kitchen := store.ProtocolDeviceID("kitchen")
	tests := []struct {
		name, device, body, wantOut, wantErr string
		status                               int
	}{
		{
			name: "removed with its user", device: "kitchen", status: http.StatusOK,
			body:    `{"id":"` + kitchen + `","mqtt_user_removed":true,"class":"dangerous"}`,
			wantOut: "Removed device " + kitchen + ".\nIts MQTT user is gone from this hub's clients file",
		},
		{
			name: "no user on this hub", device: kitchen, status: http.StatusOK,
			body:    `{"id":"` + kitchen + `","mqtt_user_removed":false,"class":"dangerous"}`,
			wantOut: "remove its user from the clients file of the hub it connects to",
		},
		{
			name: "denied", device: kitchen, status: http.StatusForbidden,
			body: `{"error":"denied by policy","code":"forbidden"}`, wantErr: "remove " + kitchen + ": denied by policy",
		},
		{name: "unknown device", device: "garage", wantErr: "remove garage: no such device protocol device"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv, f := startFakeProtocolHub(t, tt.status, tt.body)
			cmd := newDeviceCmd()
			var out bytes.Buffer
			cmd.SetOut(&out)
			cmd.SetErr(io.Discard)
			cmd.SetArgs([]string{"remove", "--hub-url", srv.URL, tt.device})
			err := cmd.Execute()
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want %q", err, tt.wantErr)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(out.String(), tt.wantOut) {
				t.Errorf("output = %q, want %q", out.String(), tt.wantOut)
			}
			for _, r := range f.requests {
				if !strings.HasPrefix(r, "DELETE /api/v1/devices/") {
					t.Errorf("request %q", r)
				}
			}
		})
	}
}
