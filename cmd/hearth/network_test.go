// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fakeScanHub answers POST /api/v1/network/scan with status and, when it
// is 202, sends on the event stream the command opened first the end of
// another admin's scan, then done.
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
		_, _ = fmt.Fprint(w, "event: network.scan.done\ndata: {\"type\":\"network.scan.done\",\"id\":\"other\",\"error\":\"not mine\"}\n\n")
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

// fakeHostsHub serves the network hosts and records the adopt and unadopt
// requests it gets, as "verb mac body".
func fakeHostsHub(t *testing.T, got *[]string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/login", func(w http.ResponseWriter, _ *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "ok", HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET /api/v1/network/hosts", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, `{"hosts":[
			{"mac":"00:11:32:00:00:05","ip":"192.168.2.50","hostname":"lgtv","name":"Living room TV","kind":"media","state":"adopted","online":true},
			{"mac":"00:11:32:00:00:06","ip":"192.168.2.60","hostname":"","name":"","kind":"unknown","state":"","online":false}]}`)
	})
	mux.HandleFunc("POST /api/v1/network/hosts/{mac}/{verb}", func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie("session"); err != nil || c.Value != "ok" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		b, _ := io.ReadAll(r.Body)
		*got = append(*got, r.PathValue("verb")+" "+r.PathValue("mac")+" "+string(b))
		if r.PathValue("mac") == "aa:aa:aa:aa:aa:aa" {
			w.WriteHeader(http.StatusNotFound)
			_, _ = fmt.Fprint(w, `{"error":"no such host","code":"not_found"}`)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestNetworkAdoptCommands(t *testing.T) {
	t.Setenv("HEARTH_ADMIN_PASSWORD", "pw")
	var got []string
	srv := fakeHostsHub(t, &got)
	run := func(args ...string) (string, error) {
		cmd := newNetworkCmd()
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetErr(&out)
		cmd.SetArgs(append(args, "--hub-url", srv.URL))
		err := cmd.ExecuteContext(t.Context())
		return out.String(), err
	}
	if _, err := run("adopt", "00:11:32:00:00:05", "--name", "Living room TV"); err != nil {
		t.Fatal(err)
	}
	if _, err := run("unadopt", "00:11:32:00:00:05"); err != nil {
		t.Fatal(err)
	}
	want := []string{`adopt 00:11:32:00:00:05 {"name":"Living room TV"}`, "unadopt 00:11:32:00:00:05 "}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("requests = %q, want %q", got, want)
	}
	if _, err := run("adopt", "00:11:32:00:00:05"); err == nil || !strings.Contains(err.Error(), "name") {
		t.Errorf("adopt without --name = %v, want an error naming the flag", err)
	}
	if _, err := run("adopt", "aa:aa:aa:aa:aa:aa", "--name", "x"); err == nil || !strings.Contains(err.Error(), "no such host") {
		t.Errorf("adopt of an unknown host = %v, want the hub's error", err)
	}

	out, err := run("hosts")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{
		"MAC                IP            NAME            KIND     STATE    ONLINE",
		"00:11:32:00:00:05  192.168.2.50  Living room TV  media    adopted  yes",
		"00:11:32:00:00:06  192.168.2.60  -               unknown  -        no",
	} {
		if !strings.Contains(out, line) {
			t.Errorf("hosts output lacks %q:\n%s", line, out)
		}
	}
}

func TestNetworkScanCommand(t *testing.T) {
	tests := []struct {
		name       string
		status     int
		body, done string
		want       string
		wantErr    string
	}{
		{
			name: "prints the result", status: http.StatusAccepted, body: `{"id":"s1"}`,
			done: `{"type":"network.scan.done","id":"s1","hosts":14,"new":3,"returned":1,"duration_ms":2300}`,
			want: "Found 14 hosts: 3 new, 1 back (2.3s)",
		},
		{
			name: "a failed scan is an error", status: http.StatusAccepted, body: `{"id":"s1"}`,
			done: `{"type":"network.scan.done","id":"s1","error":"sweep: boom"}`, wantErr: "the scan failed: sweep: boom",
		},
		{
			name: "a running scan is an error", status: http.StatusConflict,
			body: `{"error":"a network scan is already running","code":"scan_running"}`, wantErr: "already running",
		},
		{
			name: "a denied scan is an error", status: http.StatusForbidden,
			body: `{"error":"denied by policy","code":"forbidden"}`, wantErr: "denied by policy",
		},
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
