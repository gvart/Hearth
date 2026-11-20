// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"io"
	stdlog "log"
	"log/slog"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/agent"
	"github.com/gvart/hearth/internal/hub"
	"github.com/gvart/hearth/internal/pki"
	"github.com/gvart/hearth/internal/policy"
)

// startTestHub serves the real agent handler over TLS on loopback and returns
// its URL and a fresh enrollment token.
func startTestHub(t *testing.T) (url, token string) {
	t.Helper()
	dir, ca := initHub(t)
	st := openStore(t, dir)
	cert, err := ca.IssueServerCert([]string{"127.0.0.1"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := httptest.NewUnstartedServer(hub.NewHandler(hub.Config{
		Store: st, CA: ca, Policy: policy.New(st.Audit()), Log: log, HeartbeatInterval: time.Second,
	}))
	srv.TLS = hub.TLSConfig(ca, cert)
	srv.EnableHTTP2 = true
	srv.Config.ErrorLog = stdlog.New(io.Discard, "", 0)
	srv.StartTLS()
	t.Cleanup(srv.Close)

	tok, err := pki.NewToken(ca.Cert())
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Tokens().Create(t.Context(), tok.Secret, nil, time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	return srv.URL, tok.Encode()
}

func TestAgentJoin(t *testing.T) {
	const warning = "token argument is visible to other local users"
	tests := []struct {
		name     string
		env      bool // put the token in HEARTH_TOKEN
		stdin    func(token string) string
		args     func(token string) []string
		wantWarn bool
	}{
		{"token from HEARTH_TOKEN", true, nil, func(string) []string { return nil }, false},
		{"token from stdin", false, func(tok string) string { return tok + "\n" }, func(string) []string { return []string{"-"} }, false},
		{"stdin without newline", false, func(tok string) string { return "  " + tok }, func(string) []string { return []string{"-"} }, false},
		{"positional token", false, nil, func(tok string) []string { return []string{tok} }, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			url, tok := startTestHub(t)
			t.Setenv(tokenEnv, "")
			if tt.env {
				t.Setenv(tokenEnv, tok)
			}
			stdin := ""
			if tt.stdin != nil {
				stdin = tt.stdin(tok)
			}
			dataDir := filepath.Join(t.TempDir(), "agent")
			args := append([]string{"agent", "join", "--data-dir", dataDir, url}, tt.args(tok)...)
			out, err := executeWithStdin(t, stdin, args...)
			if err != nil {
				t.Fatalf("join: %v\n%s", err, out)
			}
			if !strings.Contains(out, "Enrolled as device") {
				t.Errorf("output = %q", out)
			}
			if strings.Contains(out, tok) {
				t.Error("join echoed the token")
			}
			if got := strings.Contains(out, warning); got != tt.wantWarn {
				t.Errorf("argv warning printed = %v, want %v; output %q", got, tt.wantWarn, out)
			}
			if v, ok := os.LookupEnv(tokenEnv); ok {
				t.Errorf("%s still set after join (%d bytes): child processes would inherit it", tokenEnv, len(v))
			}
			if _, err := os.Stat(filepath.Join(dataDir, agent.CertFile)); err != nil {
				t.Errorf("no identity: %v", err)
			}
		})
	}
}

func TestAgentJoinRejectsMissingToken(t *testing.T) {
	for _, env := range []string{"", "  "} {
		t.Setenv(tokenEnv, env)
		_, err := executeWithStdin(t, "", "agent", "join", "--data-dir", t.TempDir(), "https://127.0.0.1:7443")
		if err == nil || !strings.Contains(err.Error(), "no enrollment token: set HEARTH_TOKEN") {
			t.Errorf("HEARTH_TOKEN=%q: err = %v, want no enrollment token", env, err)
		}
	}
	// The last join unset HEARTH_TOKEN.
	if _, ok := os.LookupEnv(tokenEnv); ok {
		t.Fatalf("%s still set after join", tokenEnv)
	}
	if _, err := executeWithStdin(t, "", "agent", "join", "--data-dir", t.TempDir(), "https://127.0.0.1:7443"); err == nil ||
		!strings.Contains(err.Error(), "no enrollment token") {
		t.Errorf("HEARTH_TOKEN unset: err = %v, want no enrollment token", err)
	}
}

func TestAgentJoinRejectsEmptyStdin(t *testing.T) {
	for _, stdin := range []string{"", "\n", "   \n"} {
		_, err := executeWithStdin(t, stdin, "agent", "join", "--data-dir", t.TempDir(), "https://127.0.0.1:7443", "-")
		if err == nil || !strings.Contains(err.Error(), "no token on stdin") {
			t.Errorf("stdin %q: err = %v, want no token on stdin", stdin, err)
		}
	}
}

// TestAgentJoinTokenFileIfNotEnrolled: the DaemonSet's join. The token comes
// from a mounted file, and a second join of the enrolled device, as when its
// pod restarts, succeeds without reading the file or reaching the hub.
func TestAgentJoinTokenFileIfNotEnrolled(t *testing.T) {
	url, tok := startTestHub(t)
	t.Setenv(tokenEnv, "")
	dataDir := filepath.Join(t.TempDir(), "agent")
	tokenFile := filepath.Join(t.TempDir(), "talos-cp-1")
	if err := os.WriteFile(tokenFile, []byte(tok+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	join := []string{"agent", "join", "--data-dir", dataDir, "--token-file", tokenFile, "--if-not-enrolled", url}
	out, err := executeWithStdin(t, "", join...)
	if err != nil || !strings.Contains(out, "Enrolled as device") {
		t.Fatalf("first join: %v\n%s", err, out)
	}
	// The token is spent and the file gone: the join must not need either.
	if err := os.Remove(tokenFile); err != nil {
		t.Fatal(err)
	}
	out, err = executeWithStdin(t, "", join...)
	if err != nil || !strings.Contains(out, "Already enrolled") {
		t.Fatalf("second join with --if-not-enrolled: %v\n%s", err, out)
	}
	if _, err := executeWithStdin(t, "", "agent", "join", "--data-dir", dataDir, "--token-file", tokenFile, url); err == nil {
		t.Error("second join without --if-not-enrolled succeeded")
	}
}

func TestAgentJoinTokenFileRejectsBadInput(t *testing.T) {
	empty := filepath.Join(t.TempDir(), "empty")
	if err := os.WriteFile(empty, []byte("\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"missing file", []string{"--token-file", filepath.Join(t.TempDir(), "nope"), "https://127.0.0.1:7443"}, "--token-file"},
		{"empty file", []string{"--token-file", empty, "https://127.0.0.1:7443"}, "no token in"},
		{"file and argument", []string{"--token-file", empty, "https://127.0.0.1:7443", "tok"}, "mutually exclusive"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := append([]string{"agent", "join", "--data-dir", t.TempDir()}, tt.args...)
			if _, err := executeWithStdin(t, "", args...); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("err = %v, want %q", err, tt.want)
			}
		})
	}
}
