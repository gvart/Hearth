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
	tests := []struct {
		name  string
		stdin func(token string) string
		arg   func(token string) string
	}{
		{"token from stdin", func(tok string) string { return tok + "\n" }, func(string) string { return "-" }},
		{"stdin without newline", func(tok string) string { return "  " + tok }, func(string) string { return "-" }},
		{"positional token", func(string) string { return "" }, func(tok string) string { return tok }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			url, tok := startTestHub(t)
			dataDir := filepath.Join(t.TempDir(), "agent")
			out, err := executeWithStdin(t, tt.stdin(tok), "agent", "join", "--data-dir", dataDir, url, tt.arg(tok))
			if err != nil {
				t.Fatalf("join: %v\n%s", err, out)
			}
			if !strings.Contains(out, "Enrolled as device") {
				t.Errorf("output = %q", out)
			}
			if strings.Contains(out, tok) {
				t.Error("join echoed the token")
			}
			if _, err := os.Stat(filepath.Join(dataDir, agent.CertFile)); err != nil {
				t.Errorf("no identity: %v", err)
			}
		})
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
