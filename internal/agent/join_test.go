// SPDX-License-Identifier: AGPL-3.0-only

package agent_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	stdlog "log"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/gvart/hearth/internal/agent"
	"github.com/gvart/hearth/internal/hub"
	"github.com/gvart/hearth/internal/pki"
	"github.com/gvart/hearth/internal/policy"
	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
	"github.com/gvart/hearth/internal/proto/hearth/agent/v1/agentv1connect"
	"github.com/gvart/hearth/internal/store"
)

// syncBuffer collects log output from concurrent handlers.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

type testHub struct {
	url  string
	st   *store.Store
	ca   *pki.CA
	logs *syncBuffer
}

// startHub serves the real hub handler and TLS config on a loopback port.
func startHub(t *testing.T) *testHub {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(t.Context(), filepath.Join(dir, "hearth.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	ca, err := pki.LoadOrCreateCA(dir, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	cert, err := ca.IssueServerCert([]string{"127.0.0.1"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	logs := &syncBuffer{}
	log := slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))

	srv := httptest.NewUnstartedServer(hub.NewHandler(hub.Config{
		Store: st, CA: ca, Policy: policy.New(st.Audit()), Log: log,
		HeartbeatInterval: time.Second,
	}))
	srv.TLS = hub.TLSConfig(ca, cert)
	srv.EnableHTTP2 = true
	srv.Config.ErrorLog = stdlog.New(io.Discard, "", 0) // rejected handshakes are expected here
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return &testHub{url: srv.URL, st: st, ca: ca, logs: logs}
}

func (h *testHub) token(t *testing.T, expires time.Time) pki.Token {
	t.Helper()
	tok, err := pki.NewToken(h.ca.Cert())
	if err != nil {
		t.Fatal(err)
	}
	if err := h.st.Tokens().Create(t.Context(), tok.Secret, map[string]string{"room": "attic"}, expires); err != nil {
		t.Fatal(err)
	}
	return tok
}

// dial returns an AgentService client using the identity Join stored in dataDir.
func dial(t *testing.T, hubURL, dataDir string) agentv1connect.AgentServiceClient {
	t.Helper()
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS13}
	if dataDir != "" {
		pair, err := tls.LoadX509KeyPair(filepath.Join(dataDir, agent.CertFile), filepath.Join(dataDir, agent.KeyFile))
		if err != nil {
			t.Fatal(err)
		}
		caPEM, err := os.ReadFile(filepath.Join(dataDir, agent.CAFile))
		if err != nil {
			t.Fatal(err)
		}
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(caPEM)
		tlsCfg.Certificates = []tls.Certificate{pair}
		tlsCfg.RootCAs = pool
	} else {
		tlsCfg.InsecureSkipVerify = true // test: client without identity
	}
	tr := &http.Transport{TLSClientConfig: tlsCfg, ForceAttemptHTTP2: true}
	t.Cleanup(tr.CloseIdleConnections)
	return agentv1connect.NewAgentServiceClient(&http.Client{Transport: tr}, hubURL)
}

// connectHello opens a stream, sends a Hello claiming claimedID and returns the
// first reply or error.
func connectHello(t *testing.T, client agentv1connect.AgentServiceClient, claimedID string) (*agentv1.HubMessage, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	t.Cleanup(cancel)
	stream := client.Connect(ctx)
	t.Cleanup(func() { _ = stream.CloseRequest() })
	_ = stream.Send(&agentv1.AgentMessage{Payload: &agentv1.AgentMessage_Hello{Hello: &agentv1.Hello{
		ProtocolVersion: &agentv1.ProtocolVersion{Major: hub.ProtocolMajor},
		DeviceId:        claimedID,
		Hostname:        "pi",
	}}})
	return stream.Receive()
}

func TestJoinAndConnect(t *testing.T) {
	h := startHub(t)
	dataDir := filepath.Join(t.TempDir(), "agent")
	tok := h.token(t, time.Now().Add(15*time.Minute))

	id, err := agent.Join(t.Context(), h.url, tok.Encode(), dataDir, "pi")
	if err != nil {
		t.Fatalf("Join: %v", err)
	}

	if runtime.GOOS != "windows" {
		fi, err := os.Stat(filepath.Join(dataDir, agent.KeyFile))
		if err != nil {
			t.Fatal(err)
		}
		if got := fi.Mode().Perm(); got != 0o600 {
			t.Errorf("agent key mode = %o, want 600", got)
		}
	}
	dev, err := h.st.Devices().Get(t.Context(), id)
	if err != nil {
		t.Fatalf("device not stored: %v", err)
	}
	if dev.Hostname != "pi" || dev.Labels["room"] != "attic" {
		t.Errorf("device = %+v, want hostname pi and token labels", dev)
	}
	entries, err := h.st.Audit().List(t.Context(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Action != string(policy.DeviceEnroll) ||
		entries[0].Decision != policy.Allow || entries[0].Result != "ok" || entries[0].Target != id {
		t.Errorf("audit = %+v, want one allowed device.enroll of %s", entries, id)
	}

	if _, err := agent.Join(t.Context(), h.url, tok.Encode(), dataDir, "pi"); !errors.Is(err, agent.ErrAlreadyEnrolled) {
		t.Errorf("second Join err = %v, want ErrAlreadyEnrolled", err)
	}

	// The Hello claims another device; the hub must use the certificate identity.
	msg, err := connectHello(t, dial(t, h.url, dataDir), "someone-else")
	if err != nil || msg.GetWelcome() == nil {
		t.Fatalf("connect: msg=%v err=%v, want Welcome", msg, err)
	}
	logs := h.logs.String()
	if !strings.Contains(logs, `msg="agent connected" device_id=`+id) {
		t.Errorf("hub did not identify the agent as %s:\n%s", id, logs)
	}
	if !strings.Contains(logs, "claimed_device_id=someone-else") {
		t.Errorf("hub did not flag the spoofed device_id:\n%s", logs)
	}
	if strings.Contains(logs, " device_id=someone-else") {
		t.Errorf("hub used the claimed device_id as identity:\n%s", logs)
	}
}

func TestJoinRejected(t *testing.T) {
	tests := []struct {
		name string
		// setup returns the token string to join with.
		setup         func(t *testing.T, h *testHub) string
		wantCode      connect.Code
		wantErr       error
		wantAuditDeny bool
	}{
		{
			name: "expired token",
			setup: func(t *testing.T, h *testHub) string {
				return h.token(t, time.Now().Add(-time.Second)).Encode()
			},
			wantCode: connect.CodeUnauthenticated,
		},
		{
			name: "reused token",
			setup: func(t *testing.T, h *testHub) string {
				tok := h.token(t, time.Now().Add(time.Minute))
				if _, err := agent.Join(t.Context(), h.url, tok.Encode(), t.TempDir(), "first"); err != nil {
					t.Fatalf("first Join: %v", err)
				}
				return tok.Encode()
			},
			wantCode: connect.CodeUnauthenticated,
		},
		{
			name: "unknown token",
			setup: func(t *testing.T, h *testHub) string {
				tok, err := pki.NewToken(h.ca.Cert())
				if err != nil {
					t.Fatal(err)
				}
				return tok.Encode()
			},
			wantCode: connect.CodeUnauthenticated,
		},
		{
			name: "wrong CA fingerprint",
			setup: func(t *testing.T, h *testHub) string {
				tok := h.token(t, time.Now().Add(time.Minute))
				other, err := pki.LoadOrCreateCA(t.TempDir(), time.Now())
				if err != nil {
					t.Fatal(err)
				}
				tok.CAFingerprint = other.Fingerprint()
				t.Cleanup(func() {
					// The secret was never sent, so the token is still usable.
					if _, err := h.st.Tokens().Consume(context.Background(), tok.Secret, time.Now()); err != nil {
						t.Errorf("token was consumed despite the pin failing: %v", err)
					}
				})
				return tok.Encode()
			},
			wantErr: pki.ErrFingerprintMismatch,
		},
		{
			name:  "malformed token",
			setup: func(*testing.T, *testHub) string { return "hearth1.nope" },
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := startHub(t)
			token := tt.setup(t, h)
			dataDir := filepath.Join(t.TempDir(), "agent")

			_, err := agent.Join(t.Context(), h.url, token, dataDir, "pi")
			if err == nil {
				t.Fatal("Join succeeded, want error")
			}
			if tt.wantCode != 0 && connect.CodeOf(err) != tt.wantCode {
				t.Errorf("code = %v (%v), want %v", connect.CodeOf(err), err, tt.wantCode)
			}
			if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Errorf("err = %v, want %v", err, tt.wantErr)
			}
			if _, statErr := os.Stat(filepath.Join(dataDir, agent.CertFile)); statErr == nil {
				t.Error("failed Join wrote an identity")
			}
		})
	}
}

func TestAgentServiceAuth(t *testing.T) {
	h := startHub(t)
	dataDir := filepath.Join(t.TempDir(), "agent")
	id, err := agent.Join(t.Context(), h.url, h.token(t, time.Now().Add(time.Minute)).Encode(), dataDir, "pi")
	if err != nil {
		t.Fatal(err)
	}
	client := dial(t, h.url, dataDir)

	if _, err := connectHello(t, client, id); err != nil {
		t.Fatalf("connect before revoke: %v", err)
	}
	if _, err := connectHello(t, dial(t, h.url, ""), id); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Errorf("connect without client cert: %v, want Unauthenticated", err)
	}

	if _, err := h.st.Certs().RevokeDevice(t.Context(), id, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := connectHello(t, client, id); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Errorf("connect after revoke: %v, want Unauthenticated", err)
	}
	if !strings.Contains(h.logs.String(), "certificate revoked") {
		t.Errorf("revocation not logged:\n%s", h.logs.String())
	}
}

func TestForeignCAClientCertRejected(t *testing.T) {
	h := startHub(t)
	other := startHub(t)
	dataDir := filepath.Join(t.TempDir(), "agent")
	// Enrolled with another hub: its cert must not open a stream here.
	if _, err := agent.Join(t.Context(), other.url, other.token(t, time.Now().Add(time.Minute)).Encode(), dataDir, "pi"); err != nil {
		t.Fatal(err)
	}
	client := dial(t, h.url, dataDir)
	if _, err := connectHello(t, client, "x"); err == nil {
		t.Fatal("connect with a foreign CA's cert succeeded")
	}
}

// TestNoSecretInLogs drives successful and failing enrollments with debug
// logging and checks neither the token nor its secret reaches the logs or the
// audit trail.
func TestNoSecretInLogs(t *testing.T) {
	h := startHub(t)
	tok := h.token(t, time.Now().Add(time.Minute))
	expired := h.token(t, time.Now().Add(-time.Minute))

	if _, err := agent.Join(t.Context(), h.url, tok.Encode(), filepath.Join(t.TempDir(), "a"), "pi"); err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{tok.Encode(), expired.Encode()} { // reused and expired
		if _, err := agent.Join(t.Context(), h.url, s, filepath.Join(t.TempDir(), "b"), "pi"); err == nil {
			t.Fatal("want error")
		}
	}

	var trail strings.Builder
	trail.WriteString(h.logs.String())
	entries, err := h.st.Audit().List(t.Context(), 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 {
		t.Errorf("audit entries = %d, want 3", len(entries))
	}
	for _, e := range entries {
		trail.WriteString(e.ActorID + e.Target + e.Result + string(e.Detail))
	}
	for _, secret := range []string{tok.Encode(), tok.Secret, expired.Encode(), expired.Secret} {
		if strings.Contains(trail.String(), secret) {
			t.Fatalf("secret leaked into logs or audit:\n%s", trail.String())
		}
	}
	if !strings.Contains(trail.String(), "device enrolled") {
		t.Fatal("expected enrollment to be logged; captured nothing useful")
	}
}
