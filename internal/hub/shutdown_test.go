// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	stdlog "log"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/gvart/hearth/internal/pki"
	"github.com/gvart/hearth/internal/policy"
	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
	"github.com/gvart/hearth/internal/proto/hearth/agent/v1/agentv1connect"
	"github.com/gvart/hearth/internal/store"
)

// TestShutdownEndsStreams wires the servers as `hearth hub` does and shuts them
// down with an agent stream and an /events subscription open. Both must end
// cleanly at once rather than hold Shutdown up to its timeout.
func TestShutdownEndsStreams(t *testing.T) {
	dir := t.TempDir()
	st := newTestStore(t)
	ca, err := pki.LoadOrCreateCA(dir, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	serverCert, err := ca.IssueServerCert([]string{"127.0.0.1"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.DiscardHandler)
	stopping, stop := context.WithCancel(context.Background())
	defer stop()
	cfg := Config{
		Store: st, CA: ca, Policy: policy.New(st.Audit()), Log: log, HeartbeatInterval: time.Hour,
		Registry: NewRegistry(RegistryConfig{Store: st, Log: log}), Stopping: stopping,
	}

	errLog := stdlog.New(io.Discard, "", 0)
	agentSrv := &http.Server{Handler: NewHandler(cfg), TLSConfig: TLSConfig(ca, serverCert), ErrorLog: errLog}
	agentSrv.RegisterOnShutdown(stop)
	webMux := http.NewServeMux()
	webH := NewHTTPHandler(cfg)
	webMux.Handle("/", webH)
	webMux.Handle("GET /api/v1/events", EndOnStop(stopping, webH))
	webSrv := &http.Server{Handler: webMux, ErrorLog: errLog}
	webSrv.RegisterOnShutdown(stop)
	agentURL := serveOn(t, func(ln net.Listener) error { return agentSrv.ServeTLS(ln, "", "") }, "https://")
	webURL := serveOn(t, webSrv.Serve, "http://")
	t.Cleanup(func() { _ = agentSrv.Close(); _ = webSrv.Close() })

	// An /events subscriber.
	if err := st.Admin().CreateSession(t.Context(), "sse-session", time.Now(), time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, webURL+"/api/v1/events", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(testCookie("sse-session"))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	events := bufio.NewReader(resp.Body)
	if line, err := events.ReadString('\n'); err != nil || line != ": subscribed\n" {
		t.Fatalf("events: first line %q, %v", line, err)
	}

	// A connected agent.
	stream := connectTestAgent(t, st, ca, agentURL)
	if err := stream.Send(hello(ProtocolMajor)); err != nil {
		t.Fatalf("send hello: %v", err)
	}
	if msg, err := stream.Receive(); err != nil || msg.GetWelcome() == nil {
		t.Fatalf("welcome: %v %v", msg, err)
	}

	start := time.Now()
	shutdownCtx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	shutdownErr := make(chan error, 2)
	for _, srv := range []*http.Server{agentSrv, webSrv} {
		go func() { shutdownErr <- srv.Shutdown(shutdownCtx) }()
	}
	for range 2 {
		if err := <-shutdownErr; err != nil {
			t.Fatalf("shutdown: %v", err)
		}
	}
	if took := time.Since(start); took > time.Second {
		t.Errorf("shutdown took %v with open streams, want under 1s", took)
	}

	// The agent gets a proper end of stream saying why, not a broken connection.
	_, err = stream.Receive()
	var cerr *connect.Error
	if !errors.As(err, &cerr) || cerr.Code() != connect.CodeUnavailable || !strings.Contains(cerr.Message(), "shutting down") {
		t.Errorf("agent stream ended with %v, want Unavailable: hub shutting down", err)
	}
	// The event stream ends with a complete response.
	if _, err := io.Copy(io.Discard, events); err != nil {
		t.Errorf("events stream ended with %v, want a clean end", err)
	}
}

// serveOn serves on a fresh loopback listener and returns its base URL.
func serveOn(t *testing.T, serve func(net.Listener) error, scheme string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { defer close(done); _ = serve(ln) }()
	t.Cleanup(func() { <-done })
	return scheme + ln.Addr().String()
}

// connectTestAgent enrolls a device through the real EnrollService and opens
// an AgentService stream with its certificate.
func connectTestAgent(t *testing.T, st *store.Store, ca *pki.CA, url string) *connect.BidiStreamForClient[agentv1.AgentMessage, agentv1.HubMessage] {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert())
	tok, err := pki.NewToken(ca.Cert())
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Tokens().Create(t.Context(), tok.Secret, nil, time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	key, err := pki.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	csr, err := pki.NewCSR(key, "pi")
	if err != nil {
		t.Fatal(err)
	}
	enrollTr := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool}}
	t.Cleanup(enrollTr.CloseIdleConnections)
	enrolled, err := agentv1connect.NewEnrollServiceClient(&http.Client{Transport: enrollTr}, url).
		Enroll(t.Context(), connect.NewRequest(&agentv1.EnrollRequest{TokenSecret: tok.Secret, Csr: csr, Hostname: "pi"}))
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	agentTr := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion:   tls.VersionTLS13,
			RootCAs:      pool,
			Certificates: []tls.Certificate{{Certificate: [][]byte{enrolled.Msg.GetCertificate()}, PrivateKey: key}},
		},
		ForceAttemptHTTP2: true,
	}
	t.Cleanup(agentTr.CloseIdleConnections)
	stream := agentv1connect.NewAgentServiceClient(&http.Client{Transport: agentTr}, url).Connect(t.Context())
	t.Cleanup(func() { _ = stream.CloseResponse() })
	return stream
}
