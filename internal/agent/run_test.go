// SPDX-License-Identifier: AGPL-3.0-only

package agent_test

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	stdlog "log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/agent"
	"github.com/gvart/hearth/internal/hub"
	"github.com/gvart/hearth/internal/pki"
	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

// restartableHub serves the real hub handler on a fixed loopback address that
// survives stop/start, like a hub process being restarted.
type restartableHub struct {
	t       *testing.T
	addr    string
	url     string
	handler http.Handler
	tls     *tls.Config
	st      *store.Store
	ca      *pki.CA
	logs    *syncBuffer
	srv     *http.Server
	done    chan struct{}
}

func startRestartableHub(t *testing.T, heartbeat time.Duration) *restartableHub {
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
	h := &restartableHub{
		t: t,
		handler: hub.NewHandler(hub.Config{
			Store: st, CA: ca, Policy: policy.New(st.Audit()), Log: log, HeartbeatInterval: heartbeat,
		}),
		tls:  hub.TLSConfig(ca, cert),
		st:   st,
		ca:   ca,
		logs: logs,
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	h.addr = ln.Addr().String()
	h.url = "https://" + h.addr
	h.serve(ln)
	t.Cleanup(h.stop)
	return h
}

func (h *restartableHub) serve(ln net.Listener) {
	h.srv = &http.Server{
		Handler:           h.handler,
		TLSConfig:         h.tls.Clone(),
		ReadHeaderTimeout: 5 * time.Second,
		ErrorLog:          stdlog.New(io.Discard, "", 0),
	}
	h.done = make(chan struct{})
	go func(srv *http.Server, done chan struct{}) {
		defer close(done)
		_ = srv.ServeTLS(ln, "", "")
	}(h.srv, h.done)
}

// stop closes the listener and every connection, like a hub process exiting.
func (h *restartableHub) stop() {
	if h.srv == nil {
		return
	}
	_ = h.srv.Close()
	<-h.done
	h.srv = nil
}

// start listens again on the same address.
func (h *restartableHub) start() {
	h.t.Helper()
	var ln net.Listener
	var err error
	for range 50 { // the old socket can linger briefly
		if ln, err = net.Listen("tcp", h.addr); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		h.t.Fatalf("relisten on %s: %v", h.addr, err)
	}
	h.serve(ln)
}

func (h *restartableHub) join(t *testing.T) (id, dataDir string) {
	t.Helper()
	tok, err := pki.NewToken(h.ca.Cert())
	if err != nil {
		t.Fatal(err)
	}
	if err := h.st.Tokens().Create(t.Context(), tok.Secret, nil, time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	dataDir = filepath.Join(t.TempDir(), "agent")
	id, err = agent.Join(t.Context(), h.url, tok.Encode(), dataDir, "pi")
	if err != nil {
		t.Fatalf("Join: %v", err)
	}
	return id, dataDir
}

// runningAgent is agent.Run in the background.
type runningAgent struct {
	logs   *syncBuffer
	cancel context.CancelFunc
	done   chan error
}

func startAgent(t *testing.T, dataDir string) *runningAgent {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	a := &runningAgent{logs: &syncBuffer{}, cancel: cancel, done: make(chan error, 1)}
	log := slog.New(slog.NewTextHandler(a.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	go func() { a.done <- agent.Run(ctx, agent.Config{DataDir: dataDir, Version: "test", Log: log}) }()
	t.Cleanup(func() { a.stop(t) })
	return a
}

// stop cancels the agent and checks it returns nil promptly.
func (a *runningAgent) stop(t *testing.T) {
	t.Helper()
	if a.done == nil {
		return
	}
	a.cancel()
	select {
	case err := <-a.done:
		if err != nil {
			t.Errorf("Run returned %v after cancel, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Error("Run did not return within 5s of cancel")
	}
	a.done = nil
}

// running reports whether Run is still going, failing the test if it returned.
func (a *runningAgent) assertRunning(t *testing.T) {
	t.Helper()
	select {
	case err := <-a.done:
		a.done = nil
		t.Fatalf("Run returned early: %v", err)
	default:
	}
}

// waitFor polls cond until it holds or timeout passes.
func waitFor(t *testing.T, timeout time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %v waiting for %s", timeout, what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestRunReconnectsAfterHubRestart(t *testing.T) {
	h := startRestartableHub(t, time.Second)
	id, dataDir := h.join(t)
	a := startAgent(t, dataDir)

	connected := func(n int) func() bool {
		return func() bool { return strings.Count(h.logs.String(), `msg="agent connected" device_id=`+id) >= n }
	}
	waitFor(t, 10*time.Second, "first connection", connected(1))
	// The hub asked for 1 s heartbeats (the default is 10 s).
	waitFor(t, 5*time.Second, "a heartbeat", func() bool { return strings.Contains(h.logs.String(), `msg=heartbeat device_id=`+id) })

	h.stop()
	h.start()
	restarted := time.Now()
	waitFor(t, 5*time.Second, "reconnection after hub restart", connected(2))
	t.Logf("reconnected %v after the hub came back", time.Since(restarted).Round(time.Millisecond))
	a.assertRunning(t)
	a.stop(t)
	if !strings.Contains(a.logs.String(), "reconnecting") {
		t.Errorf("agent did not log the lost connection:\n%s", a.logs.String())
	}
}

func TestRunUnreachableHub(t *testing.T) {
	h := startRestartableHub(t, time.Second)
	_, dataDir := h.join(t)
	h.stop()

	a := startAgent(t, dataDir)
	// Delays are 0.5–1 s then 1–2 s, so two failures fit in 2.5 s.
	waitFor(t, 5*time.Second, "two failed attempts", func() bool {
		return strings.Count(a.logs.String(), "reconnecting") >= 2
	})
	a.assertRunning(t)
	a.stop(t)
}

func TestRunRevokedCertBacksOff(t *testing.T) {
	h := startRestartableHub(t, time.Second)
	id, dataDir := h.join(t)
	if _, err := h.st.Certs().RevokeDevice(t.Context(), id, time.Now()); err != nil {
		t.Fatal(err)
	}

	a := startAgent(t, dataDir)
	time.Sleep(4 * time.Second)
	a.assertRunning(t)
	a.stop(t)

	// Attempts at 0, then after 0.5–1 s, 1–2 s, 2–4 s: 3 or 4 in 4 s. A spinning
	// agent would make hundreds.
	if n := strings.Count(h.logs.String(), "certificate revoked"); n < 2 || n > 5 {
		t.Errorf("hub saw %d attempts with the revoked cert in 4s, want 2-5:\n%s", n, a.logs.String())
	}
	if strings.Contains(h.logs.String(), `msg="agent connected"`) {
		t.Error("revoked agent was let in")
	}
}

func TestRunMissingIdentity(t *testing.T) {
	h := startRestartableHub(t, time.Second)
	for _, missing := range []string{agent.CertFile, agent.KeyFile, agent.CAFile, agent.HubURLFile} {
		t.Run("without "+missing, func(t *testing.T) {
			_, dataDir := h.join(t)
			if err := os.Remove(filepath.Join(dataDir, missing)); err != nil {
				t.Fatal(err)
			}
			assertRunFails(t, dataDir, agent.ErrNotEnrolled)
		})
	}
	t.Run("empty data dir", func(t *testing.T) {
		assertRunFails(t, t.TempDir(), agent.ErrNotEnrolled)
	})
	t.Run("bad hub URL", func(t *testing.T) {
		_, dataDir := h.join(t)
		if err := os.WriteFile(filepath.Join(dataDir, agent.HubURLFile), []byte("http://plain\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		assertRunFails(t, dataDir, nil)
	})
}

func assertRunFails(t *testing.T, dataDir string, want error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	err := agent.Run(ctx, agent.Config{DataDir: dataDir, Log: slog.New(slog.DiscardHandler)})
	if err == nil {
		t.Fatal("Run succeeded, want error")
	}
	if want != nil && !errors.Is(err, want) {
		t.Errorf("Run err = %v, want %v", err, want)
	}
}

func TestJoinStoresHubURL(t *testing.T) {
	h := startRestartableHub(t, time.Second)
	_, dataDir := h.join(t)
	b, err := os.ReadFile(filepath.Join(dataDir, agent.HubURLFile))
	if err != nil {
		t.Fatal(err)
	}
	if got := string(b); got != h.url+"\n" {
		t.Errorf("%s = %q, want %q", agent.HubURLFile, got, h.url+"\n")
	}
}
