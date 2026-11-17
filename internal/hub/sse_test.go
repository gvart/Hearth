// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	stdlog "log"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/gvart/hearth/internal/pki"
	"github.com/gvart/hearth/internal/policy"
	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
	"github.com/gvart/hearth/internal/proto/hearth/agent/v1/agentv1connect"
)

type sseEvent struct {
	name string
	data EventJSON
}

// readSSE parses server-sent events from body onto the returned channel and
// signals subscribed once the hub has confirmed the subscription.
func readSSE(t *testing.T, body io.Reader) (events <-chan sseEvent, subscribed <-chan struct{}) {
	t.Helper()
	ch := make(chan sseEvent, 16)
	sub := make(chan struct{})
	go func() {
		defer close(ch)
		sc := bufio.NewScanner(body)
		var name, data string
		for sc.Scan() {
			line := sc.Text()
			switch {
			case line == ": subscribed":
				close(sub)
			case strings.HasPrefix(line, "event: "):
				name = strings.TrimPrefix(line, "event: ")
			case strings.HasPrefix(line, "data: "):
				data = strings.TrimPrefix(line, "data: ")
			case line == "" && name != "":
				var e EventJSON
				if err := json.Unmarshal([]byte(data), &e); err != nil {
					t.Errorf("bad event data %q: %v", data, err)
					return
				}
				ch <- sseEvent{name: name, data: e}
				name, data = "", ""
			}
		}
	}()
	return ch, sub
}

func waitEvent(t *testing.T, events <-chan sseEvent, want string, within time.Duration) sseEvent {
	t.Helper()
	timeout := time.After(within)
	for {
		select {
		case e, ok := <-events:
			if !ok {
				t.Fatalf("event stream closed while waiting for %s", want)
			}
			if e.name == want {
				return e
			}
		case <-timeout:
			t.Fatalf("no %s event within %v", want, within)
		}
	}
}

// TestSSEDeviceOnlineOffline: subscribe to /events, connect an enrolled agent
// over mTLS, get device.online within 1s; stop it, get device.offline after
// the (shortened) offline timeout.
func TestSSEDeviceOnlineOffline(t *testing.T) {
	const offlineAfter = 500 * time.Millisecond
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
	reg := NewRegistry(RegistryConfig{Store: st, Log: log, OfflineAfter: offlineAfter})
	cfg := Config{Store: st, CA: ca, Policy: policy.New(st.Audit()), Log: log, HeartbeatInterval: time.Hour, Registry: reg}

	runCtx, stopRun := context.WithCancel(t.Context())
	runDone := make(chan struct{})
	go func() { defer close(runDone); _ = reg.Run(runCtx) }()
	t.Cleanup(func() { stopRun(); <-runDone })

	agentSrv := httptest.NewUnstartedServer(NewHandler(cfg))
	agentSrv.TLS = TLSConfig(ca, serverCert)
	agentSrv.EnableHTTP2 = true
	agentSrv.Config.ErrorLog = stdlog.New(io.Discard, "", 0)
	agentSrv.StartTLS()
	t.Cleanup(agentSrv.Close)
	webSrv := httptest.NewServer(NewHTTPHandler(cfg))
	t.Cleanup(webSrv.Close)

	// Subscribe as a logged-in admin.
	if err := st.Admin().CreateSession(t.Context(), "sse-session", time.Now(), time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, webSrv.URL+"/api/v1/events", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(testCookie("sse-session"))
	resp, err := webSrv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatalf("events: %d %s", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	events, subscribed := readSSE(t, resp.Body)
	select {
	case <-subscribed:
	case <-time.After(2 * time.Second):
		t.Fatal("no subscription confirmation")
	}

	// Enroll a device through the real EnrollService.
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert())
	tok, err := pki.NewToken(ca.Cert())
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Tokens().Create(t.Context(), tok.Secret, map[string]string{"room": "attic"}, time.Now().Add(time.Minute)); err != nil {
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
	enrolled, err := agentv1connect.NewEnrollServiceClient(&http.Client{Transport: enrollTr}, agentSrv.URL).
		Enroll(t.Context(), connect.NewRequest(&agentv1.EnrollRequest{TokenSecret: tok.Secret, Csr: csr, Hostname: "pi"}))
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	deviceID := enrolled.Msg.GetDeviceId()

	// Connect over mTLS with the issued certificate.
	agentTr := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion:   tls.VersionTLS13,
			RootCAs:      pool,
			Certificates: []tls.Certificate{{Certificate: [][]byte{enrolled.Msg.GetCertificate()}, PrivateKey: key}},
		},
		ForceAttemptHTTP2: true,
	}
	t.Cleanup(agentTr.CloseIdleConnections)
	streamCtx, cancelStream := context.WithCancel(t.Context())
	stream := agentv1connect.NewAgentServiceClient(&http.Client{Transport: agentTr}, agentSrv.URL).Connect(streamCtx)
	// The agent hangs up as a real one does on shutdown: close its side, then cancel.
	stopAgent := func() {
		_ = stream.CloseRequest()
		_ = stream.CloseResponse()
		cancelStream()
	}
	defer stopAgent()
	connectedAt := time.Now()
	if err := stream.Send(hello(ProtocolMajor)); err != nil {
		t.Fatalf("send hello: %v", err)
	}
	if msg, err := stream.Receive(); err != nil || msg.GetWelcome() == nil {
		t.Fatalf("welcome: %v %v", msg, err)
	}

	online := waitEvent(t, events, EventDeviceOnline, time.Second)
	if d := online.data.Device; d.ID != deviceID || d.Status != "online" || d.OS != "linux" || d.Labels["room"] != "attic" {
		t.Fatalf("online event device = %+v", d)
	}
	if online.data.Type != EventDeviceOnline {
		t.Errorf("data.type = %q", online.data.Type)
	}

	// Stop the agent. The device goes offline only after the timeout.
	stopAgent()
	offline := waitEvent(t, events, EventDeviceOffline, offlineAfter+2*time.Second)
	if elapsed := time.Since(connectedAt); elapsed < offlineAfter {
		t.Errorf("offline after %v, before the %v timeout", elapsed, offlineAfter)
	}
	if d := offline.data.Device; d.ID != deviceID || d.Status != "offline" {
		t.Fatalf("offline event device = %+v", d)
	}
}
