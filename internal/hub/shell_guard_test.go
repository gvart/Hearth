// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/gvart/hearth/internal/policy"
	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
	"github.com/gvart/hearth/internal/store"
)

func TestShellTransport(t *testing.T) {
	t.Parallel()
	const (
		lan      = "192.168.2.50:50000"
		loopback = "127.0.0.1:50000"
	)
	for name, tc := range map[string]struct {
		origin, host, remote string
		tls, forwarded       bool
		want                 string // the refusal; empty allows
	}{
		"tls":                          {origin: "https://hub.lan:7443", host: "hub.lan:7443", remote: lan, tls: true},
		"tls, origin in another case":  {origin: "https://HUB.lan:7443", host: "hub.lan:7443", remote: lan, tls: true},
		"proxy terminating tls":        {origin: "https://hub.example", host: "hub.example", remote: lan},
		"loopback, localhost":          {origin: "http://localhost:7080", host: "localhost:7080", remote: loopback},
		"loopback, 127.0.0.1":          {origin: "http://127.0.0.1:7080", host: "127.0.0.1:7080", remote: loopback},
		"loopback, ipv6":               {origin: "http://[::1]:7080", host: "[::1]:7080", remote: "[::1]:50000"},
		"lan http":                     {origin: "http://192.168.2.124:7080", host: "192.168.2.124:7080", remote: lan, want: "HTTPS"},
		"lan http, forwarded as https": {origin: "http://192.168.2.124:7080", host: "192.168.2.124:7080", remote: lan, forwarded: true, want: "HTTPS"},
		"http over loopback, lan host": {origin: "http://192.168.2.124:7080", host: "192.168.2.124:7080", remote: loopback, want: "HTTPS"},
		"loopback origin, lan remote":  {origin: "http://localhost:7080", host: "localhost:7080", remote: lan, want: "HTTPS"},
		"no origin":                    {host: "hub.lan:7443", remote: lan, tls: true, want: "cross-origin"},
		"null origin":                  {origin: "null", host: "hub.lan:7443", remote: lan, tls: true, want: "cross-origin"},
		"cross-origin https":           {origin: "https://evil.example", host: "hub.lan:7443", remote: lan, tls: true, want: "cross-origin"},
		"cross-origin, other port":     {origin: "https://hub.lan:9999", host: "hub.lan:7443", remote: lan, tls: true, want: "cross-origin"},
		"not a web origin":             {origin: "file://hub.lan:7443", host: "hub.lan:7443", remote: lan, tls: true, want: "cross-origin"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			r := httptest.NewRequest(http.MethodGet, "/api/v1/devices/dev-1/shell", nil)
			r.Host, r.RemoteAddr = tc.host, tc.remote
			if tc.origin != "" {
				r.Header.Set("Origin", tc.origin)
			}
			if tc.tls {
				r.TLS = &tls.ConnectionState{}
			}
			if tc.forwarded {
				r.Header.Set("X-Forwarded-Proto", "https")
				r.Header.Set("X-Forwarded-Host", tc.host)
			}
			err := shellTransport(r)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("shellTransport = %v, want allowed", err)
				}
				return
			}
			if !errors.Is(err, policy.ErrDenied) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("shellTransport = %v, want denied (%s)", err, tc.want)
			}
		})
	}
}

// noRequest fails if the agent got any request.
func (f *terminalFixture) noRequest(t *testing.T) {
	t.Helper()
	select {
	case req := <-f.got:
		t.Errorf("the agent got %v", req)
	case <-time.After(100 * time.Millisecond):
	}
}

// TestTerminalRefusedOverLANHTTP is a browser on http://<lan address>: the
// refusal comes before the upgrade and is audited as a denial.
func TestTerminalRefusedOverLANHTTP(t *testing.T) {
	t.Parallel()
	f := newTerminalFixture(t, false)
	r := httptest.NewRequest(http.MethodGet, "/api/v1/devices/dev-1/shell", nil)
	r.Host, r.RemoteAddr = "192.168.2.124:7080", "192.168.2.50:50000"
	r.Header.Set("Origin", "http://192.168.2.124:7080")
	r.AddCookie(f.cookie)
	w := httptest.NewRecorder()
	f.srv.Config.Handler.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status %d, want 403", w.Code)
	}
	e := waitShellAudit(t, f.st, 1)[0]
	if e.Decision != policy.Deny || e.Target != "dev-1" || !strings.Contains(e.Result, "HTTPS") {
		t.Errorf("entry = %+v, want a denial that says why", e)
	}
	f.noRequest(t)
}

// TestTerminalBehindTLSProxy is a TLS-terminating proxy: the hub sees plain
// HTTP from the proxy, the browser's Origin says https.
func TestTerminalBehindTLSProxy(t *testing.T) {
	t.Parallel()
	f := newTerminalFixture(t, false)
	ws, err := f.dial(t, strings.Replace(f.srv.URL, "http://", "https://", 1))
	if err != nil {
		t.Fatal(err)
	}
	if m, _ := next(t, ws); m.Type != "started" {
		t.Fatalf("first message = %+v, want started", m)
	}
}

// TestTerminalNeedsHTTP1 is a request whose connection cannot be taken over,
// as on HTTP/2: refused, not a panic.
func TestTerminalNeedsHTTP1(t *testing.T) {
	t.Parallel()
	f := newTerminalFixture(t, false)
	r := httptest.NewRequest(http.MethodGet, "/api/v1/devices/dev-1/shell", nil)
	r.Host, r.RemoteAddr = "localhost:7080", "127.0.0.1:50000"
	r.Header.Set("Origin", "http://localhost:7080")
	r.AddCookie(f.cookie)
	w := httptest.NewRecorder()
	f.srv.Config.Handler.ServeHTTP(w, r)
	if w.Code != http.StatusHTTPVersionNotSupported {
		t.Fatalf("status %d, want 505", w.Code)
	}
	f.noRequest(t)
}

// confirmTerminals holds every terminal for approval.
func confirmTerminals(c *Config) {
	c.Policy = policy.NewWithConfig(c.Store.Audit(), c.Store.Approvals(), policy.Config{
		Actors: map[string]map[policy.Class]policy.Mode{policy.ActorWeb: {policy.Dangerous: policy.ModeConfirm}},
	})
}

func TestTerminalHeldInputIsDiscarded(t *testing.T) {
	t.Parallel()
	f := newTerminalFixture(t, false, confirmTerminals)
	ws, err := f.dial(t, f.srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	m, _ := next(t, ws)
	if m.Type != "pending" {
		t.Fatalf("first message = %+v, want pending", m)
	}
	if err := shellCodec.Send(ws, shellFrame{binary: true, data: []byte("typed-while-held\r")}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	if err := f.api.policy.Decide(t.Context(), policy.ActorAdmin, "root", m.Approval, true, reauthed); err != nil {
		t.Fatal(err)
	}
	if m, _ := next(t, ws); m.Type != "started" {
		t.Fatalf("message = %+v, want started", m)
	}
	if err := shellCodec.Send(ws, shellFrame{binary: true, data: []byte("typed-after\r")}); err != nil {
		t.Fatal(err)
	}
	for req := range f.got {
		if in := req.GetInput(); in != nil {
			if string(in) != "typed-after\r" {
				t.Fatalf("first input = %q, want only what was typed after the start", in)
			}
			return
		}
	}
}

func TestTerminalHeldThenSignedOut(t *testing.T) {
	t.Parallel()
	f := newTerminalFixture(t, false, confirmTerminals)
	ws, err := f.dial(t, f.srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	m, _ := next(t, ws)
	if m.Type != "pending" {
		t.Fatalf("first message = %+v, want pending", m)
	}
	if resp := f.do(t, http.MethodPost, "/api/v1/logout", "", f.cookie); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("logout: status %d", resp.StatusCode)
	}
	if err := f.api.policy.Decide(t.Context(), policy.ActorAdmin, "root", m.Approval, true, reauthed); err != nil {
		t.Fatal(err)
	}
	if m, _ := next(t, ws); m.Type != "error" || m.Code != "forbidden" {
		t.Fatalf("message = %+v, want forbidden", m)
	}
	f.noRequest(t)
}

// TestTerminalHeldThenBrowserLeaves withdraws the request: approving it
// later starts no shell for nobody.
func TestTerminalHeldThenBrowserLeaves(t *testing.T) {
	t.Parallel()
	f := newTerminalFixture(t, false, confirmTerminals)
	ws, err := f.dial(t, f.srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	m, _ := next(t, ws)
	if m.Type != "pending" {
		t.Fatalf("first message = %+v, want pending", m)
	}
	_ = ws.Close()
	for range 500 {
		ap, err := f.st.Approvals().Get(t.Context(), m.Approval)
		if err != nil {
			t.Fatal(err)
		}
		if ap.Status != store.ApprovalPending {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := f.api.policy.Decide(t.Context(), policy.ActorAdmin, "root", m.Approval, true, reauthed); !errors.Is(err, store.ErrApprovalClosed) {
		t.Fatalf("approving a withdrawn request = %v, want it closed", err)
	}
	f.noRequest(t)
}

// switchAudit fails every append once failing is set.
type switchAudit struct {
	policy.Auditor
	failing atomic.Bool
}

func (a *switchAudit) Append(ctx context.Context, e store.AuditEntry) (int64, error) {
	if a.failing.Load() {
		return 0, errors.New("the audit log is unavailable")
	}
	return a.Auditor.Append(ctx, e)
}

// TestTerminalUnauditedShellIsClosed is the audit log failing after the shell
// started: a shell without an audit entry does not stay.
func TestTerminalUnauditedShellIsClosed(t *testing.T) {
	t.Parallel()
	audit := &switchAudit{}
	f := newTerminalFixture(t, false, func(c *Config) {
		audit.Auditor = c.Store.Audit()
		c.Policy = policy.New(audit)
	})
	audit.failing.Store(true)
	ws, err := f.dial(t, f.srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if m, _ := next(t, ws); m.Type != "error" {
		t.Fatalf("message = %+v, want an error", m)
	}
	if req := <-f.got; req.GetOpen() == nil {
		t.Fatalf("first request = %v, want open", req)
	}
	select {
	case req := <-f.got:
		if req.GetClose() == nil {
			t.Fatalf("request = %v, want close", req)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the unaudited shell was left running")
	}
}

// TestTerminalIdleCountsOnlyInput keeps a session busy with everything a
// browser sends on its own: it still ends at the idle timeout.
func TestTerminalIdleCountsOnlyInput(t *testing.T) {
	t.Parallel()
	f := newTerminalFixture(t, false, func(c *Config) { c.ShellIdleTimeout = 400 * time.Millisecond })
	ws, err := f.dial(t, f.srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if m, _ := next(t, ws); m.Type != "started" {
		t.Fatalf("first message = %+v, want started", m)
	}
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		tick := time.NewTicker(40 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-stop:
				return
			case <-tick.C:
				_ = shellCodec.Send(ws, shellFrame{data: []byte(`{"type":"resize","rows":40,"cols":120}`)})
				_ = shellCodec.Send(ws, shellFrame{data: []byte(`{"type":"reply","data":"\u001b[1;1R"}`)})
			}
		}
	}()
	for {
		m, out := next(t, ws)
		if out != nil {
			if string(out) != "echo:\x1b[1;1R" {
				t.Fatalf("output = %q, want the reply delivered to the shell", out)
			}
			continue
		}
		if m.Type != "exit" || m.Reason != "idle timeout" {
			t.Fatalf("message = %+v, want exit on idle timeout", m)
		}
		return
	}
}

func TestTerminalTypingKeepsSessionAlive(t *testing.T) {
	t.Parallel()
	const idle = 400 * time.Millisecond
	f := newTerminalFixture(t, false, func(c *Config) { c.ShellIdleTimeout = idle })
	ws, err := f.dial(t, f.srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if m, _ := next(t, ws); m.Type != "started" {
		t.Fatalf("first message = %+v, want started", m)
	}
	for start := time.Now(); time.Since(start) < 2*idle; {
		if err := shellCodec.Send(ws, shellFrame{binary: true, data: []byte("x")}); err != nil {
			t.Fatal(err)
		}
		if m, out := next(t, ws); out == nil {
			t.Fatalf("message = %+v while typing, want output", m)
		}
		time.Sleep(idle / 8)
	}
}

func TestOpenShellNeedsPolicyGrant(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	st := newTestStore(t)
	enrollDevice(t, st, "dev-1")
	client, agents := newExecClient(t, st)
	stream := connectAgent(ctx, t, client, minShellMinor, &agentv1.Ceiling{Shell: true})
	got := fakeShellAgent(stream, false)
	if _, err := openShellUntilAttached(grantShell(ctx, t, st), t, agents); err != nil {
		t.Fatal(err)
	}
	<-got // the granted open
	if _, err := agents.OpenShell(ctx, "dev-1", 24, 80); !errors.Is(err, policy.ErrDenied) {
		t.Fatalf("OpenShell without a grant = %v, want denied", err)
	}
	select {
	case req := <-got:
		t.Errorf("a shell outside policy reached the agent: %v", req)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestOpenShellCapsSessionsPerDevice(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	st := newTestStore(t)
	enrollDevice(t, st, "dev-1")
	client, agents := newExecClient(t, st)
	stream := connectAgent(ctx, t, client, minShellMinor, &agentv1.Ceiling{Shell: true})
	fakeShellAgent(stream, false)
	granted := grantShell(ctx, t, st)
	var first *Shell
	for i := range maxDeviceShells {
		sh, err := openShellUntilAttached(granted, t, agents)
		if err != nil {
			t.Fatalf("shell %d: %v", i, err)
		}
		if first == nil {
			first = sh
		}
	}
	if _, err := agents.OpenShell(granted, "dev-1", 24, 80); err == nil || !strings.Contains(err.Error(), "terminals open") {
		t.Fatalf("one shell over the cap = %v, want refused", err)
	}
	// An ended session makes room.
	first.Close()
	for first.Exit() == nil {
		if _, err := first.Read(ctx); err != nil {
			break
		}
	}
	if _, err := agents.OpenShell(granted, "dev-1", 24, 80); err != nil {
		t.Fatalf("after one ended: %v", err)
	}
}

// stalledAgent answers the open of a shell, then never reads its stream again.
func stalledAgent(stream *connect.BidiStreamForClient[agentv1.AgentMessage, agentv1.HubMessage]) <-chan *agentv1.ShellRequest {
	got := make(chan *agentv1.ShellRequest, 1)
	go func() {
		msg, err := stream.Receive()
		if err != nil {
			return
		}
		got <- msg.GetShellRequest()
		_ = stream.Send(&agentv1.AgentMessage{Payload: &agentv1.AgentMessage_ShellEvent{ShellEvent: &agentv1.ShellEvent{
			Id: msg.GetShellRequest().GetId(), Event: &agentv1.ShellEvent_Started{Started: &agentv1.ShellStarted{Shell: "/bin/fake"}},
		}}})
	}()
	return got
}

// shellEndBound is how soon after a limit fires a stalled session must be over.
const shellEndBound = 5 * time.Second

// waitForced checks a session ended force-closed, audited, with the stream gone.
func (f *terminalFixture) waitForced(t *testing.T, why string) {
	t.Helper()
	e := waitShellAudit(t, f.st, 2)[1]
	if !strings.Contains(e.Result, "ended: "+why) || !strings.Contains(e.Result, "force-closed") ||
		!strings.Contains(string(e.Detail), `"forced":true`) {
		t.Errorf("end entry = %q %s, want it force-closed", e.Result, e.Detail)
	}
	for range 500 {
		if errors.Is(f.agents.CheckShell(t.Context(), "dev-1"), ErrAgentNotConnected) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Error("the stalled stream was not torn down")
}

// TestTerminalLimitsEndStalledSession is the limits of a session whose agent
// stopped reading its stream, with the send window open and with it full.
func TestTerminalLimitsEndStalledSession(t *testing.T) {
	t.Parallel()
	const limit = 300 * time.Millisecond
	for name, tc := range map[string]struct {
		window  int
		flood   bool
		signOut bool
		// detect is how long the hub may take to notice the limit.
		detect time.Duration
		opts   func(*Config)
		why    string
	}{
		"idle, window open":  {detect: limit, opts: func(c *Config) { c.ShellIdleTimeout = limit }, why: "idle timeout"},
		"max duration, full": {window: 64 << 10, flood: true, detect: limit, opts: func(c *Config) { c.ShellMaxDuration = limit }, why: "maximum session duration reached"},
		"sign-out, full": {
			window: 64 << 10, flood: true, signOut: true, detect: time.Second,
			opts: func(c *Config) { c.ShellIdleTimeout = 4 * time.Second }, why: "signed out", // checked every second
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := newTerminalFixtureWith(t, tc.window, stalledAgent, tc.opts)
			ws, err := f.dial(t, f.srv.URL)
			if err != nil {
				t.Fatal(err)
			}
			if m, _ := next(t, ws); m.Type != "started" {
				t.Fatalf("first message = %+v, want started", m)
			}
			var accepted atomic.Int64
			if tc.flood {
				go func() {
					frame := shellFrame{binary: true, data: make([]byte, 32<<10)}
					for {
						_ = ws.SetWriteDeadline(time.Now().Add(10 * time.Second))
						if shellCodec.Send(ws, frame) != nil {
							return
						}
						accepted.Add(int64(len(frame.data)))
					}
				}()
				time.Sleep(500 * time.Millisecond) // the window fills
			}
			fired := time.Now()
			if tc.signOut {
				if resp := f.do(t, http.MethodPost, "/api/v1/logout", "", f.cookie); resp.StatusCode != http.StatusNoContent {
					t.Fatalf("logout: status %d", resp.StatusCode)
				}
			}
			// The browser is told, or at least disconnected, within the bound.
			_ = ws.SetReadDeadline(time.Now().Add(limit + shellEndBound + 10*time.Second))
			for {
				var fr shellFrame
				if shellCodec.Receive(ws, &fr) != nil {
					break
				}
			}
			if d := time.Since(fired); d > tc.detect+shellEndBound {
				t.Errorf("the browser was released %s after the limit, want within %s", d, tc.detect+shellEndBound)
			}
			f.waitForced(t, tc.why)
			if n := accepted.Load(); n > 32<<20 {
				t.Errorf("the hub took %d bytes of input for an agent that does not read", n)
			}
		})
	}
}

// TestShellCloseDoesNotBlockOnStalledStream fills the stream of an agent that
// stopped reading: Close returns, and the session ends, within their bounds.
func TestShellCloseDoesNotBlockOnStalledStream(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	st := newTestStore(t)
	enrollDevice(t, st, "dev-1")
	client, agents := newExecClientWindow(t, st, 64<<10)
	stream := connectAgent(ctx, t, client, minShellMinor, &agentv1.Ceiling{Shell: true})
	stalledAgent(stream)
	sh, err := openShellUntilAttached(grantShell(ctx, t, st), t, agents)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		b := make([]byte, 32<<10)
		for sh.Write(b) == nil {
		}
	}()
	time.Sleep(300 * time.Millisecond) // the window fills
	start := time.Now()
	sh.Close()
	if d := time.Since(start); d > shellSendTimeout+time.Second {
		t.Errorf("Close took %s", d)
	}
	for {
		if _, err := sh.Read(ctx); err != nil {
			break
		}
	}
	if d := time.Since(start); d > shellEndBound {
		t.Errorf("the session ended %s after Close", d)
	}
	if !sh.Unconfirmed() {
		t.Errorf("exit = %v, want it unconfirmed", sh.Exit())
	}
}
