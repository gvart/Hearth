// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"golang.org/x/net/websocket"

	"github.com/gvart/hearth/internal/policy"
	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
	"github.com/gvart/hearth/internal/proto/hearth/agent/v1/agentv1connect"
	"github.com/gvart/hearth/internal/store"
)

// fakeShellAgent answers shell requests on stream as an agent would: it
// starts a "shell" that echoes its input, or, with deny, refuses as an
// agent without --allow-shell does. Every request it gets goes to the
// returned channel.
func fakeShellAgent(stream *connect.BidiStreamForClient[agentv1.AgentMessage, agentv1.HubMessage], deny bool) <-chan *agentv1.ShellRequest {
	got := make(chan *agentv1.ShellRequest, 64)
	event := func(ev *agentv1.ShellEvent) {
		_ = stream.Send(&agentv1.AgentMessage{Payload: &agentv1.AgentMessage_ShellEvent{ShellEvent: ev}})
	}
	go func() {
		for {
			msg, err := stream.Receive()
			if err != nil {
				close(got)
				return
			}
			req := msg.GetShellRequest()
			if req == nil {
				continue
			}
			got <- req
			id := req.GetId()
			switch op := req.GetOp().(type) {
			case *agentv1.ShellRequest_Open:
				if deny {
					event(&agentv1.ShellEvent{Id: id, Event: &agentv1.ShellEvent_Exited{Exited: &agentv1.ShellExited{
						Denied: true, ExitCode: -1, Error: "shell: " + policy.ErrBeyondCeiling.Error(),
					}}})
					continue
				}
				event(&agentv1.ShellEvent{Id: id, Event: &agentv1.ShellEvent_Started{Started: &agentv1.ShellStarted{Shell: "/bin/fake"}}})
			case *agentv1.ShellRequest_Input:
				event(&agentv1.ShellEvent{Id: id, Event: &agentv1.ShellEvent_Output{Output: append([]byte("echo:"), op.Input...)}})
			case *agentv1.ShellRequest_Close:
				event(&agentv1.ShellEvent{Id: id, Event: &agentv1.ShellEvent_Exited{Exited: &agentv1.ShellExited{ExitCode: -1}}})
			}
		}
	}()
	return got
}

// grantShell is ctx with policy's grant of device.shell, as Do gives it.
func grantShell(ctx context.Context, t *testing.T, st *store.Store) context.Context {
	t.Helper()
	var granted context.Context
	err := policy.New(st.Audit()).Do(ctx, policy.Request{
		ActorKind: policy.ActorWeb, ActorID: "test", Action: policy.DeviceShell, Target: "dev-1",
	}, func(c context.Context) error {
		granted = c //nolint:fatcontext // the grant is what the test needs
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return granted
}

// openShellUntilAttached retries OpenShell while the session is not attached yet.
func openShellUntilAttached(ctx context.Context, t *testing.T, agents *Agents) (*Shell, error) {
	t.Helper()
	var sh *Shell
	var err error
	for range 100 {
		if sh, err = agents.OpenShell(ctx, "dev-1", 24, 80); !errors.Is(err, ErrAgentNotConnected) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	return sh, err
}

func TestAgentsShell(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	st := newTestStore(t)
	enrollDevice(t, st, "dev-1")
	client, agents := newExecClient(t, st)
	stream := connectAgent(ctx, t, client, minShellMinor, &agentv1.Ceiling{Shell: true})
	got := fakeShellAgent(stream, false)

	sh, err := openShellUntilAttached(grantShell(ctx, t, st), t, agents)
	if err != nil || sh.Path() != "/bin/fake" {
		t.Fatalf("OpenShell = %v, %v; want the started shell", sh, err)
	}
	if req := <-got; req.GetOpen().GetSize().GetCols() != 80 {
		t.Errorf("open = %v, want 80 columns", req)
	}
	if err := sh.Write([]byte("ls\n")); err != nil {
		t.Fatal(err)
	}
	out, err := sh.Read(ctx)
	if err != nil || string(out) != "echo:ls\n" {
		t.Fatalf("Read = %q, %v", out, err)
	}
	<-got                                               // the input
	if req := <-got; req.GetAck() != uint32(len(out)) { //nolint:gosec // a few bytes
		t.Errorf("after Read the agent got %v, want an ack of %d bytes", req, len(out))
	}
	sh.Close()
	if req := <-got; req.GetClose() == nil {
		t.Errorf("after Close the agent got %v, want close", req)
	}
	if _, err := sh.Read(ctx); err == nil || sh.Exit() == nil {
		t.Fatalf("Read after the end = %v (exit %v), want EOF", err, sh.Exit())
	}
}

// TestAgentsShellRefusedByAgent is the agent's own ceiling at work: the hub
// believes shells are allowed (here, a ceiling that says so), the agent
// refuses, and OpenShell fails beyond the ceiling.
func TestAgentsShellRefusedByAgent(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	st := newTestStore(t)
	enrollDevice(t, st, "dev-1")
	client, agents := newExecClient(t, st)
	stream := connectAgent(ctx, t, client, minShellMinor, &agentv1.Ceiling{Shell: true})
	fakeShellAgent(stream, true)

	if _, err := openShellUntilAttached(grantShell(ctx, t, st), t, agents); !errors.Is(err, policy.ErrBeyondCeiling) ||
		!strings.Contains(err.Error(), "agent refused") {
		t.Fatalf("OpenShell = %v, want the agent's refusal, beyond the ceiling", err)
	}
}

func TestAgentsShellNeverBeyondCeiling(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		minor   uint32
		ceiling *agentv1.Ceiling
		want    string
	}{
		"old agent":         {minor: minShellMinor - 1, ceiling: &agentv1.Ceiling{Shell: true}, want: "too old"},
		"shell not allowed": {minor: minShellMinor, ceiling: &agentv1.Ceiling{Exec: []string{"/bin/sh"}, Probe: true}, want: "turn Terminal on"},
		"no ceiling":        {minor: minShellMinor, want: "turn Terminal on"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			st := newTestStore(t)
			enrollDevice(t, st, "dev-1")
			client, agents := newExecClient(t, st)
			stream := connectAgent(ctx, t, client, tc.minor, tc.ceiling)
			got := fakeShellAgent(stream, false)
			_, err := openShellUntilAttached(grantShell(ctx, t, st), t, agents)
			if !errors.Is(err, policy.ErrBeyondCeiling) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("OpenShell = %v, want beyond the ceiling (%s)", err, tc.want)
			}
			if err := agents.CheckShell(ctx, "dev-1"); !errors.Is(err, policy.ErrBeyondCeiling) {
				t.Errorf("CheckShell = %v, want beyond the ceiling", err)
			}
			select {
			case req := <-got:
				t.Errorf("a shell beyond the ceiling reached the agent: %v", req)
			case <-time.After(50 * time.Millisecond):
			}
		})
	}
}

// terminalFixture is the web API with a fake agent of dev-1 that allows
// shells (or refuses them, with deny).
type terminalFixture struct {
	*apiFixture
	agents *Agents
	cookie *http.Cookie
	got    <-chan *agentv1.ShellRequest
}

func newTerminalFixture(t *testing.T, deny bool, opts ...func(*Config)) *terminalFixture {
	t.Helper()
	return newTerminalFixtureWith(t, 0, func(stream *connect.BidiStreamForClient[agentv1.AgentMessage, agentv1.HubMessage]) <-chan *agentv1.ShellRequest {
		return fakeShellAgent(stream, deny)
	}, opts...)
}

// newTerminalFixtureWith is newTerminalFixture with agent answering on the
// stream, whose client takes at most window unread bytes (0: the default).
func newTerminalFixtureWith(t *testing.T, window int,
	agent func(*connect.BidiStreamForClient[agentv1.AgentMessage, agentv1.HubMessage]) <-chan *agentv1.ShellRequest,
	opts ...func(*Config),
) *terminalFixture {
	t.Helper()
	var agents *Agents
	var stream *connect.BidiStreamForClient[agentv1.AgentMessage, agentv1.HubMessage]
	f := newAPIFixture(t, true, append([]func(*Config){func(c *Config) {
		enrollDevice(t, c.Store, "dev-1")
		var client agentv1connect.AgentServiceClient
		client, agents = newExecClientWindow(t, c.Store, window)
		c.Agents = agents
		stream = connectAgent(t.Context(), t, client, minShellMinor, &agentv1.Ceiling{Shell: true})
	}}, opts...)...)
	got := agent(stream)
	for range 100 {
		if err := agents.CheckShell(t.Context(), "dev-1"); !errors.Is(err, ErrAgentNotConnected) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	return &terminalFixture{apiFixture: f, agents: agents, cookie: sessionCookie(t, f.login(t, testPassword)), got: got}
}

// dial opens the terminal WebSocket of dev-1 from origin.
func (f *terminalFixture) dial(t *testing.T, origin string) (*websocket.Conn, error) {
	t.Helper()
	cfg, err := websocket.NewConfig(strings.Replace(f.srv.URL, "http", "ws", 1)+"/api/v1/devices/dev-1/shell?rows=30&cols=100", origin)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Header = http.Header{"Cookie": {f.cookie.String()}}
	ws, err := websocket.DialConfig(cfg)
	if err == nil {
		t.Cleanup(func() { _ = ws.Close() })
	}
	return ws, err
}

// next reads the next message: JSON text, or binary output.
func next(t *testing.T, ws *websocket.Conn) (ShellMessageJSON, []byte) {
	t.Helper()
	_ = ws.SetReadDeadline(time.Now().Add(5 * time.Second))
	var fr shellFrame
	if err := shellCodec.Receive(ws, &fr); err != nil {
		t.Fatalf("receive: %v", err)
	}
	if fr.binary {
		return ShellMessageJSON{}, fr.data
	}
	var m ShellMessageJSON
	if err := json.Unmarshal(fr.data, &m); err != nil {
		t.Fatalf("decode %q: %v", fr.data, err)
	}
	return m, nil
}

// shellAudit is the device.shell entries, oldest first.
func shellAudit(t *testing.T, st *store.Store) []store.AuditEntry {
	t.Helper()
	all, err := st.Audit().List(t.Context(), 100)
	if err != nil {
		t.Fatal(err)
	}
	var out []store.AuditEntry
	for _, e := range all {
		if e.Action == string(policy.DeviceShell) {
			out = append(out, e)
		}
	}
	if len(out) > 1 && out[0].ID > out[1].ID {
		for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
			out[i], out[j] = out[j], out[i]
		}
	}
	return out
}

func waitShellAudit(t *testing.T, st *store.Store, n int) []store.AuditEntry {
	t.Helper()
	for range 200 {
		if got := shellAudit(t, st); len(got) >= n {
			return got
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("want %d device.shell audit entries, have %v", n, shellAudit(t, st))
	return nil
}

func TestTerminalSession(t *testing.T) {
	t.Parallel()
	f := newTerminalFixture(t, false)
	ws, err := f.dial(t, f.srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if m, _ := next(t, ws); m.Type != "started" || m.Shell != "/bin/fake" || m.IdleTimeout != int(DefaultShellIdleTimeout/time.Second) {
		t.Fatalf("first message = %+v, want started", m)
	}
	if req := <-f.got; req.GetOpen().GetSize().GetRows() != 30 || req.GetOpen().GetSize().GetCols() != 100 {
		t.Errorf("open = %v, want 30x100", req)
	}
	if err := shellCodec.Send(ws, shellFrame{binary: true, data: []byte("uname -a\r")}); err != nil {
		t.Fatal(err)
	}
	if _, out := next(t, ws); string(out) != "echo:uname -a\r" {
		t.Fatalf("output = %q", out)
	}
	if err := shellCodec.Send(ws, shellFrame{data: []byte(`{"type":"resize","rows":40,"cols":120}`)}); err != nil {
		t.Fatal(err)
	}
	for req := range f.got {
		if r := req.GetResize(); r != nil {
			if r.GetRows() != 40 || r.GetCols() != 120 {
				t.Errorf("resize = %v", r)
			}
			break
		}
	}

	// Closing the tab closes the socket: the hub ends the session.
	_ = ws.Close()
	for req := range f.got {
		if req.GetClose() != nil {
			break
		}
	}
	entries := waitShellAudit(t, f.st, 2)
	start, end := entries[0], entries[1]
	if start.Decision != policy.Allow || start.Result != "ok" || start.ActorKind != policy.ActorWeb ||
		start.Target != "dev-1" || !strings.Contains(string(start.Detail), `"shell":"/bin/fake"`) {
		t.Errorf("start entry = %+v", start)
	}
	if !strings.HasPrefix(end.Result, "ended: terminal closed") || !strings.Contains(string(end.Detail), `"duration_s"`) ||
		!strings.Contains(string(end.Detail), `"exit_code":-1`) {
		t.Errorf("end entry = %+v %s", end, end.Detail)
	}
	var startDetail, endDetail struct{ Session string }
	_ = json.Unmarshal(start.Detail, &startDetail)
	_ = json.Unmarshal(end.Detail, &endDetail)
	if startDetail.Session == "" || startDetail.Session != endDetail.Session {
		t.Errorf("start and end entries name sessions %q and %q, want the same", startDetail.Session, endDetail.Session)
	}
	// Never the contents.
	for _, e := range entries {
		if strings.Contains(string(e.Detail)+e.Result, "uname") {
			t.Errorf("audit entry carries terminal contents: %+v", e)
		}
	}
	if strings.Contains(f.logs.String(), "uname") {
		t.Error("hub log carries terminal contents")
	}
}

func TestTerminalIdleTimeout(t *testing.T) {
	t.Parallel()
	f := newTerminalFixture(t, false, func(c *Config) { c.ShellIdleTimeout = 200 * time.Millisecond })
	ws, err := f.dial(t, f.srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if m, _ := next(t, ws); m.Type != "started" {
		t.Fatalf("first message = %+v, want started", m)
	}
	m, _ := next(t, ws)
	if m.Type != "exit" || m.Reason != "idle timeout" {
		t.Fatalf("message = %+v, want exit on idle timeout", m)
	}
	if e := waitShellAudit(t, f.st, 2)[1]; !strings.HasPrefix(e.Result, "ended: idle timeout") {
		t.Errorf("end entry = %+v", e)
	}
}

// TestTerminalEndsWithAdminSession signs out while a terminal is open: the
// terminal needs an admin session for as long as it runs.
func TestTerminalEndsWithAdminSession(t *testing.T) {
	t.Parallel()
	f := newTerminalFixture(t, false, func(c *Config) { c.ShellIdleTimeout = 2 * time.Second })
	ws, err := f.dial(t, f.srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if m, _ := next(t, ws); m.Type != "started" {
		t.Fatalf("first message = %+v, want started", m)
	}
	if resp := f.do(t, http.MethodPost, "/api/v1/logout", "", f.cookie); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("logout: status %d", resp.StatusCode)
	}
	if m, _ := next(t, ws); m.Type != "exit" || m.Reason != "signed out" {
		t.Fatalf("message = %+v, want exit on sign-out", m)
	}
}

func TestTerminalRefused(t *testing.T) {
	t.Parallel()
	t.Run("cross origin", func(t *testing.T) {
		t.Parallel()
		f := newTerminalFixture(t, false)
		if _, err := f.dial(t, "http://evil.example"); err == nil {
			t.Fatal("a cross-origin terminal opened")
		}
		resp := f.do(t, http.MethodGet, "/api/v1/devices/dev-1/shell", "", f.cookie)
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("no Origin: status %d, want 403", resp.StatusCode)
		}
		select {
		case req := <-f.got:
			t.Errorf("the agent got %v", req)
		case <-time.After(50 * time.Millisecond):
		}
	})
	t.Run("not logged in", func(t *testing.T) {
		t.Parallel()
		f := newTerminalFixture(t, false)
		f.cookie = testCookie("nope")
		if _, err := f.dial(t, f.srv.URL); err == nil {
			t.Fatal("a terminal opened without a session")
		}
	})
	t.Run("denied by policy", func(t *testing.T) {
		t.Parallel()
		f := newTerminalFixture(t, false, func(c *Config) {
			c.Policy = policy.NewWithConfig(c.Store.Audit(), nil, policy.Config{
				Actors: map[string]map[policy.Class]policy.Mode{policy.ActorWeb: {policy.Dangerous: policy.ModeDeny}},
			})
		})
		ws, err := f.dial(t, f.srv.URL)
		if err != nil {
			t.Fatal(err)
		}
		if m, _ := next(t, ws); m.Type != "error" || m.Code != "forbidden" {
			t.Fatalf("message = %+v, want forbidden", m)
		}
		if e := waitShellAudit(t, f.st, 1); e[0].Decision != policy.Deny {
			t.Errorf("entry = %+v, want deny", e[0])
		}
		select {
		case req := <-f.got:
			t.Errorf("the agent got %v", req)
		case <-time.After(50 * time.Millisecond):
		}
	})
	t.Run("refused by the agent", func(t *testing.T) {
		t.Parallel()
		f := newTerminalFixture(t, true)
		ws, err := f.dial(t, f.srv.URL)
		if err != nil {
			t.Fatal(err)
		}
		if m, _ := next(t, ws); m.Type != "error" || m.Code != "forbidden" || !strings.Contains(m.Reason, "agent refused") {
			t.Fatalf("message = %+v, want the agent's refusal", m)
		}
	})
}
