// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/gvart/hearth/internal/policy"
	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
	"github.com/gvart/hearth/internal/proto/hearth/agent/v1/agentv1connect"
)

// fakeLogAgent answers each LogRequest on stream with lines, then end if
// set, and reports the requests and cancels it gets.
func fakeLogAgent(stream *connect.BidiStreamForClient[agentv1.AgentMessage, agentv1.HubMessage], end string,
) (reqs <-chan *agentv1.LogRequest, cancels <-chan string) {
	rq := make(chan *agentv1.LogRequest, 8)
	cn := make(chan string, 8)
	go func() {
		for {
			msg, err := stream.Receive()
			if err != nil {
				return
			}
			if c := msg.GetLogCancel(); c != nil {
				cn <- c.GetId()
				continue
			}
			req := msg.GetLogRequest()
			if req == nil {
				continue
			}
			rq <- req
			ll := &agentv1.LogLines{Id: req.GetId(), Lines: []*agentv1.LogLine{{Text: "hello from " + req.GetSource().GetName()}}}
			_ = stream.Send(&agentv1.AgentMessage{Payload: &agentv1.AgentMessage_LogLines{LogLines: ll}})
			if end != "" {
				_ = stream.Send(&agentv1.AgentMessage{Payload: &agentv1.AgentMessage_LogLines{LogLines: &agentv1.LogLines{
					Id: req.GetId(), End: true, Error: end,
				}}})
			}
		}
	}()
	return rq, cn
}

// logsFixture serves the web API with the Agents of an agent stream for
// dev-1, and a logged-in session.
type logsFixture struct {
	srv    *httptest.Server
	client agentv1connect.AgentServiceClient
	audit  func() []string
}

func newLogsFixture(t *testing.T) *logsFixture {
	t.Helper()
	st := newTestStore(t)
	enrollDevice(t, st, "dev-1")
	client, agents := newExecClient(t, st)
	log := slog.New(slog.DiscardHandler)
	a := newAPI(Config{Store: st, Policy: policy.New(st.Audit()), Log: log, Agents: agents})
	srv := httptest.NewServer(a.routes())
	t.Cleanup(srv.Close)
	if err := st.Admin().CreateSession(t.Context(), "logs-session", time.Now(), time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	return &logsFixture{srv: srv, client: client, audit: func() []string {
		es, err := st.Audit().List(t.Context(), 100)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, e := range es {
			if e.Action == string(policy.DeviceLogs) {
				out = append(out, e.Decision+" "+e.Target+" "+string(e.Detail))
			}
		}
		return out
	}}
}

// open GETs the log stream of source. The response body is closed when ctx
// is done.
func (f *logsFixture) open(ctx context.Context, t *testing.T, source string) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.srv.URL+"/api/v1/devices/dev-1/logs?source="+source, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(testCookie("logs-session"))
	resp, err := f.srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

// logEvents parses the server-sent events of a log stream.
func logEvents(body io.Reader) <-chan [2]string {
	ch := make(chan [2]string, 16)
	go func() {
		defer close(ch)
		sc := bufio.NewScanner(body)
		var name string
		for sc.Scan() {
			line := sc.Text()
			if s, ok := strings.CutPrefix(line, "event: "); ok {
				name = s
			} else if s, ok := strings.CutPrefix(line, "data: "); ok {
				ch <- [2]string{name, s}
			}
		}
	}()
	return ch
}

func nextEvent(t *testing.T, ch <-chan [2]string) (name, data string) {
	t.Helper()
	select {
	case e, ok := <-ch:
		if !ok {
			t.Fatal("log stream closed")
		}
		return e[0], e[1]
	case <-time.After(5 * time.Second):
		t.Fatal("no log event")
	}
	return "", ""
}

func TestDeviceLogsStream(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	f := newLogsFixture(t)
	stream := connectAgent(ctx, t, f.client, minLogsMinor, &agentv1.Ceiling{Logs: []string{"systemd:*"}})
	reqs, cancels := fakeLogAgent(stream, "")

	var resp *http.Response
	for range 100 { // until the session is attached
		resp = f.open(ctx, t, "systemd:nginx.service")
		if resp.StatusCode != http.StatusConflict {
			break
		}
		_ = resp.Body.Close()
		time.Sleep(10 * time.Millisecond)
	}
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatalf("open = %d %s, want an event stream", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	req := <-reqs
	if req.GetSource().GetManager() != "systemd" || req.GetSource().GetName() != "nginx.service" || req.GetTail() != defaultLogTail {
		t.Errorf("agent got %v", req)
	}
	name, data := nextEvent(t, logEvents(resp.Body))
	var lines LogLinesJSON
	if err := json.Unmarshal([]byte(data), &lines); err != nil || name != "lines" || len(lines.Lines) != 1 ||
		lines.Lines[0].Text != "hello from nginx.service" {
		t.Fatalf("event %s %s, want the agent's line", name, data)
	}
	if got := f.audit(); len(got) != 1 || !strings.HasPrefix(got[0], "allow dev-1 ") || !strings.Contains(got[0], "systemd:nginx.service") {
		t.Errorf("audit = %q, want one allowed device.logs entry", got)
	}

	// The client going away cancels the stream on the agent.
	_ = resp.Body.Close()
	select {
	case id := <-cancels:
		if id != req.GetId() {
			t.Errorf("cancel of %s, want %s", id, req.GetId())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("agent got no LogCancel after the client went away")
	}
	if got := f.audit(); len(got) != 1 {
		t.Errorf("audit = %q, want still one entry", got)
	}
}

func TestDeviceLogsEnd(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	f := newLogsFixture(t)
	stream := connectAgent(ctx, t, f.client, minLogsMinor, &agentv1.Ceiling{Logs: []string{"docker:web"}})
	_, cancels := fakeLogAgent(stream, "docker exited: No such container: web")
	var resp *http.Response
	for range 100 {
		resp = f.open(ctx, t, "docker:web")
		if resp.StatusCode != http.StatusConflict {
			break
		}
		_ = resp.Body.Close()
		time.Sleep(10 * time.Millisecond)
	}
	events := logEvents(resp.Body)
	if name, _ := nextEvent(t, events); name != "lines" {
		t.Fatalf("first event %s, want lines", name)
	}
	name, data := nextEvent(t, events)
	if name != "end" || !strings.Contains(data, "No such container") {
		t.Errorf("event %s %s, want the end with the agent's error", name, data)
	}
	select {
	case id := <-cancels:
		t.Errorf("cancel %s sent for a stream the agent ended", id)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestDeviceLogsRefused(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		minor   uint32
		ceiling *agentv1.Ceiling
		source  string
		status  int
		want    string
	}{
		{"agent too old", minLogsMinor - 1, &agentv1.Ceiling{Logs: []string{"systemd:*"}}, "systemd:a.service", http.StatusForbidden, "too old"},
		{"beyond the ceiling", minLogsMinor, &agentv1.Ceiling{Logs: []string{"systemd:a.service"}}, "systemd:b.service", http.StatusForbidden, "--allow-logs"},
		{"wrong manager", minLogsMinor, &agentv1.Ceiling{Logs: []string{"systemd:*"}}, "docker:a", http.StatusForbidden, "capability ceiling"},
		{"no ceiling", minLogsMinor, nil, "systemd:a.service", http.StatusForbidden, "capability ceiling"},
		{"bad source", minLogsMinor, nil, "nginx", http.StatusBadRequest, "manager:name"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()
			f := newLogsFixture(t)
			stream := connectAgent(ctx, t, f.client, tc.minor, tc.ceiling)
			reqs, _ := fakeLogAgent(stream, "")
			var resp *http.Response
			for range 100 {
				resp = f.open(ctx, t, tc.source)
				if resp.StatusCode != http.StatusConflict {
					break
				}
				_ = resp.Body.Close()
				time.Sleep(10 * time.Millisecond)
			}
			body, _ := io.ReadAll(resp.Body)
			if resp.StatusCode != tc.status || !strings.Contains(string(body), tc.want) {
				t.Errorf("open = %d %s, want %d with %q", resp.StatusCode, body, tc.status, tc.want)
			}
			select {
			case r := <-reqs:
				t.Errorf("agent got %v for a refused stream", r)
			default:
			}
			if tc.status == http.StatusForbidden {
				if got := f.audit(); len(got) != 1 || !strings.HasPrefix(got[0], "deny ") {
					t.Errorf("audit = %q, want one denial", got)
				}
			}
		})
	}
}

// TestDeliverLogsSlowReader: a reader that falls logBuffer messages behind
// loses its stream, and the agent is told to stop it, without blocking the
// agent's stream.
func TestDeliverLogsSlowReader(t *testing.T) {
	t.Parallel()
	var sent []*agentv1.HubMessage
	s := &agentSession{done: make(chan struct{}), logs: map[string]chan *agentv1.LogLines{}, send: func(m *agentv1.HubMessage) error {
		sent = append(sent, m)
		return nil
	}}
	ch := make(chan *agentv1.LogLines, logBuffer)
	s.logs["x"] = ch
	for range logBuffer + 5 {
		s.deliverLogs(&agentv1.LogLines{Id: "x", Lines: []*agentv1.LogLine{{Text: "a"}}})
	}
	if len(sent) != 1 || sent[0].GetLogCancel().GetId() != "x" {
		t.Fatalf("sent %v, want one LogCancel", sent)
	}
	n := 0
	for range ch {
		n++
	}
	if n != logBuffer {
		t.Errorf("reader got %d messages, then the closed channel; want %d", n, logBuffer)
	}
	if _, open := s.logs["x"]; open {
		t.Error("stream still registered")
	}
}
