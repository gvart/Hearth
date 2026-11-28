// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"golang.org/x/net/websocket"

	"github.com/gvart/hearth/internal/automation"
	"github.com/gvart/hearth/internal/hubconfig"
	"github.com/gvart/hearth/internal/integrations/kubernetes"
	"github.com/gvart/hearth/internal/notify"
	"github.com/gvart/hearth/internal/policy"
	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
	"github.com/gvart/hearth/internal/store"
)

// recSecret is a value a session shows that must reach neither the model,
// the audit log, the hub's log nor the store.
const recSecret = "s3cretRECSENTINEL"

// hiddenPassword is typed at a prompt that does not echo.
const hiddenPassword = "hunter2HIDDEN"

// passwordAgent is fakeShellAgent's echoing shell, but one that echoes
// nothing of what is typed after it asked for a password, as a terminal
// with its echo off: that input never comes back as output.
func passwordAgent(stream *connect.BidiStreamForClient[agentv1.AgentMessage, agentv1.HubMessage]) <-chan *agentv1.ShellRequest {
	got := make(chan *agentv1.ShellRequest, 64)
	event := func(ev *agentv1.ShellEvent) {
		_ = stream.Send(&agentv1.AgentMessage{Payload: &agentv1.AgentMessage_ShellEvent{ShellEvent: ev}})
	}
	output := func(id, s string) {
		event(&agentv1.ShellEvent{Id: id, Event: &agentv1.ShellEvent_Output{Output: []byte(s)}})
	}
	go func() {
		hidden := false
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
				event(&agentv1.ShellEvent{Id: id, Event: &agentv1.ShellEvent_Started{Started: &agentv1.ShellStarted{Shell: "/bin/fake"}}})
			case *agentv1.ShellRequest_Input:
				in := string(op.Input)
				switch {
				case hidden:
					hidden = false
					output(id, "\r\nok\r\n$ ")
				case strings.HasPrefix(in, "sudo"):
					output(id, in+"\r\n[sudo] password for pi: ")
					hidden = true
				default:
					output(id, "\x1b[32m$\x1b[0m "+in+"\r\n")
				}
			case *agentv1.ShellRequest_Close:
				event(&agentv1.ShellEvent{Id: id, Event: &agentv1.ShellEvent_Exited{Exited: &agentv1.ShellExited{ExitCode: -1}}})
			}
		}
	}()
	return got
}

// recordFixture is a terminal fixture of dev-1 whose shell is passwordAgent,
// with the configuration documents, the runbook engine, and AI set up
// against model unless model is nil.
func recordFixture(t *testing.T, model *scriptedModel, pol policy.Config) *terminalFixture {
	t.Helper()
	sealer, err := kubernetes.NewSealer([]byte("test secret"))
	if err != nil {
		t.Fatal(err)
	}
	f := newTerminalFixtureWith(t, 0, passwordAgent, withConfigDocs, func(c *Config) {
		c.Runbooks = automation.NewRunbooks(automation.RunbooksConfig{
			Source: hubconfig.StoreDocs(c.Store.ConfigDocs(), store.ConfigRunbook, "", string(policy.ConfigImport), time.Now),
			Kinds:  testKinds(&notify.Notifier{}), Policy: c.Policy, Runs: c.Store.RunbookRuns(), Sealer: sealer,
		})
	})
	if err := f.st.ConfigDocs().Put(t.Context(), "test", []store.ConfigDoc{
		{Kind: store.ConfigPolicy, Name: hubconfig.PolicyFile, Content: []byte{}},
	}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if model != nil {
		srv := model.start(t)
		setAI(t, f.apiFixture, f.cookie, map[string]any{"provider": "openai", "base_url": srv.URL + "/v1", "model": "llama3.2"})
	}
	// The policy under test applies once AI is set up.
	f.api.policy = policy.NewWithConfig(f.st.Audit(), f.st.Approvals(), pol)
	return f
}

// dialRecorded opens the terminal of dev-1 asking for a recording, with
// cookie.
func (f *terminalFixture) dialRecorded(t *testing.T, cookie *http.Cookie) *websocket.Conn {
	t.Helper()
	cfg, err := websocket.NewConfig(strings.Replace(f.srv.URL, "http", "ws", 1)+"/api/v1/devices/dev-1/shell?record=1", f.srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Header = http.Header{"Cookie": {cookie.String()}}
	ws, err := websocket.DialConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ws.Close() })
	return ws
}

func typeLine(t *testing.T, ws *websocket.Conn, line string) []byte {
	t.Helper()
	if err := shellCodec.Send(ws, shellFrame{binary: true, data: []byte(line)}); err != nil {
		t.Fatal(err)
	}
	_, out := next(t, ws)
	return out
}

func (f *terminalFixture) recordings(t *testing.T) []RecordingJSON {
	t.Helper()
	resp := f.do(t, http.MethodGet, "/api/v1/devices/dev-1/recordings", "", f.cookie)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list recordings = %d %s", resp.StatusCode, resp.body)
	}
	return decode[struct {
		Recordings []RecordingJSON `json:"recordings"`
	}](t, resp).Recordings
}

// recordSession records a session on dev-1 that installs Docker, shows a
// secret and answers a password prompt, then closes it. It returns the
// recording's id.
func (f *terminalFixture) recordSession(t *testing.T) string {
	t.Helper()
	ws := f.dialRecorded(t, f.cookie)
	m, _ := next(t, ws)
	if m.Type != "started" || m.Recording == "" || m.RecordLimit != maxRecordingBytes {
		t.Fatalf("first message = %+v, want started with a recording", m)
	}
	typeLine(t, ws, "export API_TOKEN="+recSecret)
	typeLine(t, ws, "sudo apt-get install -y docker.io")
	typeLine(t, ws, hiddenPassword)
	if got := f.recordings(t); len(got) != 1 || got[0].ID != m.Recording || got[0].Ended != nil {
		t.Fatalf("recordings while recording = %+v", got)
	}
	_ = ws.Close()
	for range 200 {
		if got := f.recordings(t); len(got) == 1 && got[0].Ended != nil {
			if got[0].Expires == nil || got[0].Expires.Sub(*got[0].Ended) != recordingTTL {
				t.Fatalf("recording = %+v, want it to expire an hour after the session", got[0])
			}
			return m.Recording
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("the recording never ended")
	return ""
}

const draftedRunbook = `id: add-docker
description: Install Docker on dev-1.
steps:
  - id: go-ahead
    type: prompt
    prompt: confirm
    message: Install Docker now?
  - id: install
    type: action
    action:
      type: exec
      device: dev-1
      command: [/usr/bin/apt-get, install, -y, docker.io]
      timeout: 10m
`

func draftRunbookBody(notes string, preview bool) string {
	b, _ := json.Marshal(RunbookDraftRequestJSON{Notes: notes, Preview: preview})
	return string(b)
}

func recAudit(t *testing.T, st *store.Store, action policy.Action) []store.AuditEntry {
	t.Helper()
	entries, err := st.Audit().Query(t.Context(), store.AuditFilter{Actions: []string{string(action)}}, 20)
	if err != nil {
		t.Fatal(err)
	}
	return entries
}

// TestRecordRunbook records a session, then drafts a runbook from it: the
// model gets the screen, redacted, never the hidden password; the draft is
// validated and retried, nothing is saved, and the recording goes.
func TestRecordRunbook(t *testing.T) {
	model := &scriptedModel{answers: []string{
		strings.Replace(draftedRunbook, "    prompt: confirm", "    prompt: maybe", 1),
		"```yaml\n" + draftedRunbook + "```",
	}}
	f := recordFixture(t, model, policy.Config{})
	id := f.recordSession(t)
	imports := len(recAudit(t, f.st, policy.ConfigImport)) // setting AI up is one

	// A preview sends nothing and keeps the recording.
	path := "/api/v1/devices/dev-1/recordings/" + id + "/runbook"
	pv := decode[RunbookDraftJSON](t, f.do(t, http.MethodPost, path, draftRunbookBody("", true), f.cookie))
	if !pv.Preview || pv.Discarded || len(model.sent()) != 0 || len(f.recordings(t)) != 1 {
		t.Fatalf("preview = %+v, calls %d", pv, len(model.sent()))
	}
	user := pv.Sent.Messages[0].Content
	if !strings.Contains(user, "\nsudo apt-get install -y docker.io\n[sudo] password for pi:\nok\n") || strings.Contains(user, "\x1b") {
		t.Fatalf("the transcript is not the screen's text:\n%s", user)
	}

	resp := f.do(t, http.MethodPost, path, draftRunbookBody("installed docker", false), f.cookie)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("draft = %d %s", resp.StatusCode, resp.body)
	}
	got := decode[RunbookDraftJSON](t, resp)
	if !got.Valid || got.Attempts != 2 || got.File != "add-docker.yaml" || got.Plan == nil || len(got.Plan.Steps) != 2 || !got.Discarded {
		t.Fatalf("draft = %+v", got)
	}
	sent := model.sent()
	if len(sent) != 2 || !strings.Contains(sent[1], "prompt") || !strings.Contains(sent[1], "not valid") {
		t.Fatalf("the problems were not fed back: %d calls", len(sent))
	}
	for _, body := range append(sent, string(resp.body)) {
		if strings.Contains(body, recSecret) || strings.Contains(body, hiddenPassword) {
			t.Fatalf("a secret or the hidden password reached the model or the answer: %s", body)
		}
	}
	if !strings.Contains(sent[0], "apt-get install -y docker.io") || !strings.Contains(sent[0], "installed docker") {
		t.Fatal("the transcript or the notes did not reach the model")
	}

	// The recording is gone once drafted; nothing was saved.
	if len(f.recordings(t)) != 0 {
		t.Fatal("the recording outlived its draft")
	}
	if again := f.do(t, http.MethodPost, path, draftRunbookBody("", false), f.cookie); again.StatusCode != http.StatusNotFound {
		t.Fatalf("draft again = %d", again.StatusCode)
	}
	files := f.do(t, http.MethodGet, "/api/v1/runbook-files", "", f.cookie)
	if strings.Contains(string(files.body), "add-docker") || len(recAudit(t, f.st, policy.ConfigImport)) != imports {
		t.Fatalf("a draft saved a runbook: %s", files.body)
	}

	// Audited: the recording's decision, both terminal entries naming it,
	// the draft; never what the session showed, anywhere the hub keeps.
	if e := recAudit(t, f.st, policy.DeviceShellRecord); len(e) != 1 || e[0].Decision != policy.Allow || e[0].Target != "dev-1" {
		t.Fatalf("device.shell.record audit = %+v", e)
	}
	for _, e := range shellAudit(t, f.st) {
		if !strings.Contains(string(e.Detail), `"recording":"`+id+`"`) {
			t.Errorf("device.shell entry does not name the recording: %s", e.Detail)
		}
	}
	if e := recAudit(t, f.st, policy.AIRunbookDraft); len(e) != 2 {
		t.Fatalf("ai.runbook.draft audit = %+v", e)
	}
	var snap bytes.Buffer
	if err := f.st.Snapshot(t.Context(), &snap); err != nil {
		t.Fatal(err)
	}
	for where, text := range map[string]string{"store": snap.String(), "log": f.logs.String(), "audit": aiAuditText(t, f.st)} {
		for _, s := range []string{recSecret, hiddenPassword, "docker.io"} {
			if strings.Contains(text, s) {
				t.Errorf("the %s holds %q from the session", where, s)
			}
		}
	}
}

func TestTerminalNotRecordedWithoutOptIn(t *testing.T) {
	f := recordFixture(t, &scriptedModel{}, policy.Config{})
	ws, err := f.dial(t, f.srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if m, _ := next(t, ws); m.Type != "started" || m.Recording != "" {
		t.Fatalf("first message = %+v, want started without a recording", m)
	}
	typeLine(t, ws, "export API_TOKEN="+recSecret)
	if got := f.recordings(t); len(got) != 0 {
		t.Fatalf("recordings = %+v", got)
	}
	_ = ws.Close()
	waitShellAudit(t, f.st, 2)
	if len(f.recordings(t)) != 0 || len(recAudit(t, f.st, policy.DeviceShellRecord)) != 0 {
		t.Fatal("a session opened without the opt-in was recorded")
	}
	for _, e := range shellAudit(t, f.st) {
		if strings.Contains(string(e.Detail), "record") {
			t.Errorf("an unrecorded session's entry says it was recorded: %s", e.Detail)
		}
	}
}

// A recorded session that is refused opens no shell at all.
func TestRecordedTerminalRefused(t *testing.T) {
	for _, tc := range []struct {
		name  string
		ai    bool
		pol   policy.Config
		stale bool
		code  string
	}{
		{name: "AI off", code: "ai_off"},
		{name: "no password again", ai: true, stale: true, code: "reauth_required"},
		{name: "denied by policy", ai: true, code: "forbidden", pol: policy.Config{Actors: map[string]map[policy.Class]policy.Mode{
			policy.ActorWeb: {policy.Dangerous: policy.ModeDeny},
		}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var model *scriptedModel
			if tc.ai {
				model = &scriptedModel{}
			}
			f := recordFixture(t, model, tc.pol)
			cookie := f.cookie
			if tc.stale {
				cookie = staleSession(t, f.apiFixture)
			}
			ws := f.dialRecorded(t, cookie)
			if m, _ := next(t, ws); m.Type != "error" || m.Code != tc.code {
				t.Fatalf("message = %+v, want error %s", m, tc.code)
			}
			select {
			case req := <-f.got:
				t.Fatalf("the agent was asked to open a shell: %v", req)
			case <-time.After(100 * time.Millisecond):
			}
			if e := recAudit(t, f.st, policy.DeviceShellRecord); len(e) != 1 || e[0].Decision != policy.Deny {
				t.Fatalf("device.shell.record audit = %+v", e)
			}
			if e := shellAudit(t, f.st); len(e) != 0 {
				t.Fatalf("device.shell was decided on: %+v", e)
			}
			if len(f.recordings(t)) != 0 {
				t.Fatal("a refused session left a recording")
			}
		})
	}
}

func TestRunbookDraftRefused(t *testing.T) {
	model := &scriptedModel{answers: []string{draftedRunbook}}
	f := recordFixture(t, model, policy.Config{})
	id := f.recordSession(t)
	path := "/api/v1/devices/dev-1/recordings/" + id + "/runbook"

	if resp := f.do(t, http.MethodPost, "/api/v1/devices/dev-1/recordings/nosuch/runbook", draftRunbookBody("", false), f.cookie); resp.StatusCode != http.StatusNotFound {
		t.Errorf("unknown recording = %d", resp.StatusCode)
	}
	if resp := f.do(t, http.MethodPost, path, draftRunbookBody("", false), nil); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("no session = %d", resp.StatusCode)
	}

	// Denied by policy: nothing reaches the model, the recording stays.
	f.api.policy = policy.NewWithConfig(f.st.Audit(), f.st.Approvals(), policy.Config{Actors: map[string]map[policy.Class]policy.Mode{
		policy.ActorWeb: {policy.Read: policy.ModeDeny},
	}})
	if resp := f.do(t, http.MethodPost, path, draftRunbookBody("", false), f.cookie); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("denied draft = %d %s", resp.StatusCode, resp.body)
	}
	if len(model.sent()) != 0 || len(f.recordings(t)) != 1 {
		t.Fatal("a denied draft reached the model or dropped the recording")
	}
	if e := recAudit(t, f.st, policy.AIRunbookDraft); len(e) != 1 || e[0].Decision != policy.Deny {
		t.Fatalf("ai.runbook.draft audit = %+v", e)
	}

	// Discarding deletes it at once.
	if resp := f.do(t, http.MethodDelete, "/api/v1/devices/dev-1/recordings/"+id, "", f.cookie); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("discard = %d", resp.StatusCode)
	}
	if len(f.recordings(t)) != 0 {
		t.Fatal("discarded, still listed")
	}
}

// A provider that fails leaves the recording for another try.
func TestRunbookDraftProviderError(t *testing.T) {
	f := recordFixture(t, nil, policy.Config{})
	model := &fakeModel{status: http.StatusUnauthorized}
	srv := model.start(t)
	setAI(t, f.apiFixture, f.cookie, map[string]any{"provider": "openai", "base_url": srv.URL + "/v1", "model": "m"})
	id := f.recordSession(t)
	resp := f.do(t, http.MethodPost, "/api/v1/devices/dev-1/recordings/"+id+"/runbook", draftRunbookBody("", false), f.cookie)
	if resp.StatusCode != http.StatusBadGateway || errorCode(t, resp) != "ai_auth" {
		t.Fatalf("draft = %d %s", resp.StatusCode, resp.body)
	}
	if len(f.recordings(t)) != 1 {
		t.Fatal("a failed draft dropped the recording")
	}

	// A model that answers nothing, at once or on the retry, makes no
	// draft: the recording stays too.
	for name, answers := range map[string][]string{
		"blank":            {""},
		"blank on a retry": {"id: Not Valid\n", ""},
	} {
		t.Run(name, func(t *testing.T) {
			model := &scriptedModel{answers: answers}
			f := recordFixture(t, model, policy.Config{})
			id := f.recordSession(t)
			resp := f.do(t, http.MethodPost, "/api/v1/devices/dev-1/recordings/"+id+"/runbook", draftRunbookBody("", false), f.cookie)
			if resp.StatusCode == http.StatusOK {
				t.Fatalf("draft = %d %s", resp.StatusCode, resp.body)
			}
			if got := len(model.sent()); got != len(answers) {
				t.Fatalf("%d calls, want %d", got, len(answers))
			}
			if len(f.recordings(t)) != 1 {
				t.Fatal("a draft that failed dropped the recording")
			}
		})
	}
}

func TestRecordingLimits(t *testing.T) {
	rs := newRecordings()
	rec, err := rs.begin("dev-1", "pi", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	chunk := bytes.Repeat([]byte("x"), 100<<10)
	for i, want := range []bool{false, false, true, false} {
		if got := rs.write(rec, chunk); got != want {
			t.Fatalf("write %d filled it: %v, want %v", i+1, got, want)
		}
	}
	if got, _ := rs.get("dev-1", rec.id); len(got.out) != maxRecordingBytes || !got.full {
		t.Fatalf("kept %d bytes, full %v", len(got.out), got.full)
	}
	if _, ok := rs.get("dev-2", rec.id); ok {
		t.Fatal("a recording read through another device")
	}

	// At most maxRecordings at a time.
	for range maxRecordings - 1 {
		if _, err := rs.begin("dev-1", "pi", time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := rs.begin("dev-1", "pi", time.Now()); err == nil || rs.room() == nil {
		t.Fatal("a recording past the limit")
	}
}

// An ended recording is deleted, its contents too, when its time is up.
func TestRecordingExpires(t *testing.T) {
	rs := newRecordings()
	rs.ttl = 20 * time.Millisecond
	rec, err := rs.begin("dev-1", "pi", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	rs.write(rec, []byte(recSecret))
	time.Sleep(50 * time.Millisecond)
	if _, ok := rs.get("dev-1", rec.id); !ok {
		t.Fatal("a live recording expired")
	}
	rs.finish(rec, time.Now())
	for range 200 {
		if _, ok := rs.get("dev-1", rec.id); !ok {
			if rec.out != nil {
				t.Fatal("the expired recording's contents are still held")
			}
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("the recording never expired")
}

func TestScreenText(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"\x1b[01;32mpi@pi5\x1b[00m:~ $ ls\r\nfile\r\n", "pi@pi5:~ $ ls\nfile\n"},
		{"$ sl\b\bls -l\r\n", "$ ls -l\n"},
		{"$ ech\b \bo hi\r\n", "$ eco hi\n"},
		{"\x1b]0;pi@pi5: ~\x07$ uptime\r\n", "$ uptime\n"},
		{"50%\r100%\r\n", "100%\n"},
		{"pi % uptime\r\r\n13:41 up\r\n", "pi % uptime\n13:41 up\n"},
		{"50%\r\r100%\r\n", "100%\n"},
		{"a\r\n\r\n\r\n\r\n\r\nb\r\n", "a\n\nb\n"},
		{"\x1b(B\x1b[?2004h$ x\x1b[?2004l\r\n", "$ x\n"},
		{"caf\xc3\xa9 \x07\x00ok", "café ok\n"},
	} {
		if got := screenText([]byte(tc.in)); got != tc.want {
			t.Errorf("screenText(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// dialRecordedAt is dialRecorded at the server srv, with header.
func dialRecordedAt(t *testing.T, srv *httptest.Server, cookie *http.Cookie, header http.Header) *websocket.Conn {
	t.Helper()
	cfg, err := websocket.NewConfig(strings.Replace(srv.URL, "http", "ws", 1)+"/api/v1/devices/dev-1/shell?record=1", srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Header = header.Clone()
	if cfg.Header == nil {
		cfg.Header = http.Header{}
	}
	cfg.Header.Set("Cookie", cookie.String())
	ws, err := websocket.DialConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ws.Close() })
	return ws
}

// provenPeerKey marks, in tests, a request from a master that proved on the
// masters' link that it holds the hub CA key (cluster.MasterPeer).
type provenPeerKey struct{}

// TestProxiedRecording: in a cluster, the password is entered on the hub the
// browser talks to, which proxies the recorded terminal and its recording
// requests to the hub holding the device's stream. That hub believes the
// re-authentication the proxying master carries only from a master that
// proved it holds the hub CA key on the link, and for at most ReauthTTL.
func TestProxiedRecording(t *testing.T) {
	f := recordFixture(t, &scriptedModel{answers: []string{draftedRunbook}}, policy.Config{})
	f.api.masterPeer = func(ctx context.Context) string {
		id, _ := ctx.Value(provenPeerKey{}).(string)
		return id
	}
	proxied := ProxiedHandler(f.srv.Config.Handler)
	link := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxied.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), provenPeerKey{}, "a")))
	}))
	t.Cleanup(link.Close)
	// A member with a hub certificate that did not prove the CA key: a
	// storage member, say.
	unproven := httptest.NewServer(proxied)
	t.Cleanup(unproven.Close)
	stale := staleSession(t, f.apiFixture)
	until := func(d time.Duration) http.Header {
		return http.Header{reauthHeader: {f.api.now().Add(d).Format(time.RFC3339Nano)}}
	}
	for _, tc := range []struct {
		name   string
		srv    *httptest.Server
		header http.Header
	}{
		{"no re-authentication carried", link, nil},
		{"one that ended", link, until(-time.Second)},
		{"one that ended over 5 min ago", link, until(-ReauthTTL - time.Minute)},
		{"one past the TTL", link, until(ReauthTTL + time.Minute)},
		{"not a time", link, http.Header{reauthHeader: {"forever"}}},
		{"from a peer that did not prove the CA key", unproven, until(2 * time.Minute)},
		{"not on the masters' link", f.srv, until(2 * time.Minute)},
	} {
		ws := dialRecordedAt(t, tc.srv, stale, tc.header)
		if m, _ := next(t, ws); m.Type != "error" || m.Code != "reauth_required" {
			t.Fatalf("%s: message = %+v, want reauth_required", tc.name, m)
		}
	}

	ws := dialRecordedAt(t, link, stale, until(2*time.Minute))
	m, _ := next(t, ws)
	if m.Type != "started" || m.Recording == "" {
		t.Fatalf("proxied recorded terminal = %+v, want started with a recording", m)
	}
	typeLine(t, ws, "uptime")
	_ = ws.Close()
	for range 200 {
		if got := f.recordings(t); len(got) == 1 && got[0].Ended != nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	// The recording routes are served on the link too.
	send := func(method, path, body string) (int, string) {
		t.Helper()
		req, err := http.NewRequestWithContext(t.Context(), method, link.URL+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(f.cookie)
		resp, err := link.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	if code, body := send(http.MethodGet, "/api/v1/devices/dev-1/recordings", ""); code != http.StatusOK || !strings.Contains(body, m.Recording) {
		t.Fatalf("proxied list = %d %s", code, body)
	}
	if code, body := send(http.MethodPost, "/api/v1/devices/dev-1/recordings/"+m.Recording+"/runbook", draftRunbookBody("", true)); code != http.StatusOK {
		t.Fatalf("proxied preview = %d %s", code, body)
	}
	if code, body := send(http.MethodDelete, "/api/v1/devices/dev-1/recordings/"+m.Recording, ""); code != http.StatusNoContent {
		t.Fatalf("proxied discard = %d %s", code, body)
	}
}

// TestCarryReauth: the proxying master sets the re-authentication of the
// session here, a time and nothing else, and drops one its client sent.
func TestCarryReauth(t *testing.T) {
	f := recordFixture(t, nil, policy.Config{})
	forge := func(cookie *http.Cookie) *http.Request {
		in := httptest.NewRequest(http.MethodGet, "/api/v1/devices/dev-1/shell?record=1", nil)
		in.AddCookie(cookie)
		in.Header.Set(reauthHeader, f.api.now().Add(time.Hour).Format(time.RFC3339Nano))
		return in
	}

	in := forge(staleSession(t, f.apiFixture))
	out := in.Clone(t.Context())
	f.api.carryReauth(out, in)
	if got := out.Header.Values(reauthHeader); len(got) != 0 {
		t.Fatalf("a session with no re-authentication carried %q", got)
	}

	in = forge(f.cookie)
	out = in.Clone(t.Context())
	f.api.carryReauth(out, in)
	got := out.Header.Values(reauthHeader)
	if len(got) != 1 {
		t.Fatalf("carried %q, want one time", got)
	}
	at, err := time.Parse(time.RFC3339Nano, got[0])
	if err != nil {
		t.Fatalf("carried %q: %v", got[0], err)
	}
	if want := f.api.reauthUntil(in); !at.Equal(want) || at.After(f.api.now().Add(ReauthTTL)) {
		t.Fatalf("carried %v, want the session's %v", at, want)
	}
	if strings.Contains(got[0], f.cookie.Value) || strings.Contains(got[0], "testpass") {
		t.Fatal("the header carries a secret")
	}
}
