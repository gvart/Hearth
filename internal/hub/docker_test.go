// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
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
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/gvart/hearth/internal/policy"
	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
	"github.com/gvart/hearth/internal/proto/hearth/agent/v1/agentv1connect"
	"github.com/gvart/hearth/internal/store"
)

// fakeDockerAgent answers each DockerRequest on stream with answer's
// result, and reports the requests it gets.
func fakeDockerAgent(stream *connect.BidiStreamForClient[agentv1.AgentMessage, agentv1.HubMessage],
	answer func(*agentv1.DockerRequest) *agentv1.DockerResult,
) <-chan *agentv1.DockerRequest {
	reqs := make(chan *agentv1.DockerRequest, 16)
	go func() {
		for {
			msg, err := stream.Receive()
			if err != nil {
				return
			}
			req := msg.GetDockerRequest()
			if req == nil {
				continue
			}
			reqs <- req
			res := answer(req)
			res.Id = req.GetId()
			_ = stream.Send(&agentv1.AgentMessage{Payload: &agentv1.AgentMessage_DockerResult{DockerResult: res}})
		}
	}()
	return reqs
}

// dockerAnswer is what a fake agent with an engine of two stacks and a
// standalone container answers.
func dockerAnswer(req *agentv1.DockerRequest) *agentv1.DockerResult {
	switch op := req.GetOp().(type) {
	case *agentv1.DockerRequest_List:
		return &agentv1.DockerResult{
			Containers: []*agentv1.DockerContainer{
				{Id: "c1", Name: "media-web-1", Image: "nginx", State: "running", ComposeProject: "media", ComposeService: "web"},
				{Id: "c2", Name: "media-db-1", Image: "postgres", State: "exited", ComposeProject: "media", ComposeService: "db"},
				{Id: "c3", Name: "dns", Image: "pihole", State: "running", ComposeProject: "adblock", ComposeService: "pihole"},
				{Id: "c4", Name: "hearth-t64-test", Image: "alpine", State: "running", Created: timestamppb.New(time.Unix(1700000000, 0))},
			},
			Images: []*agentv1.DockerImage{{Id: "sha256:1", Tags: []string{"nginx:latest"}, SizeBytes: 1 << 20}, {Id: "sha256:2"}},
		}
	case *agentv1.DockerRequest_Logs:
		return &agentv1.DockerResult{Lines: []*agentv1.LogLine{{Text: "hello from " + op.Logs.GetContainer()}}, Truncated: true}
	case *agentv1.DockerRequest_Action:
		if op.Action.GetContainer() == "gone" {
			return &agentv1.DockerResult{Error: "stop gone: docker engine: No such container: gone (HTTP 404)"}
		}
		return &agentv1.DockerResult{}
	}
	return &agentv1.DockerResult{Denied: true, Error: "unknown"}
}

type dockerFixture struct {
	srv    *httptest.Server
	client agentv1connect.AgentServiceClient
	st     *store.Store
}

func newDockerFixture(t *testing.T, cfg policy.Config) *dockerFixture {
	t.Helper()
	st := newTestStore(t)
	enrollDevice(t, st, "dev-1")
	client, agents := newExecClient(t, st)
	a := newAPI(Config{Store: st, Policy: policy.NewWithConfig(st.Audit(), nil, cfg), Log: slog.New(slog.DiscardHandler), Agents: agents})
	srv := httptest.NewServer(a.routes())
	t.Cleanup(srv.Close)
	if err := st.Admin().CreateSession(t.Context(), "docker-session", time.Now(), time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	return &dockerFixture{srv: srv, client: client, st: st}
}

// do sends a request, retrying while the agent's stream is not attached
// yet.
func (f *dockerFixture) do(t *testing.T, method, path, body string) (int, string) {
	t.Helper()
	for range 100 {
		req, err := http.NewRequestWithContext(t.Context(), method, f.srv.URL+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		req.AddCookie(testCookie("docker-session"))
		resp, err := f.srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusConflict {
			return resp.StatusCode, string(b)
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("the agent never attached")
	return 0, ""
}

// audit is the docker audit entries, oldest first, as "decision action
// target result".
func (f *dockerFixture) audit(t *testing.T) []string {
	t.Helper()
	es, err := f.st.Audit().List(t.Context(), 100)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for i := len(es) - 1; i >= 0; i-- {
		if e := es[i]; strings.HasPrefix(e.Action, "device.docker.") {
			out = append(out, e.Decision+" "+e.Action+" "+e.Target+" "+e.Result)
		}
	}
	return out
}

func TestDeviceDockerList(t *testing.T) {
	t.Parallel()
	f := newDockerFixture(t, policy.Config{})
	reqs := fakeDockerAgent(connectAgent(t.Context(), t, f.client, minDockerMinor, &agentv1.Ceiling{Docker: true}), dockerAnswer)
	status, body := f.do(t, http.MethodGet, "/api/v1/devices/dev-1/docker", "")
	if status != http.StatusOK {
		t.Fatalf("list = %d %s", status, body)
	}
	var got DockerJSON
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Stacks) != 2 || got.Stacks[0].Project != "adblock" || got.Stacks[1].Project != "media" {
		t.Fatalf("stacks = %+v, want adblock and media", got.Stacks)
	}
	media := got.Stacks[1]
	if media.Running != 1 || len(media.Containers) != 2 || media.Containers[0].Service != "db" || media.Containers[1].Name != "media-web-1" {
		t.Errorf("media = %+v", media)
	}
	if len(got.Containers) != 1 || got.Containers[0].Name != "hearth-t64-test" || got.Containers[0].Created == nil {
		t.Errorf("standalone = %+v", got.Containers)
	}
	if len(got.Images) != 2 || got.Images[1].Tags == nil {
		t.Errorf("images = %+v", got.Images)
	}
	if r := <-reqs; r.GetList() == nil || r.GetTimeout().AsDuration() != dockerTimeout {
		t.Errorf("agent got %v", r)
	}
	if a := f.audit(t); len(a) != 1 || a[0] != "allow device.docker.list dev-1 read allowed" {
		t.Errorf("audit = %q", a)
	}
}

func TestDeviceDockerLogs(t *testing.T) {
	t.Parallel()
	f := newDockerFixture(t, policy.Config{})
	reqs := fakeDockerAgent(connectAgent(t.Context(), t, f.client, minDockerMinor, &agentv1.Ceiling{Docker: true}), dockerAnswer)
	status, body := f.do(t, http.MethodGet, "/api/v1/devices/dev-1/docker/logs?container=web&tail=5000", "")
	if status != http.StatusOK || !strings.Contains(body, `"text":"hello from web"`) || !strings.Contains(body, `"truncated":true`) {
		t.Fatalf("logs = %d %s", status, body)
	}
	if r := <-reqs; r.GetLogs().GetContainer() != "web" || r.GetLogs().GetTail() != policy.MaxDockerLogTail {
		t.Errorf("agent got %v, want the tail capped at %d", r, policy.MaxDockerLogTail)
	}
	if a := f.audit(t); len(a) != 1 || a[0] != "allow device.docker.logs dev-1 read allowed" {
		t.Errorf("audit = %q", a)
	}
}

func TestDeviceDockerAction(t *testing.T) {
	t.Parallel()
	f := newDockerFixture(t, policy.Config{})
	reqs := fakeDockerAgent(connectAgent(t.Context(), t, f.client, minDockerMinor, &agentv1.Ceiling{Docker: true}), dockerAnswer)
	for _, verb := range []string{"start", "stop", "restart"} {
		status, body := f.do(t, http.MethodPost, "/api/v1/devices/dev-1/docker/actions", `{"action":"`+verb+`","container":"web"}`)
		if status != http.StatusOK || !strings.Contains(body, `"result":"ok"`) {
			t.Errorf("%s = %d %s", verb, status, body)
		}
		if r := <-reqs; r.GetAction().GetVerb() != verb || r.GetAction().GetContainer() != "web" {
			t.Errorf("agent got %v", r)
		}
	}
	status, body := f.do(t, http.MethodPost, "/api/v1/devices/dev-1/docker/actions", `{"action":"stop","container":"gone"}`)
	if status != http.StatusBadGateway || !strings.Contains(body, "No such container: gone") || !strings.Contains(body, "docker_error") {
		t.Errorf("stop of an unknown container = %d %s", status, body)
	}
	want := []string{
		"allow device.docker.start dev-1 ok", "allow device.docker.stop dev-1 ok", "allow device.docker.restart dev-1 ok",
	}
	a := f.audit(t)
	if len(a) != len(want)+1 || strings.Join(a[:len(want)], "|") != strings.Join(want, "|") ||
		!strings.Contains(a[len(want)], "error: docker: stop gone") {
		t.Errorf("audit = %q", a)
	}
}

// A request beyond the agent's ceiling, or that policy denies, is refused
// and audited, and never reaches the agent; a malformed one is refused
// before policy.
func TestDeviceDockerRefused(t *testing.T) {
	t.Parallel()
	denySafe := policy.Config{Actors: map[string]map[policy.Class]policy.Mode{policy.ActorWeb: {policy.Safe: policy.ModeDeny}}}
	on := &agentv1.Ceiling{Docker: true}
	for _, tc := range []struct {
		name    string
		cfg     policy.Config
		minor   uint32
		ceiling *agentv1.Ceiling
		method  string
		path    string
		body    string
		status  int
		want    string
		audited string
	}{
		{"ceiling off", policy.Config{}, minDockerMinor, &agentv1.Ceiling{Logs: []string{"docker:*"}, Restart: []string{"docker:web"}},
			http.MethodGet, "/api/v1/devices/dev-1/docker", "", http.StatusForbidden, "--allow-docker", "deny device.docker.list"},
		{"ceiling off, action", policy.Config{}, minDockerMinor, &agentv1.Ceiling{Restart: []string{"docker:web"}},
			http.MethodPost, "/api/v1/devices/dev-1/docker/actions", `{"action":"restart","container":"web"}`, http.StatusForbidden, "--allow-docker", "deny device.docker.restart"},
		{"ceiling off, logs", policy.Config{}, minDockerMinor, nil,
			http.MethodGet, "/api/v1/devices/dev-1/docker/logs?container=web", "", http.StatusForbidden, "--allow-docker", "deny device.docker.logs"},
		{"agent too old", policy.Config{}, minDockerMinor - 1, on,
			http.MethodGet, "/api/v1/devices/dev-1/docker", "", http.StatusForbidden, "too old", "deny device.docker.list"},
		{"policy denies", denySafe, minDockerMinor, on,
			http.MethodPost, "/api/v1/devices/dev-1/docker/actions", `{"action":"stop","container":"web"}`, http.StatusForbidden, "denied by policy", "deny device.docker.stop"},
		{"invalid container", policy.Config{}, minDockerMinor, on,
			http.MethodPost, "/api/v1/devices/dev-1/docker/actions", `{"action":"stop","container":"../../images/create"}`, http.StatusBadRequest, "container", ""},
		{"invalid container, logs", policy.Config{}, minDockerMinor, on,
			http.MethodGet, "/api/v1/devices/dev-1/docker/logs?container=web%2F..%2Fexec", "", http.StatusBadRequest, "container", ""},
		{"exec", policy.Config{}, minDockerMinor, on,
			http.MethodPost, "/api/v1/devices/dev-1/docker/actions", `{"action":"exec","container":"web"}`, http.StatusBadRequest, "start, stop, restart", ""},
		{"remove", policy.Config{}, minDockerMinor, on,
			http.MethodPost, "/api/v1/devices/dev-1/docker/actions", `{"action":"remove","container":"web"}`, http.StatusBadRequest, "start, stop, restart", ""},
		{"no tail", policy.Config{}, minDockerMinor, on,
			http.MethodGet, "/api/v1/devices/dev-1/docker/logs?container=web&tail=0", "", http.StatusBadRequest, "tail", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newDockerFixture(t, tc.cfg)
			reqs := fakeDockerAgent(connectAgent(t.Context(), t, f.client, tc.minor, tc.ceiling), dockerAnswer)
			status, body := f.do(t, tc.method, tc.path, tc.body)
			if status != tc.status || !strings.Contains(body, tc.want) {
				t.Errorf("= %d %s, want %d with %q", status, body, tc.status, tc.want)
			}
			select {
			case r := <-reqs:
				t.Errorf("agent got %v for a refused request", r)
			default:
			}
			a := f.audit(t)
			switch {
			case tc.audited == "" && len(a) != 0:
				t.Errorf("audit = %q, want nothing", a)
			case tc.audited != "" && (len(a) != 1 || !strings.HasPrefix(a[0], tc.audited+" dev-1 ")):
				t.Errorf("audit = %q, want one %q", a, tc.audited)
			}
		})
	}
}

// The agent's own refusal is an error, audited as the action's outcome.
func TestDeviceDockerAgentRefuses(t *testing.T) {
	t.Parallel()
	f := newDockerFixture(t, policy.Config{})
	fakeDockerAgent(connectAgent(context.WithoutCancel(t.Context()), t, f.client, minDockerMinor, &agentv1.Ceiling{Docker: true}),
		func(*agentv1.DockerRequest) *agentv1.DockerResult {
			return &agentv1.DockerResult{Denied: true, Error: "docker: beyond the capability ceiling"}
		})
	status, body := f.do(t, http.MethodPost, "/api/v1/devices/dev-1/docker/actions", `{"action":"start","container":"web"}`)
	if status != http.StatusForbidden || !strings.Contains(body, "the agent refused") {
		t.Errorf("= %d %s, want 403", status, body)
	}
}
