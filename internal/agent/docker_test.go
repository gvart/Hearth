// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/durationpb"

	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
)

// socketDir is a directory for a unix socket: t.TempDir(), unless its path
// is too long for one (macOS allows 104 bytes).
func socketDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if len(dir) < 80 {
		return dir
	}
	dir, err := os.MkdirTemp("", "hd")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// fakeDocker is a Docker Engine API on a unix socket that serves what the
// agent uses, and records every request.
type fakeDocker struct {
	socket string
	// logsType is the Content-Type of a logs answer; logs is its body.
	logsType string
	logs     []byte
	// containers and images, when set, are the bodies of the lists.
	containers, images []byte

	mu   sync.Mutex
	reqs []string
}

func (f *fakeDocker) requests() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.reqs...)
}

func startFakeDocker(t *testing.T) *fakeDocker {
	t.Helper()
	f := &fakeDocker{socket: filepath.Join(socketDir(t), "d.sock"), logsType: multiplexedStream}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /containers/json", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("all") != "1" {
			http.Error(w, "want all=1", http.StatusBadRequest)
			return
		}
		if f.containers != nil {
			_, _ = w.Write(f.containers)
			return
		}
		writeJSONBody(w, []map[string]any{
			{
				"Id": "aaa111", "Names": []string{"/web"}, "Image": "nginx:1.27", "State": "running", "Status": "Up 2 hours",
				"Created": 1700000000,
				"Labels":  map[string]string{"com.docker.compose.project": "media", "com.docker.compose.service": "web"},
			},
			{"Id": "bbb222", "Names": []string{"/hearth-t64-test"}, "Image": "alpine", "State": "exited", "Status": "Exited (0) 1 minute ago", "Created": 1700000100},
		})
	})
	mux.HandleFunc("GET /images/json", func(w http.ResponseWriter, _ *http.Request) {
		if f.images != nil {
			_, _ = w.Write(f.images)
			return
		}
		writeJSONBody(w, []map[string]any{
			{"Id": "sha256:111", "RepoTags": []string{"nginx:1.27"}, "Size": int64(5) << 30, "Created": 1690000000},
			{"Id": "sha256:222", "RepoTags": []string{"<none>:<none>"}, "Size": 1000, "Created": 1690000000},
		})
	})
	mux.HandleFunc("POST /containers/{id}/{verb}", func(w http.ResponseWriter, r *http.Request) {
		switch r.PathValue("id") {
		case "web", "aaa111", "hearth-t64-test":
			w.WriteHeader(http.StatusNoContent)
		case "already":
			w.WriteHeader(http.StatusNotModified)
		case "moved":
			http.Redirect(w, r, "/containers/web/kill", http.StatusTemporaryRedirect)
		default:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			writeJSONBody(w, map[string]string{"message": "No such container: " + r.PathValue("id")})
		}
	})
	mux.HandleFunc("GET /containers/{id}/logs", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Has("follow") {
			http.Error(w, "follow", http.StatusBadRequest)
			return
		}
		if f.logsType != "" {
			w.Header().Set("Content-Type", f.logsType)
		}
		_, _ = w.Write(f.logs)
	})
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.reqs = append(f.reqs, r.Method+" "+r.URL.RequestURI())
		f.mu.Unlock()
		mux.ServeHTTP(w, r)
	}), ReadHeaderTimeout: time.Second}
	ln, err := net.Listen("unix", f.socket)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return f
}

func writeJSONBody(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// frame is one frame of a multiplexed log stream.
func frame(stream byte, s string) []byte {
	h := make([]byte, 8, 8+len(s))
	h[0] = stream
	binary.BigEndian.PutUint32(h[4:], uint32(len(s))) //nolint:gosec // test data
	return append(h, s...)
}

func listReq() *agentv1.DockerRequest {
	return &agentv1.DockerRequest{Id: "1", Op: &agentv1.DockerRequest_List{List: &agentv1.DockerList{}}}
}

func actionReq(verb, c string) *agentv1.DockerRequest {
	return &agentv1.DockerRequest{Id: "2", Op: &agentv1.DockerRequest_Action{Action: &agentv1.DockerAction{Verb: verb, Container: c}}}
}

func logsReq(c string, tail uint32) *agentv1.DockerRequest {
	return &agentv1.DockerRequest{Id: "3", Op: &agentv1.DockerRequest_Logs{Logs: &agentv1.DockerLogs{Container: c, Tail: tail}}}
}

var dockerOn = Ceiling{Docker: true}

func TestDockerList(t *testing.T) {
	t.Parallel()
	f := startFakeDocker(t)
	res := dockerEngine{sockets: []string{f.socket}}.docker(t.Context(), dockerOn, listReq())
	if res.GetError() != "" || res.GetDenied() {
		t.Fatalf("list: %v", res)
	}
	if res.GetId() != "1" || len(res.GetContainers()) != 2 || len(res.GetImages()) != 2 {
		t.Fatalf("list = %v", res)
	}
	web := res.GetContainers()[0]
	if web.GetName() != "web" || web.GetImage() != "nginx:1.27" || web.GetState() != "running" || web.GetStatus() != "Up 2 hours" ||
		web.GetComposeProject() != "media" || web.GetComposeService() != "web" || web.GetCreated().GetSeconds() != 1700000000 {
		t.Errorf("web = %v", web)
	}
	if c := res.GetContainers()[1]; c.GetName() != "hearth-t64-test" || c.GetComposeProject() != "" || c.GetState() != "exited" {
		t.Errorf("standalone = %v", c)
	}
	if i := res.GetImages()[0]; i.GetSizeBytes() != 5<<30 || len(i.GetTags()) != 1 || i.GetTags()[0] != "nginx:1.27" {
		t.Errorf("image = %v", i)
	}
	if i := res.GetImages()[1]; len(i.GetTags()) != 0 {
		t.Errorf("dangling image tags = %v, want none", i.GetTags())
	}
	want := []string{"GET /containers/json?all=1", "GET /images/json"}
	if got := f.requests(); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("requests = %v, want %v", got, want)
	}
}

func TestDockerActions(t *testing.T) {
	t.Parallel()
	f := startFakeDocker(t)
	d := dockerEngine{sockets: []string{f.socket}}
	for _, verb := range []string{"start", "stop", "restart"} {
		if res := d.docker(t.Context(), dockerOn, actionReq(verb, "web")); res.GetError() != "" || res.GetDenied() {
			t.Errorf("%s: %v", verb, res)
		}
	}
	// Already in that state: success.
	if res := d.docker(t.Context(), dockerOn, actionReq("start", "already")); res.GetError() != "" {
		t.Errorf("start of a started container: %v", res)
	}
	res := d.docker(t.Context(), dockerOn, actionReq("stop", "nope"))
	if res.GetDenied() || !strings.Contains(res.GetError(), "No such container: nope") || !strings.Contains(res.GetError(), "404") {
		t.Errorf("stop of an unknown container = %v", res)
	}
	want := []string{
		"POST /containers/web/start", "POST /containers/web/stop", "POST /containers/web/restart",
		"POST /containers/already/start", "POST /containers/nope/stop",
	}
	if got := f.requests(); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("requests = %v, want %v", got, want)
	}
}

func TestDockerLogs(t *testing.T) {
	t.Parallel()
	ts := "2026-11-20T11:36:27.216328192Z"
	long := strings.Repeat("x", maxLogLine+100)
	multiplexed := append(append(frame(1, ts+" line 1\n"), frame(2, ts+" err 1\n")...), frame(1, ts+" "+long+"\n")...)
	for _, tc := range []struct {
		name, contentType string
		body              []byte
	}{
		{"multiplexed", multiplexedStream, multiplexed},
		{"multiplexed sniffed", "application/octet-stream", multiplexed},
		{"multiplexed untyped", "", multiplexed},
		{"tty", rawStream, []byte(ts + " line 1\r\n" + ts + " err 1\r\n" + ts + " " + long + "\r\n")},
		{"tty sniffed", "", []byte(ts + " line 1\n" + ts + " err 1\n" + ts + " " + long)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := startFakeDocker(t)
			f.logsType, f.logs = tc.contentType, tc.body
			res := dockerEngine{sockets: []string{f.socket}}.docker(t.Context(), dockerOn, logsReq("web", 50))
			if res.GetError() != "" {
				t.Fatalf("logs: %v", res.GetError())
			}
			lines := res.GetLines()
			if len(lines) != 3 || lines[0].GetText() != "line 1" || lines[1].GetText() != "err 1" {
				t.Fatalf("lines = %v", lines)
			}
			if lines[0].GetTs().AsTime().Format(time.RFC3339Nano) != ts {
				t.Errorf("ts = %v", lines[0].GetTs().AsTime())
			}
			if got := lines[2].GetText(); len(got) > maxLogLine+len("…") || !strings.HasPrefix(got, "xxx") {
				t.Errorf("long line: %d bytes, want clipped to %d", len(got), maxLogLine)
			}
			if got := f.requests(); len(got) != 1 || got[0] != "GET /containers/web/logs?stderr=1&stdout=1&tail=50&timestamps=1" {
				t.Errorf("requests = %v", got)
			}
		})
	}
}

// The agent never asks for more than MaxDockerLogTail lines, and keeps no
// more than that whatever the engine sends.
func TestDockerLogsTailCapped(t *testing.T) {
	t.Parallel()
	f := startFakeDocker(t)
	var body []byte
	for i := range 300 {
		body = append(body, frame(1, "line "+strconv.Itoa(i)+"\n")...)
	}
	f.logs = body
	res := dockerEngine{sockets: []string{f.socket}}.docker(t.Context(), dockerOn, logsReq("web", 100000))
	if res.GetError() != "" {
		t.Fatal(res.GetError())
	}
	if got := f.requests(); len(got) != 1 || !strings.Contains(got[0], "tail=200&") {
		t.Errorf("requests = %v, want tail=200", got)
	}
	if n := len(res.GetLines()); n != 200 || res.GetLines()[199].GetText() != "line 299" || !res.GetTruncated() {
		t.Errorf("%d lines, last %q, truncated %v; want the last 200", n, res.GetLines()[n-1].GetText(), res.GetTruncated())
	}
	// A tail of 0 reads one line, not the whole log.
	f2 := startFakeDocker(t)
	dockerEngine{sockets: []string{f2.socket}}.docker(t.Context(), dockerOn, logsReq("web", 0))
	if got := f2.requests(); len(got) != 1 || !strings.Contains(got[0], "tail=1&") {
		t.Errorf("requests = %v, want tail=1", got)
	}
}

// Without --allow-docker, or for a request no agent takes, the engine is
// never asked anything.
func TestDockerRefused(t *testing.T) {
	t.Parallel()
	f := startFakeDocker(t)
	d := dockerEngine{sockets: []string{f.socket}}
	off := Ceiling{Logs: []string{"docker:*"}, Restart: []string{"docker:web"}, Exec: []string{"docker"}}
	for _, tc := range []struct {
		name string
		c    Ceiling
		req  *agentv1.DockerRequest
	}{
		{"list, ceiling off", off, listReq()},
		{"logs, ceiling off", off, logsReq("web", 10)},
		{"restart, ceiling off", off, actionReq("restart", "web")},
		{"exec", dockerOn, actionReq("exec", "web")},
		{"kill", dockerOn, actionReq("kill", "web")},
		{"path", dockerOn, actionReq("start", "../../images/create")},
		{"escaped path", dockerOn, actionReq("start", "web%2F..%2Fexec")},
		{"query", dockerOn, logsReq("web?follow=1", 10)},
		{"slash", dockerOn, logsReq("a/b", 10)},
		{"empty", dockerOn, actionReq("stop", "")},
		{"no op", dockerOn, &agentv1.DockerRequest{Id: "x"}},
	} {
		res := d.docker(t.Context(), tc.c, tc.req)
		if !res.GetDenied() || res.GetError() == "" || len(res.GetContainers()) > 0 || len(res.GetLines()) > 0 {
			t.Errorf("%s: %v, want denied", tc.name, res)
		}
	}
	if got := f.requests(); len(got) != 0 {
		t.Errorf("the engine was asked %v, want nothing", got)
	}
}

func TestDockerSocketErrors(t *testing.T) {
	t.Parallel()
	dir := socketDir(t)
	missing := filepath.Join(dir, "missing.sock")
	file := filepath.Join(dir, "file.sock")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A socket nobody listens on any more.
	stale := filepath.Join(dir, "stale.sock")
	ln, err := net.Listen("unix", stale)
	if err != nil {
		t.Fatal(err)
	}
	ln.(*net.UnixListener).SetUnlinkOnClose(false)
	_ = ln.Close()
	// A socket that serves something other than Docker.
	other := filepath.Join(dir, "other.sock")
	oln, err := net.Listen("unix", other)
	if err != nil {
		t.Fatal(err)
	}
	osrv := &http.Server{Handler: http.NotFoundHandler(), ReadHeaderTimeout: time.Second}
	go func() { _ = osrv.Serve(oln) }()
	t.Cleanup(func() { _ = osrv.Close() })

	for _, tc := range []struct {
		name    string
		sockets []string
		want    []string
	}{
		{"missing", []string{missing}, []string{"no Docker or Podman socket at " + missing, "--docker-socket"}},
		{"not a socket", []string{file}, []string{"no Docker or Podman socket at " + file}},
		{"defaults missing", []string{missing, file}, []string{"tried " + missing + ", " + file}},
		{"nobody listening", []string{stale}, []string{"cannot reach the Docker engine at " + stale}},
		{"not docker", []string{other}, []string{"list containers: docker engine:", "HTTP 404"}},
	} {
		res := dockerEngine{sockets: tc.sockets}.docker(t.Context(), dockerOn, listReq())
		if res.GetDenied() {
			t.Errorf("%s: denied, want an error", tc.name)
		}
		for _, w := range tc.want {
			if !strings.Contains(res.GetError(), w) {
				t.Errorf("%s: error %q, want it to say %q", tc.name, res.GetError(), w)
			}
		}
	}
}

func TestDockerSocketFallback(t *testing.T) {
	f := startFakeDocker(t)
	// The first that exists wins.
	res := dockerEngine{sockets: []string{filepath.Join(filepath.Dir(f.socket), "none.sock"), f.socket}}.docker(t.Context(), dockerOn, listReq())
	if res.GetError() != "" {
		t.Errorf("fallback: %v", res.GetError())
	}

	t.Setenv("XDG_RUNTIME_DIR", "/run/user/1000")
	want := []string{"/var/run/docker.sock", "/run/user/1000/podman/podman.sock", "/run/podman/podman.sock"}
	if got := dockerSockets(""); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("dockerSockets() = %v, want %v", got, want)
	}
	t.Setenv("XDG_RUNTIME_DIR", "")
	if got := dockerSockets(""); strings.Join(got, ",") != "/var/run/docker.sock,/run/podman/podman.sock" {
		t.Errorf("dockerSockets() without XDG_RUNTIME_DIR = %v", got)
	}
	if got := dockerSockets("unix:///home/u/.colima/default/docker.sock"); len(got) != 1 || got[0] != "/home/u/.colima/default/docker.sock" {
		t.Errorf("dockerSockets(explicit) = %v, want only it", got)
	}
}

// An engine slower than the request's timeout fails the request in time.
func TestDockerTimeout(t *testing.T) {
	t.Parallel()
	sock := filepath.Join(socketDir(t), "slow.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	release := make(chan struct{})
	srv := &http.Server{Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) { <-release }), ReadHeaderTimeout: time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { close(release); _ = srv.Close() })
	req := actionReq("stop", "web")
	req.Timeout = durationpb.New(50 * time.Millisecond)
	start := time.Now()
	res := dockerEngine{sockets: []string{sock}}.docker(t.Context(), dockerOn, req)
	if !strings.Contains(res.GetError(), context.DeadlineExceeded.Error()) || time.Since(start) > 5*time.Second {
		t.Errorf("slow engine: %q after %v", res.GetError(), time.Since(start))
	}
}

func TestLastLines(t *testing.T) {
	t.Parallel()
	lines, dropped, err := lastLines(strings.NewReader("a\nb\nc\nd\n"), 2)
	if err != nil || !dropped || len(lines) != 2 || lines[0].GetText() != "c" || lines[1].GetText() != "d" {
		t.Errorf("lastLines = %v, %v, %v", lines, dropped, err)
	}
	lines, dropped, err = lastLines(strings.NewReader("a\n\nb"), 5)
	if err != nil || dropped || len(lines) != 3 || lines[1].GetText() != "" || lines[2].GetText() != "b" {
		t.Errorf("lastLines with a blank line and no final newline = %v, %v, %v", lines, dropped, err)
	}
	_, _, err = lastLines(&demux{r: strings.NewReader("\x07\x00\x00\x00\x00\x00\x00\x01x")}, 5)
	if err == nil || errors.Is(err, context.Canceled) {
		t.Errorf("malformed frame: %v, want an error", err)
	}
}
