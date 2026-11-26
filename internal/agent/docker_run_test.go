// SPDX-License-Identifier: AGPL-3.0-only

package agent_test

import (
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/agent"
	"github.com/gvart/hearth/internal/hub"
	"github.com/gvart/hearth/internal/policy"
	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
)

// startEngine serves a minimal Docker Engine API on a unix socket and
// counts the requests it gets.
func startEngine(t *testing.T, hits *atomic.Int32) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "hd") // short: a unix socket path is at most 104 bytes on macOS
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "d.sock")
	mux := http.NewServeMux()
	mux.HandleFunc("GET /containers/json", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`[{"Id":"c1","Names":["/web"],"Image":"nginx","State":"running","Status":"Up","Labels":{"com.docker.compose.project":"media"}}]`))
	})
	mux.HandleFunc("GET /images/json", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`[]`)) })
	mux.HandleFunc("POST /containers/web/restart", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		mux.ServeHTTP(w, r)
	}), ReadHeaderTimeout: time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return sock
}

func listRequest() *agentv1.DockerRequest {
	return &agentv1.DockerRequest{Op: &agentv1.DockerRequest_List{List: &agentv1.DockerList{}}}
}

// A hub reaches a device's engine through its agent started with
// --allow-docker.
func TestRunDocker(t *testing.T) {
	h := startRestartableHub(t, time.Minute)
	id, dataDir := h.join(t)
	var hits atomic.Int32
	sock := startEngine(t, &hits)
	a := startAgentWith(t, agent.Config{DataDir: dataDir, Ceiling: agent.Ceiling{Docker: true}, DockerSocket: "unix://" + sock})
	defer a.stop(t)

	var res *agentv1.DockerResult
	var err error
	waitFor(t, 10*time.Second, "the agent", func() bool {
		res, err = h.agents.Docker(t.Context(), id, listRequest(), 5*time.Second)
		return !errors.Is(err, hub.ErrAgentNotConnected)
	})
	if err != nil || res.GetError() != "" || len(res.GetContainers()) != 1 || res.GetContainers()[0].GetComposeProject() != "media" {
		t.Fatalf("list = %v, %v", res, err)
	}
	restart := &agentv1.DockerRequest{Op: &agentv1.DockerRequest_Action{Action: &agentv1.DockerAction{Verb: "restart", Container: "web"}}}
	if res, err := h.agents.Docker(t.Context(), id, restart, 5*time.Second); err != nil || res.GetError() != "" {
		t.Errorf("restart = %v, %v", res, err)
	}
	if n := hits.Load(); n != 3 {
		t.Errorf("the engine got %d requests, want 3", n)
	}
}

// Without --allow-docker the hub refuses to send a Docker request, and the
// engine is never reached.
func TestRunDockerWithoutTheCeiling(t *testing.T) {
	h := startRestartableHub(t, time.Minute)
	id, dataDir := h.join(t)
	var hits atomic.Int32
	sock := startEngine(t, &hits)
	a := startAgentWith(t, agent.Config{
		DataDir: dataDir, DockerSocket: sock,
		Ceiling: agent.Ceiling{Logs: []string{"docker:*"}, Restart: []string{"docker:web"}},
	})
	defer a.stop(t)

	var err error
	waitFor(t, 10*time.Second, "the agent", func() bool {
		_, err = h.agents.Docker(t.Context(), id, listRequest(), 5*time.Second)
		return !errors.Is(err, hub.ErrAgentNotConnected)
	})
	if !errors.Is(err, policy.ErrBeyondCeiling) || !strings.Contains(err.Error(), "turn Containers on") {
		t.Errorf("list = %v, want beyond the ceiling", err)
	}
	if n := hits.Load(); n != 0 {
		t.Errorf("the engine got %d requests, want none", n)
	}
}
