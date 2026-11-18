// SPDX-License-Identifier: AGPL-3.0-only

//go:build unix

package agent_test

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/agent"
	"github.com/gvart/hearth/internal/hub"
	"github.com/gvart/hearth/internal/policy"
	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
)

// fakeDocker puts a docker on PATH whose `logs` prints a timestamped line
// every 50 ms and writes its pid to the returned file.
func fakeDocker(t *testing.T) (pidFile string) {
	t.Helper()
	dir := t.TempDir()
	pidFile = filepath.Join(dir, "pid")
	script := "#!/bin/sh\necho $$ > '" + pidFile + "'\n" +
		"i=0; while :; do echo \"2024-05-01T10:00:00Z line $i\"; i=$((i+1)); sleep 0.05; done\n"
	if err := os.WriteFile(filepath.Join(dir, "docker"), []byte(script), 0o755); err != nil { //nolint:gosec // an executable test fake
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return pidFile
}

// alive reports whether the process in pidFile still runs.
func alive(t *testing.T, pidFile string) bool {
	t.Helper()
	b, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		t.Fatal(err)
	}
	return syscall.Kill(pid, 0) == nil
}

// TestLogsOverStream streams a container's log through a real agent: lines
// arrive within a second, the agent's process and every goroutine are gone
// once the hub closes the stream, and a source beyond the ceiling is never
// asked for.
func TestLogsOverStream(t *testing.T) {
	pidFile := fakeDocker(t)
	h := startRestartableHub(t, time.Second)
	id, dataDir := h.join(t)
	src := &agentv1.LogSource{Manager: "docker", Name: "web"}
	a := startAgentWith(t, agent.Config{DataDir: dataDir, Ceiling: agent.Ceiling{Logs: []string{"docker:web"}}})
	var err error
	waitFor(t, 5*time.Second, "agent connected", func() bool {
		err = h.agents.CheckLogs(t.Context(), id, src)
		return !errors.Is(err, hub.ErrAgentNotConnected)
	})
	if err != nil {
		t.Fatalf("CheckLogs = %v, want nil", err)
	}
	if err := h.agents.CheckLogs(t.Context(), id, &agentv1.LogSource{Manager: "docker", Name: "db"}); !errors.Is(err, policy.ErrBeyondCeiling) {
		t.Errorf("CheckLogs beyond the ceiling = %v, want ErrBeyondCeiling", err)
	}
	if _, err := h.agents.Logs(t.Context(), id, &agentv1.LogSource{Manager: "systemd", Name: "web"}, 10); !errors.Is(err, policy.ErrBeyondCeiling) {
		t.Errorf("Logs beyond the ceiling = %v, want ErrBeyondCeiling", err)
	}

	for round := range 2 {
		before := runtime.NumGoroutine()
		start := time.Now()
		stream, err := h.agents.Logs(t.Context(), id, src, 10)
		if err != nil {
			t.Fatal(err)
		}
		select {
		case <-stream.Ready():
			m := stream.Take()
			if len(m.GetLines()) == 0 || !strings.HasPrefix(m.GetLines()[0].GetText(), "line ") {
				t.Fatalf("first message = %v, want lines", m)
			}
			t.Logf("round %d: first line after %v", round, time.Since(start))
			if d := time.Since(start); d > time.Second {
				t.Errorf("first line after %v, want under 1s", d)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("no lines")
		}
		stream.Close()
		waitFor(t, 5*time.Second, "the agent's log process to stop", func() bool { return !alive(t, pidFile) })
		waitFor(t, 5*time.Second, "goroutines to end", func() bool { return runtime.NumGoroutine() <= before })
	}

	// The agent going away ends an open stream, and its process.
	stream, err := h.agents.Logs(t.Context(), id, src, 10)
	if err != nil {
		t.Fatal(err)
	}
	<-stream.Ready()
	a.stop(t)
	select {
	case <-stream.Disconnected():
	case <-time.After(5 * time.Second):
		t.Fatal("stream still open after the agent stopped")
	}
	stream.Close()
	waitFor(t, 5*time.Second, "the agent's log process to stop", func() bool { return !alive(t, pidFile) })
}
