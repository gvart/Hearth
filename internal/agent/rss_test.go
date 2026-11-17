// SPDX-License-Identifier: AGPL-3.0-only

package agent_test

import (
	"bufio"
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/hub"
)

const (
	rssIdle  = 60 * time.Second
	rssLimit = 20 << 20 // bytes; CLAUDE.md: the agent idles under 20 MB RSS
)

// TestAgentIdleRSS builds the release binary, runs `hearth agent run` against a
// test hub for a minute and checks its resident memory stays under 20 MB.
func TestAgentIdleRSS(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("reads /proc; Linux only")
	}
	if testing.Short() {
		t.Skip("takes over a minute")
	}
	t.Parallel()

	bin := filepath.Join(t.TempDir(), "hearth")
	build := exec.CommandContext(t.Context(), "go", "build", "-trimpath", "-ldflags", "-s -w", "-o", bin, "github.com/gvart/hearth/cmd/hearth")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}

	h := startRestartableHub(t, hub.DefaultHeartbeatInterval)
	id, dataDir := h.join(t)

	var stderr bytes.Buffer
	cmd := exec.CommandContext(t.Context(), bin, "agent", "run", "--data-dir", dataDir)
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 10*time.Second, "agent to connect", func() bool {
		return strings.Contains(h.logs.String(), `msg="agent connected" device_id=`+id)
	})

	time.Sleep(rssIdle)
	status, err := os.ReadFile("/proc/" + strconv.Itoa(cmd.Process.Pid) + "/status")
	if err != nil {
		t.Fatal(err)
	}
	rss, peak := procKB(t, status, "VmRSS"), procKB(t, status, "VmHWM")
	t.Logf("agent after %v idle: VmRSS %d kB, VmHWM %d kB", rssIdle, rss, peak)
	if rss*1024 >= rssLimit {
		t.Errorf("idle RSS %d kB, want < %d kB", rss, rssLimit/1024)
	}

	if err := cmd.Process.Signal(os.Interrupt); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("agent exited with %v after SIGINT:\n%s", err, stderr.String())
		}
	case <-time.After(5 * time.Second):
		t.Errorf("agent did not exit within 5s of SIGINT")
	}
}

// procKB returns a "Key:   123 kB" field of /proc/<pid>/status.
func procKB(t *testing.T, status []byte, key string) int {
	t.Helper()
	sc := bufio.NewScanner(bytes.NewReader(status))
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), ":")
		if !ok || k != key {
			continue
		}
		n, err := strconv.Atoi(strings.TrimSuffix(strings.TrimSpace(v), " kB"))
		if err != nil {
			t.Fatalf("parse %s: %v", key, err)
		}
		return n
	}
	t.Fatalf("%s not in /proc status", key)
	return 0
}
