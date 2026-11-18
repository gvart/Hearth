// SPDX-License-Identifier: AGPL-3.0-only

package agent_test

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/gvart/hearth/internal/agent"
	"github.com/gvart/hearth/internal/hub"
	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
)

func command(argv ...string) *agentv1.ExecRequest {
	return &agentv1.ExecRequest{Action: &agentv1.ExecRequest_Command{Command: &agentv1.Command{Argv: argv}}}
}

func restart(manager, name string) *agentv1.ExecRequest {
	return &agentv1.ExecRequest{Action: &agentv1.ExecRequest_Restart{
		Restart: &agentv1.RestartService{Manager: manager, Name: name},
	}}
}

func lookPath(t *testing.T, name string) string {
	t.Helper()
	p, err := exec.LookPath(name)
	if err != nil {
		t.Skipf("%s not found: %v", name, err)
	}
	return p
}

// TestExecOverStream sends exec requests from the hub to a real agent and
// checks the agent runs exactly what its ceiling allows.
func TestExecOverStream(t *testing.T) {
	truePath, falsePath, sh := lookPath(t, "true"), lookPath(t, "false"), lookPath(t, "sh")
	sleep := lookPath(t, "sleep")
	h := startRestartableHub(t, time.Second)
	id, dataDir := h.join(t)
	startAgentWith(t, agent.Config{DataDir: dataDir, Ceiling: agent.Ceiling{
		Exec:    []string{truePath, falsePath, sh, sleep},
		Restart: []string{"docker:hearth-test-no-such-container"},
	}})
	waitFor(t, 5*time.Second, "agent connected", func() bool {
		_, err := h.agents.Exec(t.Context(), id, command(truePath))
		return !errors.Is(err, hub.ErrAgentNotConnected)
	})

	tests := []struct {
		name       string
		device     string
		req        *agentv1.ExecRequest
		wantDenied bool
		wantExit   int32
		wantErr    string // substring of the result's error; "" means none
		// failed only checks the request failed, without being denied: how
		// depends on whether the host has docker.
		failed bool
	}{
		{name: "allowed command runs", device: id, req: command(truePath), wantExit: 0},
		{name: "device by hostname", device: "pi", req: command(truePath), wantExit: 0},
		{name: "failing command reports its exit", device: id, req: command(falsePath), wantExit: 1, wantErr: "exit status 1"},
		{
			name: "stderr tail is reported", device: id, req: command(sh, "-c", "echo oops >&2; exit 3"),
			wantExit: 3, wantErr: "exit status 3: oops",
		},
		{
			name: "program outside the ceiling is denied", device: id, req: command("/bin/echo", "hi"),
			wantDenied: true, wantExit: -1, wantErr: "capability ceiling",
		},
		{
			name: "same program by another path is denied", device: id, req: command("true"),
			wantDenied: true, wantExit: -1, wantErr: "capability ceiling",
		},
		{
			name: "restart outside the ceiling is denied", device: id, req: restart("systemd", "ssh.service"),
			wantDenied: true, wantExit: -1, wantErr: "capability ceiling",
		},
		{
			name: "restart under another manager is denied", device: id, req: restart("systemd", "hearth-test-no-such-container"),
			wantDenied: true, wantExit: -1, wantErr: "capability ceiling",
		},
		{name: "allowed restart runs and fails on a missing container", device: id, req: restart("docker", "hearth-test-no-such-container"), failed: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()
			res, err := h.agents.Exec(ctx, tt.device, tt.req)
			if err != nil {
				t.Fatalf("Exec: %v", err)
			}
			if res.GetDenied() != tt.wantDenied {
				t.Errorf("denied = %v, want %v (error %q)", res.GetDenied(), tt.wantDenied, res.GetError())
			}
			if tt.failed {
				if res.GetError() == "" {
					t.Error("request succeeded, want it to fail")
				}
				return
			}
			if tt.wantErr == "" && res.GetError() != "" || !strings.Contains(res.GetError(), tt.wantErr) {
				t.Errorf("error = %q, want it to contain %q", res.GetError(), tt.wantErr)
			}
			if res.GetExitCode() != tt.wantExit {
				t.Errorf("exit code = %d, want %d", res.GetExitCode(), tt.wantExit)
			}
		})
	}

	t.Run("timeout kills the process", func(t *testing.T) {
		req := command(sleep, "30")
		req.Timeout = durationpb.New(200 * time.Millisecond)
		start := time.Now()
		res, err := h.agents.Exec(t.Context(), id, req)
		if err != nil {
			t.Fatalf("Exec: %v", err)
		}
		if !strings.Contains(res.GetError(), "deadline exceeded") || time.Since(start) > 10*time.Second {
			t.Errorf("result = %+v after %v, want a timeout well before 30s", res, time.Since(start))
		}
	})

	t.Run("unknown device", func(t *testing.T) {
		if _, err := h.agents.Exec(t.Context(), "nope", command(truePath)); err == nil {
			t.Error("Exec on an unknown device succeeded")
		}
	})
}

// TestExecZeroCeiling checks an agent started without a ceiling runs nothing.
func TestExecZeroCeiling(t *testing.T) {
	truePath := lookPath(t, "true")
	h := startRestartableHub(t, time.Second)
	id, dataDir := h.join(t)
	startAgent(t, dataDir)
	var res *agentv1.ExecResult
	waitFor(t, 5*time.Second, "agent connected", func() bool {
		var err error
		res, err = h.agents.Exec(t.Context(), id, command(truePath))
		return err == nil
	})
	if !res.GetDenied() {
		t.Errorf("result = %+v, want denied", res)
	}
}

func TestParseRestart(t *testing.T) {
	for entry, ok := range map[string]bool{
		"systemd:pihole-FTL.service": true, "systemd-user:hearth.service": true, "docker:jellyfin": true,
		"docker:": false, "jellyfin": false, "podman:x": false, "": false,
	} {
		if err := agent.ParseRestart(entry); (err == nil) != ok {
			t.Errorf("ParseRestart(%q) = %v, want ok %v", entry, err, ok)
		}
	}
}
