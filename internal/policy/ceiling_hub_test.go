// SPDX-License-Identifier: AGPL-3.0-only

package policy

import (
	"errors"
	"testing"

	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
)

// TestRestartGlob is a restart entry with a pattern, as "on" sets it: every
// service of that manager, no other manager's.
func TestRestartGlob(t *testing.T) {
	c := &agentv1.Ceiling{Restart: []string{"docker:*", "systemd:pihole-*"}}
	restart := func(m, n string) *agentv1.ExecRequest {
		return &agentv1.ExecRequest{Action: &agentv1.ExecRequest_Restart{Restart: &agentv1.RestartService{Manager: m, Name: n}}}
	}
	for _, tt := range []struct {
		m, n string
		ok   bool
	}{
		{"docker", "jellyfin", true},
		{"systemd", "pihole-FTL.service", true},
		{"systemd", "ssh.service", false},
		{"systemd-user", "jellyfin", false},
		{"docker", "", false},
		{"docker", "a/b", false},
	} {
		err := WithinCeiling(c, restart(tt.m, tt.n))
		if (err == nil) != tt.ok || (err != nil && !errors.Is(err, ErrBeyondCeiling)) {
			t.Errorf("restart %s:%s = %v, want allowed %v", tt.m, tt.n, err, tt.ok)
		}
	}
	if !IsPattern("docker:*") || IsPattern("docker:jellyfin") {
		t.Error("IsPattern")
	}
}

// TestDockerRead is Docker read only: lists and logs, no start, stop or
// restart.
func TestDockerRead(t *testing.T) {
	read := &agentv1.Ceiling{DockerRead: true}
	list := &agentv1.DockerRequest{Op: &agentv1.DockerRequest_List{List: &agentv1.DockerList{}}}
	logs := &agentv1.DockerRequest{Op: &agentv1.DockerRequest_Logs{Logs: &agentv1.DockerLogs{Container: "web"}}}
	stop := &agentv1.DockerRequest{Op: &agentv1.DockerRequest_Action{Action: &agentv1.DockerAction{Verb: "stop", Container: "web"}}}
	if err := DockerWithinCeiling(read, list); err != nil {
		t.Errorf("list: %v", err)
	}
	if err := DockerWithinCeiling(read, logs); err != nil {
		t.Errorf("logs: %v", err)
	}
	if err := DockerWithinCeiling(read, stop); !errors.Is(err, ErrBeyondCeiling) {
		t.Errorf("stop with read only = %v, want beyond the ceiling", err)
	}
	if err := DockerWithinCeiling(&agentv1.Ceiling{Docker: true}, stop); err != nil {
		t.Errorf("stop with docker: %v", err)
	}
}
