// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"slices"
	"testing"

	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
)

// TestCeilingCommand checks the agent enforces its ceiling itself, whatever
// the hub sends: the hub checks first, but the agent never relies on it.
func TestCeilingCommand(t *testing.T) {
	c := Ceiling{Exec: []string{"/usr/bin/df"}, Restart: []string{"docker:jellyfin", "systemd:pihole-FTL.service"}}
	cmd := func(argv ...string) *agentv1.ExecRequest {
		return &agentv1.ExecRequest{Action: &agentv1.ExecRequest_Command{Command: &agentv1.Command{Argv: argv}}}
	}
	restart := func(m, n string) *agentv1.ExecRequest {
		return &agentv1.ExecRequest{Action: &agentv1.ExecRequest_Restart{Restart: &agentv1.RestartService{Manager: m, Name: n}}}
	}
	tests := []struct {
		name       string
		ceiling    Ceiling
		req        *agentv1.ExecRequest
		want       []string
		wantDenied bool
	}{
		{"allowed exec", c, cmd("/usr/bin/df", "-h"), []string{"/usr/bin/df", "-h"}, false},
		{"allowed docker restart", c, restart("docker", "jellyfin"), []string{"docker", "restart", "--", "jellyfin"}, false},
		{
			"allowed systemd restart", c, restart("systemd", "pihole-FTL.service"),
			[]string{"systemctl", "restart", "--", "pihole-FTL.service"},
			false,
		},
		{"exec beyond", c, cmd("/bin/sh", "-c", "id"), nil, true},
		{"exec by bare name", c, cmd("df"), nil, true},
		{"restart beyond", c, restart("docker", "pihole"), nil, true},
		{"restart, other manager", c, restart("systemd-user", "jellyfin"), nil, true},
		{"zero ceiling", Ceiling{}, cmd("/usr/bin/df"), nil, true},
		{"empty command", c, cmd(), nil, false},
		{"no action", c, &agentv1.ExecRequest{}, nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.ceiling.command(tt.req)
			if tt.want != nil {
				if err != nil || !slices.Equal(got, tt.want) {
					t.Fatalf("command = %q, %v; want %q", got, err, tt.want)
				}
				return
			}
			if err == nil {
				t.Fatalf("command = %q, want refused", got)
			}
			res := tt.ceiling.execute(t.Context(), tt.req)
			if res.GetDenied() != tt.wantDenied || res.GetExitCode() != -1 {
				t.Errorf("execute = %+v, want denied %v and nothing run", res, tt.wantDenied)
			}
		})
	}
}

func TestCeilingReported(t *testing.T) {
	c := Ceiling{Exec: []string{"/usr/bin/df"}, Restart: []string{"docker:jellyfin"}}
	p := c.proto()
	if !slices.Equal(p.GetExec(), c.Exec) || !slices.Equal(p.GetRestart(), c.Restart) {
		t.Errorf("proto = %v", p)
	}
	if p := (Ceiling{}).proto(); p == nil || len(p.GetExec())+len(p.GetRestart()) != 0 {
		t.Errorf("zero ceiling reported as %v, want an empty, non-nil ceiling", p)
	}
}
