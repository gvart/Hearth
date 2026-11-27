// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"

	"github.com/gvart/hearth/internal/policy"
	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
)

// hubRunner is a runner with flags local, locked or not, and the ceiling
// saved in dataDir.
func hubRunner(t *testing.T, dataDir string, local Ceiling, locked bool) *runner {
	t.Helper()
	hub, version, err := readCeilingFile(dataDir)
	if err != nil {
		hub, version = Ceiling{}, 0
	}
	return &runner{
		cfg: Config{DataDir: dataDir, Ceiling: local, LocalCeiling: locked}, log: slog.New(slog.DiscardHandler), id: &identity{deviceID: "d"},
		ceilings: newCeilings(local, hub, version, locked), ceilingChanged: make(chan struct{}, 1),
	}
}

func push(c *agentv1.Ceiling) *agentv1.CeilingConfig { return &agentv1.CeilingConfig{Ceiling: c} }

// TestOlderCeilingIgnored: a config older than the one applied, as a stale
// heartbeat push on the hub may send after a lowering, changes nothing, and
// still not after a restart, since the version is saved with the ceiling.
func TestOlderCeilingIgnored(t *testing.T) {
	dir := t.TempDir()
	r := hubRunner(t, dir, Ceiling{}, false)
	r.applyCeiling(t.Context(), &agentv1.CeilingConfig{Ceiling: &agentv1.Ceiling{Shell: true}, Version: 5})
	// The lowering.
	r.applyCeiling(t.Context(), &agentv1.CeilingConfig{Ceiling: &agentv1.Ceiling{}, Version: 6})
	if r.ceiling().Shell {
		t.Fatal("lowering not applied")
	}
	// The stale push that read version 5 before the lowering.
	if r.applyCeiling(t.Context(), &agentv1.CeilingConfig{Ceiling: &agentv1.Ceiling{Shell: true}, Version: 5}) || r.ceiling().Shell {
		t.Fatal("an older ceiling turned the shell back on")
	}
	restarted := hubRunner(t, dir, Ceiling{}, false)
	if restarted.ceilings.version != 6 {
		t.Fatalf("saved version %d, want 6", restarted.ceilings.version)
	}
	if restarted.applyCeiling(t.Context(), &agentv1.CeilingConfig{Ceiling: &agentv1.Ceiling{Shell: true}, Version: 5}) || restarted.ceiling().Shell {
		t.Fatal("after a restart, an older ceiling turned the shell back on")
	}
	// A newer one applies.
	if !restarted.applyCeiling(t.Context(), &agentv1.CeilingConfig{Ceiling: &agentv1.Ceiling{Shell: true}, Version: 7}) || !restarted.ceiling().Shell {
		t.Fatal("a newer ceiling was not applied")
	}
}

// TestApplyCeiling is the ceiling the hub sets: added to the flags, saved,
// reported at once; a lower one takes back only what the hub granted.
func TestApplyCeiling(t *testing.T) {
	dir := t.TempDir()
	r := hubRunner(t, dir, Ceiling{Logs: []string{"systemd:nginx.service"}, Probe: true}, false)
	if !r.applyCeiling(t.Context(), push(&agentv1.Ceiling{Logs: []string{"docker:*"}, DockerRead: true})) {
		t.Fatal("applyCeiling = false, want a change")
	}
	got := r.ceiling()
	if !slices.Equal(got.Logs, []string{"systemd:nginx.service", "docker:*"}) || !got.Probe || !got.DockerRead || got.Docker {
		t.Errorf("effective = %+v, want flags plus the hub's", got)
	}
	select {
	case <-r.ceilingChanged:
	default:
		t.Error("sendLoop not woken to report the new ceiling")
	}
	fi, err := os.Stat(filepath.Join(dir, CeilingFile))
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Errorf("%s mode %v, want 0600", CeilingFile, fi.Mode().Perm())
	}
	// A restart loads it before any hub connects.
	if again := hubRunner(t, dir, r.cfg.Ceiling, false).ceiling(); !again.equal(got) {
		t.Errorf("after restart %+v, want %+v", again, got)
	}
	// The same again changes nothing.
	if r.applyCeiling(t.Context(), push(&agentv1.Ceiling{Logs: []string{"docker:*"}, DockerRead: true})) {
		t.Error("the same ceiling again reported a change")
	}
	// Lowering keeps what the flags grant.
	if !r.applyCeiling(t.Context(), push(&agentv1.Ceiling{})) {
		t.Fatal("lowering reported no change")
	}
	if got := r.ceiling(); !got.equal(r.cfg.Ceiling) {
		t.Errorf("after lowering %+v, want the flags %+v", got, r.cfg.Ceiling)
	}
}

// TestApplyCeilingLocked is --local-ceiling: a push is ignored, and so is a
// saved ceiling.
func TestApplyCeilingLocked(t *testing.T) {
	dir := t.TempDir()
	if err := writeCeilingFile(dir, Ceiling{Shell: true, Exec: []string{"/bin/sh"}}, 0); err != nil {
		t.Fatal(err)
	}
	flags := Ceiling{Probe: true}
	r := hubRunner(t, dir, flags, true)
	if got := r.ceiling(); !got.equal(flags) {
		t.Fatalf("locked agent took the saved ceiling: %+v", got)
	}
	if r.applyCeiling(t.Context(), push(&agentv1.Ceiling{Shell: true, Docker: true})) {
		t.Error("locked agent applied a push")
	}
	if got := r.ceiling(); !got.equal(flags) {
		t.Errorf("locked agent's ceiling = %+v, want the flags", got)
	}
	if err := policy.ShellWithinCeiling(r.ceiling().proto()); err == nil {
		t.Error("locked agent allows a shell the hub pushed")
	}
	if h := r.hello(t.Context()); !h.GetCeilingLocked() || h.GetLocalCeiling().GetProbe() != true {
		t.Errorf("hello = locked %v local %v, want locked with the flags", h.GetCeilingLocked(), h.GetLocalCeiling())
	}
}

// TestApplyCeilingRefusesBadEntries checks the agent refuses a push with an
// entry it would refuse as a flag, whole, and keeps what it had.
func TestApplyCeilingRefusesBadEntries(t *testing.T) {
	for name, c := range map[string]*agentv1.Ceiling{
		"relative exec":   {Exec: []string{"df"}, Logs: []string{"docker:*"}},
		"bad log manager": {Logs: []string{"syslog:*"}},
		"bad restart":     {Restart: []string{"systemd"}},
		"bad pattern":     {Restart: []string{"systemd:["}},
		"bad scan":        {Scan: []string{"fe80::/64"}},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			r := hubRunner(t, dir, Ceiling{}, false)
			if r.applyCeiling(t.Context(), push(c)) {
				t.Error("a bad ceiling was applied")
			}
			if got := r.ceiling(); !got.equal(Ceiling{}) {
				t.Errorf("ceiling = %+v, want nothing", got)
			}
			if _, err := os.Stat(filepath.Join(dir, CeilingFile)); !os.IsNotExist(err) {
				t.Errorf("a bad ceiling was saved: %v", err)
			}
		})
	}
}

// TestCorruptCeilingFile is a saved ceiling that cannot be read: the agent
// falls back to its flags only.
func TestCorruptCeilingFile(t *testing.T) {
	for name, body := range map[string]string{
		"not json":  "{shell: true",
		"bad entry": `{"exec": ["sh"], "shell": true}`,
		"unknown":   `{"shell": true, "root": true}`,
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, CeilingFile), []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, _, err := readCeilingFile(dir); err == nil {
				t.Fatal("readCeilingFile accepted a corrupt file")
			}
			flags := Ceiling{Logs: []string{"systemd:*"}}
			if got := hubRunner(t, dir, flags, false).ceiling(); !got.equal(flags) {
				t.Errorf("ceiling = %+v, want the flags only", got)
			}
		})
	}
}

// TestAgentRefusesBeyondHubCeiling checks the agent enforces the effective
// ceiling itself, whatever the hub granted before or checked.
func TestAgentRefusesBeyondHubCeiling(t *testing.T) {
	r := hubRunner(t, t.TempDir(), Ceiling{}, false)
	r.applyCeiling(t.Context(), push(&agentv1.Ceiling{Exec: []string{"/usr/bin/df"}, Restart: []string{"docker:*"}, DockerRead: true}))
	c := r.ceiling()
	run := func(argv ...string) *agentv1.ExecRequest {
		return &agentv1.ExecRequest{Action: &agentv1.ExecRequest_Command{Command: &agentv1.Command{Argv: argv}}}
	}
	if res := c.execute(t.Context(), run("/bin/sh", "-c", "id")); !res.GetDenied() {
		t.Errorf("exec beyond the ceiling: %+v", res)
	}
	if _, err := c.command(&agentv1.ExecRequest{Action: &agentv1.ExecRequest_Restart{Restart: &agentv1.RestartService{Manager: "systemd", Name: "ssh.service"}}}); err == nil {
		t.Error("restart of another manager allowed")
	}
	if _, err := c.command(&agentv1.ExecRequest{Action: &agentv1.ExecRequest_Restart{Restart: &agentv1.RestartService{Manager: "docker", Name: "jellyfin"}}}); err != nil {
		t.Errorf("docker:* refused docker:jellyfin: %v", err)
	}
	// A requested name is never a glob, whatever the hub sent: the agent
	// refuses it before docker or systemctl could expand it.
	for _, name := range []string{"*", "jelly*", "web?"} {
		if _, err := c.command(&agentv1.ExecRequest{Action: &agentv1.ExecRequest_Restart{Restart: &agentv1.RestartService{Manager: "docker", Name: name}}}); err == nil {
			t.Errorf("restart docker:%s allowed by docker:*", name)
		}
	}
	r.applyCeiling(t.Context(), push(&agentv1.Ceiling{Restart: []string{"systemd:web?.service"}, Logs: []string{"systemd:web?.service"}}))
	if _, err := r.ceiling().command(&agentv1.ExecRequest{Action: &agentv1.ExecRequest_Restart{Restart: &agentv1.RestartService{Manager: "systemd", Name: "web*.service"}}}); err == nil {
		t.Error("restart systemd:web*.service allowed by systemd:web?.service")
	}
	if err := newLogStreams(r.ceiling(), r.log).check(&agentv1.LogSource{Manager: "systemd", Name: "web*.service"}); err == nil {
		t.Error("logs systemd:web*.service allowed by systemd:web?.service")
	}
	r.applyCeiling(t.Context(), push(&agentv1.Ceiling{Exec: []string{"/usr/bin/df"}, Restart: []string{"docker:*"}, DockerRead: true}))
	action := &agentv1.DockerRequest{Op: &agentv1.DockerRequest_Action{Action: &agentv1.DockerAction{Verb: "stop", Container: "jellyfin"}}}
	if err := policy.DockerWithinCeiling(c.proto(), action); err == nil {
		t.Error("docker read allows a stop")
	}
	if err := policy.ShellWithinCeiling(c.proto()); err == nil {
		t.Error("shell allowed without being granted")
	}
	// Lowered, what was granted is refused again.
	r.applyCeiling(t.Context(), push(&agentv1.Ceiling{}))
	if res := r.ceiling().execute(t.Context(), run("/usr/bin/df")); !res.GetDenied() {
		t.Errorf("exec after lowering: %+v", res)
	}
}
