// SPDX-License-Identifier: AGPL-3.0-only

package plugins

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

func TestPluginDiscoversAndRunsCommands(t *testing.T) {
	m, audit := startManager(t, policy.Config{}, helperManifest(t, "good", "good"))
	waitFor(t, "the plugin's devices", func() bool { return commandsRun(m, "good") == "0" })
	s := status(m, "good")
	if s.State != StateRunning || s.StartedAt == nil || s.Restarts != 0 {
		t.Fatalf("status = %+v, want running", s)
	}

	res, err := m.Command(t.Context(), policy.ActorWeb, "10.0.0.1", "good",
		CommandRequest{Command: "toggle", Device: "lamp", Args: json.RawMessage(`{"on":true}`)})
	if err != nil {
		t.Fatal(err)
	}
	if res.Output != "toggle lamp" {
		t.Errorf("output = %q", res.Output)
	}
	waitFor(t, "the pushed state", func() bool { return commandsRun(m, "good") == "1" })

	starts := audit.find(string(policy.PluginStart), policy.Allow)
	if len(starts) == 0 || starts[0].Target != "good" || starts[0].ActorKind != policy.ActorHub {
		t.Errorf("plugin.start entries = %+v", starts)
	}
	cmds := audit.find(string(policy.PluginCommandSafe), policy.Allow)
	if len(cmds) != 2 || cmds[1].Result != "ok" || cmds[0].Target != "good/toggle" {
		t.Fatalf("plugin.command.safe entries = %+v", cmds)
	}
	if strings.Contains(string(cmds[0].Detail), `"on"`) {
		t.Errorf("audit detail holds the command's args: %s", cmds[0].Detail)
	}

	_, err = m.Command(t.Context(), policy.ActorWeb, "10.0.0.1", "good", CommandRequest{Command: "fail"})
	if !errors.Is(err, ErrCommandFailed) || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("failing command: err = %v", err)
	}
	if e := audit.find(string(policy.PluginCommandRead), policy.Allow); len(e) != 2 || !strings.Contains(e[1].Result, "boom") {
		t.Errorf("plugin.command.read entries = %+v", e)
	}
}

func TestCommandsWithoutPolicyAllowAreDeniedAndAudited(t *testing.T) {
	tests := []struct {
		name      string
		cfg       policy.Config
		actorKind string
		command   string
		action    policy.Action
	}{
		{"undeclared command", policy.Config{}, policy.ActorWeb, "format-disk", policy.PluginCommandDangerous},
		{
			"class denied by the policy configuration",
			policy.Config{Actors: map[string]map[policy.Class]policy.Mode{policy.ActorWeb: {policy.Safe: policy.ModeDeny}}},
			policy.ActorWeb, "toggle", policy.PluginCommandSafe,
		},
		{
			"dangerous denied for every actor",
			policy.Config{Classes: map[policy.Class]policy.Mode{policy.Dangerous: policy.ModeDeny}},
			policy.ActorWeb, "wipe", policy.PluginCommandDangerous,
		},
		{"actor kind not admitted", policy.Config{}, policy.ActorAutomation, "toggle", policy.PluginCommandSafe},
		{
			"confirm without approvals",
			policy.Config{Classes: map[policy.Class]policy.Mode{policy.Safe: policy.ModeConfirm}},
			policy.ActorWeb, "toggle", policy.PluginCommandSafe,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, audit := startManager(t, tt.cfg, helperManifest(t, "p", "good"))
			waitFor(t, "the plugin's devices", func() bool { return commandsRun(m, "p") == "0" })
			_, err := m.Command(t.Context(), tt.actorKind, "someone", "p", CommandRequest{Command: tt.command, Device: "lamp"})
			if !errors.Is(err, policy.ErrDenied) {
				t.Fatalf("err = %v, want ErrDenied", err)
			}
			denied := audit.find(string(tt.action), policy.Deny)
			if len(denied) != 1 || denied[0].Target != "p/"+tt.command {
				t.Fatalf("denied entries of %s = %+v", tt.action, denied)
			}
			if allowed := audit.find(string(tt.action), policy.Allow); len(allowed) != 0 {
				t.Errorf("allowed entries = %+v", allowed)
			}
			// A command the plugin got would have changed this; wait for a
			// discover round trip so that it would have arrived.
			time.Sleep(100 * time.Millisecond)
			if got := commandsRun(m, "p"); got != "0" {
				t.Errorf("the plugin got the denied command: commands run = %s", got)
			}
		})
	}
}

func TestCommandErrors(t *testing.T) {
	m, audit := startManager(t, policy.Config{}, helperManifest(t, "p", "good"))
	waitFor(t, "the plugin's devices", func() bool { return commandsRun(m, "p") == "0" })
	for _, tt := range []struct {
		name, plugin string
		req          CommandRequest
		want         error
	}{
		{"unknown plugin", "nope", CommandRequest{Command: "toggle"}, ErrNotFound},
		{"bad command name", "p", CommandRequest{Command: "../x"}, ErrBadRequest},
		{"bad device", "p", CommandRequest{Command: "toggle", Device: "a b"}, ErrBadRequest},
		{"args not an object", "p", CommandRequest{Command: "toggle", Args: json.RawMessage(`[1]`)}, ErrBadRequest},
		{"args too large", "p", CommandRequest{Command: "toggle", Args: json.RawMessage(`{"a":"` + strings.Repeat("x", maxArgs) + `"}`)}, ErrBadRequest},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := m.Command(t.Context(), policy.ActorWeb, "x", tt.plugin, tt.req); !errors.Is(err, tt.want) {
				t.Fatalf("err = %v, want %v", err, tt.want)
			}
		})
	}
	audit.mu.Lock()
	defer audit.mu.Unlock()
	for _, e := range audit.entries {
		if strings.HasPrefix(e.Action, "plugin.command") {
			t.Errorf("a malformed request was decided: %+v", e)
		}
	}
}

// TestMisbehavingPluginIsContained runs a plugin that crashes, hangs or
// prints garbage next to a good one: the bad one is restarted with backoff,
// the good one keeps answering, and Run keeps running.
func TestMisbehavingPluginIsContained(t *testing.T) {
	tests := []struct{ mode, wantErr string }{
		{"crash", "plugin process: exit status 3"},
		{"hang", "no reply in time"},
		{"silent", "no hello within"},
		{"junk", "a line is not a JSON message"},
		{"huge", "a line is longer than 65536 bytes"},
		{"flood", "more than 100 lines a second"},
		{"badhello", `plugin says it is "someone-else"`},
	}
	for _, tt := range tests {
		t.Run(tt.mode, func(t *testing.T) {
			m, _ := startManager(t, policy.Config{}, helperManifest(t, "bad", tt.mode), helperManifest(t, "good", "good"))
			var last Status
			waitFor(t, "two restarts of the bad plugin", func() bool {
				last = status(m, "bad")
				return last.Restarts >= 2
			})
			if !strings.Contains(last.Error, tt.wantErr) {
				// The error of a restart may be the next attempt's; look
				// again at a later one.
				waitFor(t, "the expected error", func() bool {
					last = status(m, "bad")
					return strings.Contains(last.Error, tt.wantErr)
				})
			}
			if tt.mode == "crash" && !strings.Contains(strings.Join(last.Stderr, "\n"), "about to crash") {
				t.Errorf("stderr tail = %q", last.Stderr)
			}
			waitFor(t, "the good plugin", func() bool { return status(m, "good").State == StateRunning })
			if _, err := m.Command(t.Context(), policy.ActorWeb, "x", "good", CommandRequest{Command: "toggle"}); err != nil {
				t.Fatalf("good plugin's command: %v", err)
			}
			if s := status(m, "good"); s.Restarts != 0 {
				t.Errorf("good plugin restarted: %+v", s)
			}
		})
	}
}

func TestCommandToStoppedPluginFailsFast(t *testing.T) {
	m, audit := startManager(t, policy.Config{}, helperManifest(t, "bad", "crash"))
	waitFor(t, "a restart", func() bool { return status(m, "bad").Restarts >= 1 })
	start := time.Now()
	_, err := m.Command(t.Context(), policy.ActorWeb, "x", "bad", CommandRequest{Command: "toggle"})
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v, want ErrUnavailable", err)
	}
	if d := time.Since(start); d > time.Second {
		t.Errorf("took %s", d)
	}
	if e := audit.find(string(policy.PluginCommandSafe), policy.Allow); len(e) != 2 || !strings.HasPrefix(e[1].Result, "error:") {
		t.Errorf("entries = %+v", e)
	}
}

func TestBackoffGrows(t *testing.T) {
	audit := &memAudit{}
	o := fastOptions
	o.BackoffMin, o.BackoffMax = 50*time.Millisecond, 200*time.Millisecond
	m, err := New(Config{Manifests: []Manifest{helperManifest(t, "bad", "crash")}, Policy: policy.New(audit), Options: o})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 700*time.Millisecond)
	defer cancel()
	_ = m.Run(ctx)
	// 50+100+200+200ms of backoff fit in 700ms with the starts: at most 5
	// starts, against dozens without backoff.
	if n := len(audit.find(string(policy.PluginStart), policy.Allow)); n < 4 || n > 12 {
		t.Errorf("%d start entries (two per start)", n)
	}
	if s := status(m, "bad"); s.State != StateStopped {
		t.Errorf("state after Run = %s", s.State)
	}
}

func TestStartRefusedWhenNotAudited(t *testing.T) {
	m, err := New(Config{
		Manifests: []Manifest{helperManifest(t, "p", "good")},
		Policy:    policy.New(failAudit{}), Options: fastOptions,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
	defer cancel()
	go func() { _ = m.Run(ctx) }()
	waitFor(t, "a refused start", func() bool { return strings.Contains(status(m, "p").Error, "audit") })
	if s := status(m, "p"); s.State == StateRunning {
		t.Errorf("plugin runs unaudited: %+v", s)
	}
	<-ctx.Done()
}

type failAudit struct{}

func (failAudit) Append(context.Context, store.AuditEntry) (int64, error) {
	return 0, errors.New("store down")
}

func TestPluginEnvironmentIsClean(t *testing.T) {
	t.Setenv("HEARTH_SECRET_FOR_TEST", "leak")
	p := &plugin{m: Manifest{Name: "p", Env: map[string]string{"B": "2", "A": "1"}}}
	env := strings.Join(p.env(), "\n")
	if strings.Contains(env, "leak") {
		t.Errorf("hub environment leaked: %s", env)
	}
	if !strings.Contains(env, "HEARTH_PLUGIN=p\nA=1\nB=2") {
		t.Errorf("env = %s", env)
	}
}

func TestLoadManifest(t *testing.T) {
	write := func(t *testing.T, body string, mode os.FileMode) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "plugin.yaml")
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		return path
	}
	good := "protocol: 1\nname: lamp\nversion: 1.0.0\ncommand: ./lamp\ncapabilities: [discover, command]\n" +
		"commands:\n  - {name: turn_on, class: safe}\n"
	m, err := LoadManifest(write(t, good, 0o644))
	if err != nil {
		t.Fatal(err)
	}
	if m.Name != "lamp" || m.Dir == "" || len(m.Commands) != 1 || m.Commands[0].Class != policy.Safe {
		t.Errorf("manifest = %+v", m)
	}
	for _, tt := range []struct{ name, body, want string }{
		{"wrong protocol", strings.Replace(good, "protocol: 1", "protocol: 2", 1), "protocol must be 1"},
		{"bad name", strings.Replace(good, "name: lamp", "name: ../lamp", 1), "name"},
		{"no command", strings.Replace(good, "command: ./lamp\n", "", 1), "command is required"},
		{"bad class", strings.Replace(good, "class: safe", "class: harmless", 1), `class "harmless"`},
		{"commands without capability", strings.Replace(good, "[discover, command]", "[discover]", 1), "command capability"},
		{"unknown capability", strings.Replace(good, "[discover, command]", "[discover, command, root]", 1), `unknown "root"`},
		{"reserved env", good + "env: {PATH: /tmp}\n", "reserved"},
		{"unknown field", good + "shell: true\n", "field shell not found"},
		{"duplicate command", strings.Replace(good, "safe}\n", "safe}\n  - {name: turn_on, class: read}\n", 1), "declared twice"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := LoadManifest(write(t, tt.body, 0o644))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want %q", err, tt.want)
			}
		})
	}
	t.Run("writable by others", func(t *testing.T) {
		if _, err := LoadManifest(write(t, good, 0o666)); err == nil || !strings.Contains(err.Error(), "writable") {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestNewRefusesDuplicatePlugins(t *testing.T) {
	_, err := New(Config{Manifests: []Manifest{helperManifest(t, "p", "good"), helperManifest(t, "p", "good")}})
	if err == nil {
		t.Fatal("no error")
	}
}
