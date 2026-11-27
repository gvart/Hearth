// SPDX-License-Identifier: AGPL-3.0-only

package mcpserver

import (
	"strings"
	"testing"

	"github.com/gvart/hearth/internal/policy"
)

func TestDockerTools(t *testing.T) {
	f := newFixture(t, policy.Config{})
	reader, safe := f.mustConnect(t, "reader-token"), f.mustConnect(t, "safe-token")

	text, isErr := call(t, reader, "list_containers", map[string]any{"device": "pi"})
	if isErr || !strings.Contains(text, `"project": "media"`) || !strings.Contains(text, `"nginx:latest"`) ||
		strings.Index(text, `"solo"`) > strings.Index(text, `"media-web-1"`) {
		t.Fatalf("list_containers = %q (error %v)", text, isErr)
	}
	e := f.lastAudit(t)
	if e.ActorKind != policy.ActorMCP || e.ActorID != "reader" || e.Action != string(policy.DeviceDockerList) || e.Target != "pi" || e.Decision != policy.Allow {
		t.Errorf("audit = %+v", e)
	}

	text, isErr = call(t, reader, "container_logs", map[string]any{"device": "pi", "container": "web", "tail": 5000})
	if isErr || !strings.Contains(text, "hello from web") {
		t.Fatalf("container_logs = %q (error %v)", text, isErr)
	}
	if got := f.agents.dockers[len(f.agents.dockers)-1].GetLogs().GetTail(); got != policy.MaxDockerLogTail {
		t.Errorf("tail sent = %d, want it capped at %d", got, policy.MaxDockerLogTail)
	}
	if e := f.lastAudit(t); e.Action != string(policy.DeviceDockerLogs) || !strings.Contains(string(e.Detail), `"container":"web"`) {
		t.Errorf("audit = %+v", e)
	}

	for _, verb := range []string{"start", "stop", "restart"} {
		text, isErr := call(t, safe, "container_action", map[string]any{"device": "pi", "container": "web", "action": verb})
		if isErr || !strings.Contains(text, "succeeded") {
			t.Errorf("%s = %q (error %v)", verb, text, isErr)
		}
		got := f.agents.dockers[len(f.agents.dockers)-1].GetAction()
		e := f.lastAudit(t)
		if got.GetVerb() != verb || got.GetContainer() != "web" || e.Action != "device.docker."+verb || e.ActorID != "safe" || e.Result != "ok" {
			t.Errorf("%s: sent %v, audit %+v", verb, got, e)
		}
	}
}

// Negative cases of the Docker tools: a refusal before policy sends nothing
// and audits nothing; a denial sends nothing and is audited as the token.
func TestDockerToolsRefused(t *testing.T) {
	denySafe := policy.Config{Actors: map[string]map[policy.Class]policy.Mode{policy.ActorMCP: {policy.Safe: policy.ModeDeny}}}
	denyRead := policy.Config{Actors: map[string]map[policy.Class]policy.Mode{policy.ActorMCP: {policy.Read: policy.ModeDeny}}}
	restart := map[string]any{"device": "pi", "container": "web", "action": "restart"}
	tests := []struct {
		name    string
		cfg     policy.Config
		ceiling error
		token   string
		tool    string
		args    map[string]any
		want    string
		audited string // the denial's reason in the audit log; empty: nothing audited
	}{
		{"policy denies an action", denySafe, nil, "safe-token", "container_action", restart, "denied", "denied by the policy configuration"},
		{"policy denies a read", denyRead, nil, "reader-token", "list_containers", map[string]any{"device": "pi"}, "denied", "denied by the policy configuration"},
		{"beyond the device ceiling", policy.Config{}, policy.ErrBeyondCeiling, "safe-token", "container_action", restart, "ceiling", "ceiling"},
		{"logs beyond the device ceiling", policy.Config{}, policy.ErrBeyondCeiling, "reader-token", "container_logs", map[string]any{"device": "pi", "container": "web"}, "ceiling", "ceiling"},
		{"a read token cannot act", policy.Config{}, nil, "reader-token", "container_action", restart, "unknown tool", ""},
		{"exec is no verb", policy.Config{}, nil, "safe-token", "container_action", map[string]any{"device": "pi", "container": "web", "action": "exec"}, "start, stop, restart", ""},
		{"a path is no container", policy.Config{}, nil, "safe-token", "container_action", map[string]any{"device": "pi", "container": "../../images/create", "action": "stop"}, "container", ""},
		{"a query is no container", policy.Config{}, nil, "reader-token", "container_logs", map[string]any{"device": "pi", "container": "web?follow=1"}, "container", ""},
		{"no device", policy.Config{}, nil, "reader-token", "list_containers", map[string]any{}, "device is required", ""},
		{"a negative tail", policy.Config{}, nil, "reader-token", "container_logs", map[string]any{"device": "pi", "container": "web", "tail": -1}, "tail", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t, tt.cfg)
			f.agents.check = tt.ceiling
			text, isErr := call(t, f.mustConnect(t, tt.token), tt.tool, tt.args)
			if !isErr || !strings.Contains(text, tt.want) {
				t.Fatalf("%s = %q, want an error with %q", tt.tool, text, tt.want)
			}
			if f.agents.dockerCount() != 0 {
				t.Fatal("a refused request reached the agent")
			}
			es, err := f.st.Audit().List(t.Context(), 10)
			if err != nil {
				t.Fatal(err)
			}
			if tt.audited == "" {
				if len(es) != 0 {
					t.Errorf("audit = %+v, want nothing", es)
				}
				return
			}
			if e := f.lastAudit(t); e.ActorKind != policy.ActorMCP || e.Decision != policy.Deny || !strings.Contains(e.Result, tt.audited) {
				t.Errorf("audit = %+v, want a denial for %q", e, tt.audited)
			}
		})
	}
}

// The engine's error, such as an unknown container, is a tool error,
// audited as the action's outcome.
func TestContainerActionEngineError(t *testing.T) {
	f := newFixture(t, policy.Config{})
	text, isErr := call(t, f.mustConnect(t, "safe-token"), "container_action", map[string]any{"device": "pi", "container": "gone", "action": "stop"})
	if !isErr || !strings.Contains(text, "No such container: gone") {
		t.Fatalf("stop gone = %q (error %v)", text, isErr)
	}
	if e := f.lastAudit(t); e.Action != string(policy.DeviceDockerStop) || e.Decision != policy.Allow || !strings.Contains(e.Result, "No such container") {
		t.Errorf("audit = %+v", e)
	}
}
