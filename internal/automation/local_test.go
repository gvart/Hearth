// SPDX-License-Identifier: AGPL-3.0-only

package automation

import (
	"errors"
	"log/slog"
	"maps"
	"strings"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/policy"
	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
)

// localKinds are the kinds a hub loads automations with, probes from pr.
func localKinds(pr Probers) Kinds {
	kinds := Builtin(slog.New(slog.DiscardHandler))
	maps.Copy(kinds.Triggers, Triggers(TriggerDeps{Probers: pr}))
	maps.Copy(kinds.Actions, Actions(ActionDeps{Probers: pr}))
	return kinds
}

const localDNSWatchdog = `id: dns-watchdog
local: true
triggers:
  - id: dns-down
    type: dns
    name: example.com
    server: 127.0.0.1
    from: pi4
    every: 5s
    for: 15s
  - id: web-down
    type: http
    url: http://127.0.0.1/admin?token=secret
    from: pi4
actions:
  - id: restart-dns
    type: restart
    device: pi4
    service: systemd:pihole-FTL.service
    timeout: 30s
  - id: verify
    type: check
    check: tcp
    address: 127.0.0.1:53
    from: pi4
    timeout: 2s
`

func TestLocalAutomationLoads(t *testing.T) {
	a, err := Parse("dns.yaml", []byte(localDNSWatchdog), localKinds(nil))
	if err != nil {
		t.Fatal(err)
	}
	if !a.Local || a.LocalDevice() != "pi4" {
		t.Fatalf("Local = %v, LocalDevice = %q; want true, pi4", a.Local, a.LocalDevice())
	}
	r, err := a.LocalRule()
	if err != nil {
		t.Fatal(err)
	}
	if r.GetId() != "dns-watchdog" || len(r.GetDigest()) != 64 {
		t.Errorf("rule id %q digest %q", r.GetId(), r.GetDigest())
	}
	if len(r.GetTriggers()) != 2 || len(r.GetActions()) != 2 {
		t.Fatalf("rule has %d triggers and %d actions, want 2 and 2", len(r.GetTriggers()), len(r.GetActions()))
	}
	dns := r.GetTriggers()[0]
	if dns.GetId() != "dns-down" || dns.GetType() != "dns" || dns.GetEvery().AsDuration() != 5*time.Second ||
		dns.GetHold().AsDuration() != 15*time.Second || dns.GetProbe().GetDns().GetServer() != "127.0.0.1:53" ||
		dns.GetProbe().GetTimeout().AsDuration() != 5*time.Second {
		t.Errorf("dns trigger = %v", dns)
	}
	web := r.GetTriggers()[1]
	// The probe carries the URL as written; the target shown never does.
	if !strings.Contains(web.GetProbe().GetHttp().GetUrl(), "secret") || strings.Contains(web.GetTarget(), "secret") {
		t.Errorf("http trigger: url %q target %q", web.GetProbe().GetHttp().GetUrl(), web.GetTarget())
	}
	restart := r.GetActions()[0]
	if restart.GetRestart().GetManager() != "systemd" || restart.GetRestart().GetName() != "pihole-FTL.service" ||
		restart.GetTimeout().AsDuration() != 30*time.Second {
		t.Errorf("restart action = %v", restart)
	}
	check := r.GetActions()[1]
	if check.GetType() != "check" || check.GetCheck().GetTcp().GetAddress() != "127.0.0.1:53" ||
		check.GetTimeout().AsDuration() != 2*time.Second {
		t.Errorf("check action = %v", check)
	}
}

// TestLocalAutomationRefused covers what a device cannot run alone: each is
// refused when the file loads, so a save from the editor is refused too.
func TestLocalAutomationRefused(t *testing.T) {
	trigger := "triggers:\n  - type: tcp\n    address: 127.0.0.1:53\n    from: pi4\n"
	restart := "actions:\n  - type: restart\n    device: pi4\n    service: systemd:dns.service\n"
	tests := []struct {
		name, src, want string
	}{
		{
			"hub check", "id: a\nlocal: true\ntriggers:\n  - type: tcp\n    address: 127.0.0.1:53\n" + restart,
			"triggers must be http, tcp or dns checks with from",
		},
		{
			"schedule trigger", "id: a\nlocal: true\ntriggers:\n  - type: schedule\n    cron: '@hourly'\n" + restart,
			"triggers must be http, tcp or dns checks with from",
		},
		{
			"two devices", "id: a\nlocal: true\n" + trigger + "  - type: tcp\n    address: 127.0.0.1:80\n    from: pi5\n" + restart,
			"must run from the same device (pi4, not pi5)",
		},
		{
			"restart elsewhere", "id: a\nlocal: true\n" + trigger + "actions:\n  - type: restart\n    device: nas\n    service: systemd:dns.service\n",
			"device must be pi4",
		},
		{
			"templated device", "id: a\nlocal: true\n" + trigger + "actions:\n  - type: restart\n    device: '{{ .Trigger.Target }}'\n    service: systemd:dns.service\n",
			"device must be pi4",
		},
		{
			"exec", "id: a\nlocal: true\n" + trigger + "actions:\n  - type: exec\n    device: pi4\n    command: [/bin/true]\n",
			"not exec",
		},
		{
			"webhook", "id: a\nlocal: true\n" + trigger + "actions:\n  - type: webhook\n    url: https://ntfy.sh/x\n",
			"not webhook",
		},
		{
			"log", "id: a\nlocal: true\n" + trigger + "actions:\n  - type: log\n    message: hi\n",
			"not log",
		},
		{
			"check from the hub", "id: a\nlocal: true\n" + trigger + "actions:\n  - type: check\n    check: tcp\n    address: 127.0.0.1:53\n",
			"from must be pi4",
		},
		{"queued", "id: a\nlocal: true\nmode: queued\n" + trigger + restart, "mode must be single"},
		{"not a bool", "id: a\nlocal: yes please\n" + trigger + restart, "local must be true or false"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse("a.yaml", []byte(tt.src), localKinds(nil))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Parse = %v, want an error containing %q", err, tt.want)
			}
		})
	}
	// Without local: true the same restart elsewhere is fine.
	src := "id: a\n" + trigger + "actions:\n  - type: restart\n    device: nas\n    service: systemd:dns.service\n"
	if _, err := Parse("a.yaml", []byte(src), localKinds(nil)); err != nil {
		t.Fatalf("Parse without local = %v", err)
	}
}

func TestCheckActionRefusesTriggerFields(t *testing.T) {
	for _, field := range []string{"every: 5s", "for: 5s"} {
		src := "id: a\ntriggers:\n  - type: manual\nactions:\n  - type: check\n    check: tcp\n    address: 127.0.0.1:53\n    " + field + "\n"
		if _, err := Parse("a.yaml", []byte(src), localKinds(nil)); err == nil || !strings.Contains(err.Error(), "runs once") {
			t.Errorf("%s: Parse = %v, want refused", field, err)
		}
	}
	src := "id: a\ntriggers:\n  - type: manual\nactions:\n  - type: check\n"
	if _, err := Parse("a.yaml", []byte(src), localKinds(nil)); err == nil || !strings.Contains(err.Error(), "check is required") {
		t.Errorf("no check: Parse = %v", err)
	}
	for src, want := range map[string]string{
		"check: icmp\n    address: 127.0.0.1:53\n": "must be http, tcp or dns",
		"check: tcp\n    url: http://x/\n":         `unknown field "url"`,
	} {
		src = "id: a\ntriggers:\n  - type: manual\nactions:\n  - type: check\n    " + src
		if _, err := Parse("a.yaml", []byte(src), localKinds(nil)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("Parse(%q) = %v, want %q", src, err, want)
		}
	}
}

func TestCheckActionRuns(t *testing.T) {
	tests := []struct {
		name    string
		answer  func() (*agentv1.ProbeResult, error)
		wantErr string
	}{
		{"passes", up, ""},
		{"fails", down, "failed: connection refused"},
		{"offline", offline, "cannot run from device pi"},
		{"beyond the ceiling", denied, "cannot run from device pi"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pr := &fakeProbers{answer: tt.answer}
			src := "id: a\ntriggers:\n  - type: manual\nactions:\n  - type: check\n    check: tcp\n    address: 127.0.0.1:53\n    from: pi\n"
			a, err := Parse("a.yaml", []byte(src), localKinds(pr))
			if err != nil {
				t.Fatal(err)
			}
			act := a.Actions[0].Impl
			if act.Policy() != policy.AutomationProbe || act.Target().String() != "pi" {
				t.Errorf("policy %s target %q", act.Policy(), act.Target())
			}
			err = act.Run(t.Context(), Event{})
			if tt.wantErr == "" && err != nil || tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)) {
				t.Fatalf("Run = %v, want %q", err, tt.wantErr)
			}
			if pr.device != "pi" || pr.reqs[0].GetTcp().GetAddress() != "127.0.0.1:53" {
				t.Errorf("probed %q with %v", pr.device, pr.reqs)
			}
		})
	}
}

func TestCheckActionPrecheck(t *testing.T) {
	pr := &fakeProbers{answer: up, check: policy.ErrBeyondCeiling}
	src := "id: a\ntriggers:\n  - type: manual\nactions:\n  - type: check\n    check: tcp\n    address: 127.0.0.1:53\n    from: pi\n"
	a, err := Parse("a.yaml", []byte(src), localKinds(pr))
	if err != nil {
		t.Fatal(err)
	}
	c, ok := a.Actions[0].Impl.(prechecker)
	if !ok {
		t.Fatal("the check action has no Precheck")
	}
	if err := c.Precheck(t.Context(), Event{}); !errors.Is(err, policy.ErrBeyondCeiling) {
		t.Fatalf("Precheck = %v, want ErrBeyondCeiling", err)
	}
}

// TestRuntimeDoesNotWatchLocal makes sure the hub never runs a local
// automation's checks, so its actions are never taken twice.
func TestRuntimeDoesNotWatchLocal(t *testing.T) {
	pr := &fakeProbers{answer: down}
	h := newHarness(t, localDNSWatchdog, localKinds(pr))
	local := h.rt.Local()
	if len(local) != 1 || local[0].ID != "dns-watchdog" {
		t.Fatalf("Local = %v, want dns-watchdog", local)
	}
	time.Sleep(100 * time.Millisecond)
	pr.mu.Lock()
	defer pr.mu.Unlock()
	if len(pr.reqs) != 0 {
		t.Fatalf("the hub sent %d probes for a local automation", len(pr.reqs))
	}
	if len(h.audit.all()) != 0 {
		t.Fatalf("the hub decided on a local automation's checks: %v", h.audit.all())
	}
}
