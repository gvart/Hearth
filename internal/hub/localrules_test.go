// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"context"
	"encoding/json"
	"log/slog"
	"maps"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/gvart/hearth/internal/automation"
	"github.com/gvart/hearth/internal/policy"
	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
	"github.com/gvart/hearth/internal/store"
)

const localWatchdog = `id: dns-watchdog
local: true
triggers:
  - id: dns-down
    type: dns
    name: example.com
    server: 127.0.0.1
    from: pi-name
actions:
  - id: restart-dns
    type: restart
    device: pi-name
    service: systemd:pihole-FTL.service
`

// fakeLocal is the runtime's local automations.
type fakeLocal struct {
	mu  sync.Mutex
	set []*automation.Automation
}

func (f *fakeLocal) Local() []*automation.Automation {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.set
}

func (f *fakeLocal) load(t *testing.T, srcs ...string) {
	t.Helper()
	kinds := automation.Builtin(slog.New(slog.DiscardHandler))
	maps.Copy(kinds.Triggers, automation.Triggers(automation.TriggerDeps{}))
	maps.Copy(kinds.Actions, automation.Actions(automation.ActionDeps{}))
	var set []*automation.Automation
	for _, src := range srcs {
		a, err := automation.Parse("a.yaml", []byte(src), kinds)
		if err != nil {
			t.Fatal(err)
		}
		set = append(set, a)
	}
	f.mu.Lock()
	f.set = set
	f.mu.Unlock()
}

// fixedVersion is the automations' version.
type fixedVersion struct{ v uint64 }

func (f *fixedVersion) Version(context.Context, string) (uint64, error) { return f.v, nil }

type localHarness struct {
	st    *store.Store
	cfg   *LocalRulesConfig
	local *fakeLocal
	ver   *fixedVersion
	sess  *agentSession
	mu    sync.Mutex
	sent  []*agentv1.HubMessage
}

func newLocalHarness(t *testing.T, ceiling *agentv1.Ceiling, pol policy.Config) *localHarness {
	t.Helper()
	st := newTestStore(t)
	enrollDevice(t, st, "pi")
	enrollDevice(t, st, "nas")
	h := &localHarness{st: st, local: &fakeLocal{}, ver: &fixedVersion{v: 10}}
	h.cfg = &LocalRulesConfig{
		Automations: h.local, Docs: h.ver, Policy: policy.NewWithConfig(st.Audit(), nil, pol),
		Audit: st.Audit(), Runs: st.AutomationRuns(), Devices: st.Devices(), Now: time.Now,
	}
	h.sess = &agentSession{
		device: "pi", minor: minLocalRulesMinor, sendTimeout: time.Second, done: make(chan struct{}),
		abort: func() {}, ceiling: ceiling,
		send: func(m *agentv1.HubMessage) error {
			h.mu.Lock()
			defer h.mu.Unlock()
			h.sent = append(h.sent, m)
			return nil
		},
	}
	return h
}

func (h *localHarness) sync(t *testing.T) {
	t.Helper()
	if err := h.sess.syncLocalRules(t.Context(), h.cfg); err != nil {
		t.Fatal(err)
	}
}

// pushes are the LocalRules sent so far.
func (h *localHarness) pushes() []*agentv1.LocalRules {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []*agentv1.LocalRules
	for _, m := range h.sent {
		if r := m.GetLocalRules(); r != nil {
			out = append(out, r)
		}
	}
	return out
}

func (h *localHarness) audit(t *testing.T) []store.AuditEntry {
	t.Helper()
	all, err := h.st.Audit().Query(t.Context(), store.AuditFilter{ActorKind: policy.ActorAutomation}, 100)
	if err != nil {
		t.Fatal(err)
	}
	return all
}

var allowsWatchdog = &agentv1.Ceiling{Probe: true, Restart: []string{"systemd:pihole-FTL.service"}}

func TestLocalRulesPushed(t *testing.T) {
	h := newLocalHarness(t, allowsWatchdog, policy.Config{})
	// On connect, with no local automation: an empty set, so a saved one goes.
	h.sync(t)
	if p := h.pushes(); len(p) != 1 || len(p[0].GetRules()) != 0 || p[0].GetVersion() != 10 {
		t.Fatalf("pushes on connect = %v, want one empty set of version 10", p)
	}
	h.local.load(t, localWatchdog, strings.ReplaceAll(strings.ReplaceAll(localWatchdog, "pi-name", "nas"), "dns-watchdog", "nas-dog"))
	h.ver.v = 11
	h.sync(t)
	p := h.pushes()
	if len(p) != 2 || len(p[1].GetRules()) != 1 || p[1].GetRules()[0].GetId() != "dns-watchdog" || p[1].GetVersion() != 11 {
		t.Fatalf("push = %v, want dns-watchdog only, version 11", p[len(p)-1])
	}
	// Decided once, as the automation, marked as pushed.
	entries := h.audit(t)
	var probe, restart bool
	for _, e := range entries {
		if e.ActorID != "dns-watchdog" || !strings.Contains(string(e.Detail), localPushed) {
			t.Errorf("unexpected entry %+v", e)
		}
		probe = probe || e.Action == string(policy.AutomationProbe) && e.Decision == policy.Allow
		restart = restart || e.Action == string(policy.AutomationRestart) && e.Decision == policy.Allow
	}
	if !probe || !restart {
		t.Fatalf("audit = %+v, want an allowed probe and restart", entries)
	}
	// Nothing changed: no push, no new decision.
	n := len(entries)
	h.sync(t)
	if len(h.pushes()) != 2 || len(h.audit(t)) != n {
		t.Fatalf("an unchanged set was pushed or decided again")
	}
	// The automation goes: the next sync empties the set.
	h.local.load(t)
	h.ver.v = 12
	h.sync(t)
	if p := h.pushes(); len(p) != 3 || len(p[2].GetRules()) != 0 {
		t.Fatalf("after the automation went: %v", p[len(p)-1])
	}
}

func TestLocalRulesNotPushed(t *testing.T) {
	tests := []struct {
		name    string
		ceiling *agentv1.Ceiling
		pol     policy.Config
		reason  string
	}{
		{"no probes", &agentv1.Ceiling{Restart: []string{"systemd:*"}}, policy.Config{}, "beyond"},
		{"restart beyond the ceiling", &agentv1.Ceiling{Probe: true, Restart: []string{"docker:x"}}, policy.Config{}, "beyond"},
		{"denied by policy", allowsWatchdog,
			policy.Config{Actors: map[string]map[policy.Class]policy.Mode{policy.ActorAutomation: {policy.Safe: policy.ModeDeny}}}, "denied"},
		{"needs approval", allowsWatchdog,
			policy.Config{Actors: map[string]map[policy.Class]policy.Mode{policy.ActorAutomation: {policy.Safe: policy.ModeConfirm}}}, "cannot wait for approval"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newLocalHarness(t, tt.ceiling, tt.pol)
			h.local.load(t, localWatchdog)
			h.sync(t)
			p := h.pushes()
			if len(p) != 1 || len(p[0].GetRules()) != 0 {
				t.Fatalf("pushes = %v, want one empty set", p)
			}
			var denied bool
			for _, e := range h.audit(t) {
				denied = denied || e.Decision == policy.Deny && strings.Contains(e.Result, tt.reason)
			}
			if !denied {
				t.Fatalf("audit = %+v, want a denial with %q", h.audit(t), tt.reason)
			}
		})
	}
}

// TestLocalRulesOldAgent: an agent before minLocalRulesMinor gets nothing.
func TestLocalRulesOldAgent(t *testing.T) {
	h := newLocalHarness(t, allowsWatchdog, policy.Config{})
	h.sess.minor = minLocalRulesMinor - 1
	h.local.load(t, localWatchdog)
	s := &AgentStream{agents: &Agents{}}
	s.agents.SetLocalRules(*h.cfg)
	s.syncLocalRules(t.Context(), slog.New(slog.DiscardHandler), h.sess)
	if len(h.sent) != 0 {
		t.Fatalf("an old agent got %v", h.sent)
	}
}

func localRun(seq uint64, id, rule string, connected bool, at time.Time) *agentv1.LocalRun {
	return &agentv1.LocalRun{
		Seq: seq, Id: id, Rule: rule, Trigger: "dns-down", TriggerType: "dns", Target: "example.com",
		TriggerError: "timeout", Started: timestamppb.New(at), Finished: timestamppb.New(at.Add(time.Second)),
		Status: automation.StatusSucceeded, HubConnected: connected,
		Steps: []*agentv1.LocalStep{{Id: "restart-dns", Type: "restart", Status: "ok"}},
	}
}

func TestLocalRunsRecorded(t *testing.T) {
	h := newLocalHarness(t, allowsWatchdog, policy.Config{})
	h.local.load(t, localWatchdog)
	s := &AgentStream{agents: &Agents{}}
	s.agents.SetLocalRules(*h.cfg)
	log := slog.New(slog.DiscardHandler)
	at := time.Now().Add(-time.Minute).Truncate(time.Millisecond)
	msg := &agentv1.LocalRuns{Runs: []*agentv1.LocalRun{
		localRun(1, "local-a1", "dns-watchdog", false, at),
		// Not a rule of this device: a device speaks for its own rules only.
		localRun(2, "local-a2", "other", false, at),
		localRun(3, "local-a3", "dns-watchdog", true, at.Add(time.Hour*24*365)), // in the future
	}}
	s.recordLocalRuns(t.Context(), log, h.sess, msg)
	// Sent again, as after a lost acknowledgement: recorded once.
	s.recordLocalRuns(t.Context(), log, h.sess, msg)

	var acks []uint64
	for _, m := range h.sent {
		if a := m.GetLocalRunsAck(); a != nil {
			acks = append(acks, a.GetSeq())
		}
	}
	if len(acks) != 2 || acks[0] != 3 || acks[1] != 3 {
		t.Fatalf("acks = %v, want 3 twice", acks)
	}
	runs, err := h.st.AutomationRuns().List(t.Context(), "", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 2 {
		t.Fatalf("runs = %+v, want 2 of dns-watchdog", runs)
	}
	for _, r := range runs {
		if r.AutomationID != "dns-watchdog" {
			t.Errorf("run of %s recorded", r.AutomationID)
		}
		var steps []automation.StepResult
		if err := json.Unmarshal(r.Steps, &steps); err != nil {
			t.Fatal(err)
		}
		if len(steps) != 2 || steps[0].RanOn != "pi" || steps[0].Status != "fired" || steps[1].ID != "restart-dns" {
			t.Errorf("steps = %+v", steps)
		}
		if r.ID == "local-a1" && (!steps[0].HubUnreachable || !r.StartedAt.Equal(at)) {
			t.Errorf("run a1: hub_unreachable %v, started %v; want true, %v", steps[0].HubUnreachable, r.StartedAt, at)
		}
		if r.ID == "local-a3" && (steps[0].HubUnreachable || r.StartedAt.After(time.Now())) {
			t.Errorf("run a3: hub_unreachable %v, started %v (in the future)", steps[0].HubUnreachable, r.StartedAt)
		}
	}
	entries := h.audit(t)
	var marked int
	for _, e := range entries {
		if e.Action != string(policy.AutomationRestart) || e.ActorID != "dns-watchdog" || e.Target != "pi" {
			continue
		}
		if strings.Contains(string(e.Detail), localRanHubsDown) && e.Result == "ok" {
			marked++
		}
		if strings.Contains(string(e.Detail), "other") {
			t.Errorf("audited a run of another automation: %+v", e)
		}
	}
	if marked != 1 {
		t.Fatalf("audit = %+v, want one restart marked %q", entries, localRanHubsDown)
	}
}
