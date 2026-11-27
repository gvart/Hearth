// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"context"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/durationpb"

	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
)

// closedAddr is a TCP address nothing listens on.
func closedAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

// openAddr is a TCP address that accepts connections until the test ends.
func openAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	return ln.Addr().String()
}

func tcpCheck(addr string) *agentv1.ProbeRequest {
	return &agentv1.ProbeRequest{Timeout: durationpb.New(time.Second), Probe: &agentv1.ProbeRequest_Tcp{Tcp: &agentv1.TCPProbe{Address: addr}}}
}

// watchdog is a rule whose check of addr fires at once, then restarts
// pihole-FTL and checks verify.
func watchdog(addr, verify string) *agentv1.LocalRule {
	return &agentv1.LocalRule{
		Id: "dns-watchdog", Digest: "d1",
		Triggers: []*agentv1.LocalTrigger{{
			Id: "dns-down", Type: "tcp", Probe: tcpCheck(addr), Every: durationpb.New(time.Second), Target: addr,
		}},
		Actions: []*agentv1.LocalAction{
			{Id: "verify", Type: "check", Action: &agentv1.LocalAction_Check{Check: tcpCheck(verify)}},
			{Id: "restart-dns", Type: "restart", Action: &agentv1.LocalAction_Restart{
				Restart: &agentv1.RestartService{Manager: "systemd", Name: "pihole-FTL.service"},
			}},
		},
	}
}

type rulesHarness struct {
	e         *rules
	runs      *runLog
	connected atomic.Bool
	ceiling   atomic.Pointer[Ceiling]
	dir       string
}

func newRulesHarness(t *testing.T, c Ceiling) *rulesHarness {
	t.Helper()
	h := &rulesHarness{dir: t.TempDir()}
	h.ceiling.Store(&c)
	log := slog.New(slog.DiscardHandler)
	h.runs = openRunLog(t.Context(), h.dir, log)
	h.e = &rules{
		dataDir: h.dir, log: log, ceiling: func() Ceiling { return *h.ceiling.Load() }, connected: h.connected.Load,
		runs: h.runs, now: time.Now,
	}
	ctx, cancel := context.WithCancel(t.Context())
	h.e.start(ctx, &agentv1.LocalRules{})
	t.Cleanup(func() {
		cancel()
		h.e.stop()
	})
	return h
}

func (h *rulesHarness) waitRuns(t *testing.T, n int) []*agentv1.LocalRun {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		h.runs.mu.Lock()
		got := append([]*agentv1.LocalRun(nil), h.runs.runs...)
		h.runs.mu.Unlock()
		if len(got) >= n {
			return got
		}
		if time.Now().After(deadline) {
			t.Fatalf("got %d runs, want %d", len(got), n)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestLocalRuleFiresWithoutAHub: a rule runs with no hub stream, its check
// action runs, and a restart beyond the ceiling is refused on the agent.
func TestLocalRuleFiresWithoutAHub(t *testing.T) {
	h := newRulesHarness(t, Ceiling{Probe: true}) // no restart allowed
	h.e.apply(t.Context(), &agentv1.LocalRules{Version: 1, Rules: []*agentv1.LocalRule{watchdog(closedAddr(t), openAddr(t))}})
	run := h.waitRuns(t, 1)[0]
	if run.GetRule() != "dns-watchdog" || run.GetTrigger() != "dns-down" || run.GetHubConnected() {
		t.Fatalf("run = %v", run)
	}
	if run.GetStatus() != "denied" || len(run.GetSteps()) != 2 || run.GetSteps()[0].GetStatus() != "ok" ||
		run.GetSteps()[1].GetStatus() != "denied" {
		t.Fatalf("run = %v, want the check ok and the restart denied", run)
	}
	// Once per outage: the check keeps failing, and fires no more.
	time.Sleep(2500 * time.Millisecond)
	if n := len(h.waitRuns(t, 1)); n != 1 {
		t.Fatalf("%d runs in one outage, want 1", n)
	}
	// The run is saved for the hub.
	saved, err := readRunLog(h.dir)
	if err != nil || len(saved.GetRuns()) != 1 {
		t.Fatalf("saved runs = %v, %v", saved, err)
	}
	// The rules too.
	rs, err := readRulesFile(h.dir)
	if err != nil || len(rs.GetRules()) != 1 || rs.GetVersion() != 1 {
		t.Fatalf("saved rules = %v, %v", rs, err)
	}
}

func TestLocalRuleProbeBeyondCeiling(t *testing.T) {
	h := newRulesHarness(t, Ceiling{}) // no probes
	h.e.apply(t.Context(), &agentv1.LocalRules{Version: 1, Rules: []*agentv1.LocalRule{watchdog(closedAddr(t), openAddr(t))}})
	time.Sleep(1500 * time.Millisecond)
	h.runs.mu.Lock()
	defer h.runs.mu.Unlock()
	if len(h.runs.runs) != 0 {
		t.Fatalf("a check beyond the ceiling fired: %v", h.runs.runs)
	}
}

func TestLocalRulesStaleIgnored(t *testing.T) {
	h := newRulesHarness(t, Ceiling{Probe: true})
	rule := watchdog(openAddr(t), openAddr(t))
	h.e.apply(t.Context(), &agentv1.LocalRules{Version: 5, Rules: []*agentv1.LocalRule{rule}})
	h.e.apply(t.Context(), &agentv1.LocalRules{Version: 4})
	if len(h.e.live) != 1 || h.e.version != 5 {
		t.Fatalf("a stale push changed the rules: %d live, version %d", len(h.e.live), h.e.version)
	}
	// The same version may carry other content: a policy change made it.
	h.e.apply(t.Context(), &agentv1.LocalRules{Version: 5})
	if len(h.e.live) != 0 {
		t.Fatalf("%d live rules after an empty set, want none", len(h.e.live))
	}
}

func TestLocalRulesInvalidRefused(t *testing.T) {
	bad := []*agentv1.LocalRule{
		{Id: "Bad ID", Triggers: watchdog("a:1", "b:1").Triggers, Actions: watchdog("a:1", "b:1").Actions},
		{Id: "no-actions", Triggers: watchdog("a:1", "b:1").Triggers},
		{Id: "exec", Triggers: watchdog("a:1", "b:1").Triggers, Actions: []*agentv1.LocalAction{{Id: "x", Type: "exec"}}},
		{Id: "no-probe", Triggers: []*agentv1.LocalTrigger{{Id: "t"}}, Actions: watchdog("a:1", "b:1").Actions},
	}
	for _, r := range bad {
		t.Run(r.GetId(), func(t *testing.T) {
			h := newRulesHarness(t, Ceiling{Probe: true})
			h.e.apply(t.Context(), &agentv1.LocalRules{Version: 1, Rules: []*agentv1.LocalRule{r}})
			if len(h.e.live) != 0 || h.e.version != 0 {
				t.Fatalf("an invalid rule was taken")
			}
			if _, err := os.Stat(filepath.Join(h.dir, RulesFile)); !os.IsNotExist(err) {
				t.Fatalf("an invalid rule was saved: %v", err)
			}
		})
	}
}

// TestCorruptRulesFileRunsNone: a rules.json that does not parse starts no
// rules, and the agent carries on.
func TestCorruptRulesFileRunsNone(t *testing.T) {
	for name, content := range map[string]string{
		"not json": "{not json",
		"invalid":  `{"rules":[{"id":"BAD"}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, RulesFile), []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := readRulesFile(dir); err == nil {
				t.Fatal("readRulesFile took a corrupt file")
			}
			r := &runner{cfg: Config{DataDir: dir}, log: slog.New(slog.DiscardHandler)}
			r.startRules(t.Context())
			defer r.rules.stop()
			if len(r.rules.live) != 0 {
				t.Fatalf("%d rules run from a corrupt file", len(r.rules.live))
			}
		})
	}
}

func TestRulesFileMode(t *testing.T) {
	dir := t.TempDir()
	if err := writeRulesFile(dir, &agentv1.LocalRules{Version: 3}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, RulesFile))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("%s mode %v, want 0600", RulesFile, info.Mode().Perm())
	}
}

func TestRunLogBoundedAndAcked(t *testing.T) {
	ctx := t.Context()
	dir := t.TempDir()
	l := openRunLog(ctx, dir, slog.New(slog.DiscardHandler))
	for range maxRunLog + 5 {
		l.add(ctx, &agentv1.LocalRun{Id: "local-x", Rule: "r"})
	}
	msg := l.next(time.Now()).GetLocalRuns()
	if len(msg.GetRuns()) != maxRunLog || msg.GetDropped() != 5 {
		t.Fatalf("sent %d runs, %d dropped; want %d and 5", len(msg.GetRuns()), msg.GetDropped(), maxRunLog)
	}
	// Not sent again until runsResend, unless a run is added.
	if l.next(time.Now()) != nil {
		t.Fatal("runs sent again at once")
	}
	if l.next(time.Now().Add(runsResend)) == nil {
		t.Fatal("runs not sent again after runsResend")
	}
	// After a restart, the saved runs are still there.
	again := openRunLog(ctx, dir, slog.New(slog.DiscardHandler))
	if len(again.runs) != maxRunLog || again.dropped != 5 {
		t.Fatalf("reopened log: %d runs, %d dropped", len(again.runs), again.dropped)
	}
	mid := msg.GetRuns()[49].GetSeq()
	l.ack(ctx, mid)
	if len(l.runs) != maxRunLog-50 || l.dropped != 0 {
		t.Fatalf("after ack: %d runs, %d dropped", len(l.runs), l.dropped)
	}
	if l.next(time.Now()) == nil {
		t.Fatal("the rest not sent after a partial ack")
	}
	l.ack(ctx, msg.GetRuns()[maxRunLog-1].GetSeq())
	if l.next(time.Now()) != nil || len(l.runs) != 0 {
		t.Fatal("runs left after a full ack")
	}
	// A corrupt file starts an empty log.
	if err := os.WriteFile(filepath.Join(dir, RunLogFile), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if l := openRunLog(ctx, dir, slog.New(slog.DiscardHandler)); len(l.runs) != 0 {
		t.Fatal("a corrupt run log was loaded")
	}
}
