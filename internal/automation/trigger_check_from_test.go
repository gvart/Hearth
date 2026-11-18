// SPDX-License-Identifier: AGPL-3.0-only

package automation

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/policy"
	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
)

// fakeProbers is a device's agent as *hub.Agents runs probes on it.
type fakeProbers struct {
	mu sync.Mutex
	// check is CheckProbe's answer.
	check error
	// answer is Probe's: a result, or an error when the probe cannot run.
	answer func() (*agentv1.ProbeResult, error)
	reqs   []*agentv1.ProbeRequest
	device string
}

func (f *fakeProbers) CheckProbe(context.Context, string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.check
}

func (f *fakeProbers) Probe(_ context.Context, device string, req *agentv1.ProbeRequest) (*agentv1.ProbeResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reqs = append(f.reqs, req)
	f.device = device
	return f.answer()
}

func (f *fakeProbers) set(answer func() (*agentv1.ProbeResult, error)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.answer = answer
}

func up() (*agentv1.ProbeResult, error) { return &agentv1.ProbeResult{}, nil }
func down() (*agentv1.ProbeResult, error) {
	return &agentv1.ProbeResult{Error: "connection refused"}, nil
}

func offline() (*agentv1.ProbeResult, error) {
	return nil, errors.New("device pi: agent not connected")
}

func denied() (*agentv1.ProbeResult, error) {
	return &agentv1.ProbeResult{Denied: true, Error: "probe: beyond"}, nil
}

// startFromCheck watches a check from device pi, as automation a1.
func startFromCheck(t *testing.T, pr *fakeProbers, pol Policy, src string) *checkSteps {
	t.Helper()
	clock := newFakeClock(time.Unix(1_700_000_000, 0))
	tr := mustBuildTrigger(t, TriggerDeps{Clock: clock, Probers: pr, Policy: pol}, src)
	w := &watching{done: make(chan error, 1)}
	ctx, cancel := context.WithCancel(withTrigger(t.Context(), "a1", "t1"))
	w.cancel = cancel
	go func() {
		w.done <- tr.Watch(ctx, func(map[string]any) { w.fires.Add(1) })
	}()
	t.Cleanup(func() {
		cancel()
		if err := <-w.done; err != nil {
			t.Errorf("Watch = %v", err)
		}
	})
	return &checkSteps{t: t, clock: clock, w: w, every: clock.waitForWaiter(t)}
}

func TestCheckFromDeviceFiresOncePerOutage(t *testing.T) {
	audit := &auditLog{}
	pr := &fakeProbers{answer: up}
	c := startFromCheck(t, pr, policy.New(audit), "type: tcp\naddress: 127.0.0.1:8080\nfrom: pi\ntimeout: 2s")

	pr.set(down)
	if n := c.next(); n != 1 {
		t.Fatalf("fires = %d when the device sees the port closed, want 1", n)
	}
	if n := c.next(); n != 1 {
		t.Fatalf("fires = %d while still closed, want 1: one firing per outage", n)
	}
	// The agent going offline mid-outage neither fires again nor ends it.
	pr.set(offline)
	c.next()
	pr.set(down)
	if n := c.next(); n != 1 {
		t.Fatalf("fires = %d after the agent came back to the same outage, want 1", n)
	}
	pr.set(up)
	c.next()
	pr.set(down)
	if n := c.next(); n != 2 {
		t.Fatalf("fires = %d after a new outage, want 2", n)
	}

	pr.mu.Lock()
	req, device := pr.reqs[0], pr.device
	pr.mu.Unlock()
	if device != "pi" || req.GetTcp().GetAddress() != "127.0.0.1:8080" || req.GetTimeout().AsDuration() != 2*time.Second {
		t.Errorf("probe to %s = %v, want tcp 127.0.0.1:8080 with a 2s timeout", device, req)
	}
	// One audited decision for the watch, not one per check.
	entries := audit.all()
	if len(entries) != 1 {
		t.Fatalf("audit has %d entries, want 1", len(entries))
	}
	e := entries[0]
	if e.Action != string(policy.AutomationProbe) || e.Decision != policy.Allow || e.ActorID != "a1" || e.Target != "pi" {
		t.Errorf("audit entry = %+v, want automation a1 allowed automation.probe on pi", e)
	}
}

func TestCheckFromOfflineDeviceNeverFires(t *testing.T) {
	for name, answer := range map[string]func() (*agentv1.ProbeResult, error){
		"offline": offline, "denied by the agent": denied,
	} {
		t.Run(name, func(t *testing.T) {
			pr := &fakeProbers{answer: answer}
			c := startFromCheck(t, pr, policy.New(&auditLog{}), "type: http\nurl: http://127.0.0.1:1/\nfrom: pi")
			for range 3 {
				if n := c.next(); n != 0 {
					t.Fatalf("fires = %d while the check cannot run, want 0", n)
				}
			}
		})
	}
}

func TestCheckFromDeviceDenied(t *testing.T) {
	for name, tc := range map[string]struct {
		pol   policy.Config
		check error
		want  string
	}{
		"policy":  {pol: policy.Config{Classes: map[policy.Class]policy.Mode{policy.Read: policy.ModeDeny}}, want: "denied by policy"},
		"ceiling": {check: policy.ErrBeyondCeiling, want: "capability ceiling"},
	} {
		t.Run(name, func(t *testing.T) {
			audit := &auditLog{}
			pr := &fakeProbers{answer: up, check: tc.check}
			tr := mustBuildTrigger(t, TriggerDeps{Probers: pr, Policy: policy.NewWithConfig(audit, nil, tc.pol)},
				"type: tcp\naddress: 127.0.0.1:8080\nfrom: pi")
			err := tr.Watch(withTrigger(t.Context(), "a1", "t1"), func(map[string]any) { t.Error("fired") })
			if !errors.Is(err, policy.ErrDenied) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Watch = %v, want a denial (%s)", err, tc.want)
			}
			if len(pr.reqs) != 0 {
				t.Errorf("%d probes sent after a denial", len(pr.reqs))
			}
			if e := audit.all(); len(e) != 1 || e[0].Decision != policy.Deny {
				t.Errorf("audit = %+v, want one denial", e)
			}
		})
	}
}

func TestCheckFromDeviceWithoutAgents(t *testing.T) {
	tr := mustBuildTrigger(t, TriggerDeps{}, "type: dns\nname: pi.hole\nserver: 127.0.0.1\nfrom: pi")
	if err := tr.Watch(t.Context(), func(map[string]any) {}); err == nil {
		t.Fatal("Watch without agents or policy = nil, want an error")
	}
}

func TestCheckFromDeviceRedactsURL(t *testing.T) {
	audit := &auditLog{}
	pr := &fakeProbers{answer: down}
	const rawURL = "http://admin:" + "s3cret@nas.lan/ping?token=t0ken"
	c := startFromCheck(t, pr, policy.New(audit), "type: http\nurl: "+rawURL+"\nfrom: pi")
	if c.w.fires.Load() != 1 {
		t.Fatal("did not fire")
	}
	pr.mu.Lock()
	sent := pr.reqs[0].GetHttp().GetUrl()
	pr.mu.Unlock()
	if sent != rawURL {
		t.Errorf("agent got %q, want the URL as written", sent)
	}
	for _, e := range audit.all() {
		if s := string(e.Detail) + e.Target; strings.Contains(s, "s3cret") || strings.Contains(s, "t0ken") {
			t.Errorf("audit entry leaks a secret: %s", s)
		}
	}
}

func TestCheckFromDeviceDescribe(t *testing.T) {
	tr := mustBuildTrigger(t, TriggerDeps{}, "type: tcp\naddress: 10.0.0.5:22\nfrom: pi")
	want := "fires when TCP connect to 10.0.0.5:22 fails (checked every 10s from device pi)"
	if got := tr.Describe(); got != want {
		t.Errorf("Describe = %q, want %q", got, want)
	}
	_, err := buildTrigger(t, TriggerDeps{}, "type: tcp\naddress: 10.0.0.5:22\nfrom: pi\nevery: 5m\ntimeout: 2m")
	wantErrContains(t, err, "at most 1m0s")
}
