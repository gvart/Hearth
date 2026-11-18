// SPDX-License-Identifier: AGPL-3.0-only

package automation

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/gvart/hearth/internal/policy"
	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
)

// ceilingAgents is fakeAgents that also knows the device's reported
// ceiling, as *hub.Agents does.
type ceilingAgents struct {
	fakeAgents
	ceiling *agentv1.Ceiling
}

func (c *ceilingAgents) Check(_ context.Context, device string, req *agentv1.ExecRequest) error {
	if err := policy.WithinCeiling(c.ceiling, req); err != nil {
		return fmt.Errorf("device %s: %w", device, err)
	}
	return nil
}

// An action beyond the ceiling the device reported is denied by policy
// itself (Precheck), before it is held or sent.
func TestDeviceActionPrecheck(t *testing.T) {
	agents := &ceilingAgents{
		fakeAgents: fakeAgents{result: &agentv1.ExecResult{}},
		ceiling:    &agentv1.Ceiling{Restart: []string{"docker:jellyfin"}},
	}
	rec, audit := runOnce(t, deviceAutomation("restart", "    service: docker:pihole"), ActionDeps{Agents: agents})
	if run := rec.all()[0]; run.Status != StatusDenied {
		t.Errorf("run = %+v, want denied", run)
	}
	if len(agents.requests()) != 0 {
		t.Error("the request reached the device")
	}
	e := audit.all()[0]
	if e.Decision != policy.Deny || !strings.Contains(e.Result, "capability ceiling") {
		t.Errorf("audit = %+v, want a policy denial", e)
	}

	rec, _ = runOnce(t, deviceAutomation("restart", "    service: docker:jellyfin"), ActionDeps{Agents: agents})
	if run := rec.all()[0]; run.Status != StatusSucceeded || len(agents.requests()) != 1 {
		t.Errorf("run within the ceiling = %+v, %d requests", run, len(agents.requests()))
	}
}

// A dry-run runtime audits every action's decision and runs none.
func TestDryRunRuntime(t *testing.T) {
	agents := &fakeAgents{result: &agentv1.ExecResult{}}
	a, err := Parse("test.yaml", []byte(deviceAutomation("restart", "    service: docker:jellyfin")), actionKinds(ActionDeps{Agents: agents}))
	if err != nil {
		t.Fatal(err)
	}
	rec, audit := &recorder{}, &auditLog{}
	rt := New(Config{Kinds: actionKinds(ActionDeps{Agents: agents}), Policy: policy.New(audit), Runs: rec, DryRun: true})
	ctx, cancel := context.WithCancel(t.Context())
	rt.reconcile(ctx, []*Automation{a})
	t.Cleanup(func() { cancel(); rt.reconcile(ctx, nil) })
	if err := rt.Fire(a.ID, "go"); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the run recorded", func() bool { return len(rec.all()) == 1 })
	if len(agents.requests()) != 0 {
		t.Error("a dry run sent a request")
	}
	entries := audit.all()
	if len(entries) != 2 {
		t.Fatalf("audit = %+v, want both actions", entries)
	}
	for _, e := range entries {
		if e.Decision != policy.Allow || e.Result != policy.DryRun {
			t.Errorf("audit entry = %+v, want an allowed dry run", e)
		}
	}
}
