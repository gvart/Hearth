// SPDX-License-Identifier: AGPL-3.0-only

package automation

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/gvart/hearth/internal/policy"
	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
	"github.com/gvart/hearth/internal/store"
)

// fromYAML is a runbook with one check step run from device pi.
const fromYAML = `id: rb
steps:
  - id: reach
    type: check
    check: {type: tcp, address: '10.0.0.5:5432', from: pi, timeout: 2s}
    within: %s
    every: 1s
`

// fromHarness is a runbook harness whose checks from devices run on pr.
func fromHarness(t *testing.T, within string, cfg policy.Config, pr Probers) *rbHarness {
	t.Helper()
	h := newRBHarness(t, fmt.Sprintf(fromYAML, within), cfg)
	h.probers = pr
	h.rb = h.engine()
	h.run(h.rb)
	return h
}

func unknownDevice() (*agentv1.ProbeResult, error) {
	return nil, fmt.Errorf("device pi: %w", store.ErrNotFound)
}

func TestRunbookCheckFromDevice(t *testing.T) {
	beyond := fmt.Errorf("device pi: %w (turn Checks on in its Capabilities)", policy.ErrBeyondCeiling)
	denyReads := policy.Config{Actors: map[string]map[policy.Class]policy.Mode{policy.ActorAutomation: {policy.Read: policy.ModeDeny}}}
	tests := []struct {
		name   string
		within string
		cfg    policy.Config
		check  error // CheckProbe's answer
		answer func() (*agentv1.ProbeResult, error)
		// status and step are the run's and the step's end; errIn is in
		// the step's error.
		status, step, errIn string
		probes              int    // probes sent, -1 for at least one
		decision, result    string // the one audit entry
	}{
		{
			name: "passes", within: "0s", answer: up,
			status: RunbookSucceeded, step: stepOK, probes: 1,
			decision: policy.Allow, result: policy.ReadAllowed,
		},
		{
			name: "fails, polled until within: one decision", within: "2s", answer: down,
			status: RunbookFailed, step: stepFailed, errIn: "connection refused", probes: -1,
			decision: policy.Allow, result: "error: connection refused",
		},
		{
			name: "unknown device fails at once", within: "1m", answer: unknownDevice,
			status: RunbookFailed, step: stepFailed, errIn: "device pi: not found", probes: 1,
			decision: policy.Allow, result: "error: the check cannot run from its device: device pi: not found",
		},
		{
			name: "offline device fails at once, never from the hub", within: "1m", answer: offline,
			status: RunbookFailed, step: stepFailed, errIn: "agent not connected", probes: 1,
			decision: policy.Allow, result: "error: the check cannot run from its device: device pi: agent not connected",
		},
		{
			name: "policy denies: nothing is probed", within: "0s", cfg: denyReads, answer: up,
			status: RunbookFailed, step: stepDenied, errIn: "denied", probes: 0,
			decision: policy.Deny,
		},
		{
			name: "the hub's view of the ceiling refuses probes", within: "0s", check: beyond, answer: up,
			status: RunbookFailed, step: stepDenied, errIn: "turn Checks on", probes: 0,
			decision: policy.Deny, result: beyond.Error(),
		},
		{
			name: "the agent refuses the probe", within: "1m", answer: denied,
			status: RunbookFailed, step: stepDenied, errIn: "capability ceiling", probes: 1,
			decision: policy.Allow,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pr := &fakeProbers{check: tt.check, answer: tt.answer}
			h := fromHarness(t, tt.within, tt.cfg, pr)
			run := h.await(h.start("rb"), tt.status)
			s := run.Steps[0]
			if s.Status != tt.step || !strings.Contains(s.Error, tt.errIn) {
				t.Errorf("step = %s %q, want %s with %q", s.Status, s.Error, tt.step, tt.errIn)
			}
			pr.mu.Lock()
			probes, device := len(pr.reqs), pr.device
			var req *agentv1.ProbeRequest
			if probes > 0 {
				req = pr.reqs[0]
			}
			pr.mu.Unlock()
			switch {
			case tt.probes == -1 && probes < 2:
				t.Errorf("%d probes, want the check polled", probes)
			case tt.probes >= 0 && probes != tt.probes:
				t.Errorf("%d probes, want %d", probes, tt.probes)
			}
			if req != nil && (device != "pi" || req.GetTcp().GetAddress() != "10.0.0.5:5432" || req.GetTimeout().AsDuration().String() != "2s") {
				t.Errorf("probe to %s = %v", device, req)
			}

			if got := h.audited(policy.RunbookCheck); len(got) != 0 {
				t.Errorf("runbook.check entries = %+v, want none: a check from a device is its probe", got)
			}
			got := h.audited(policy.AutomationProbe)
			if len(got) != 1 {
				t.Fatalf("automation.probe entries = %+v, want exactly one", got)
			}
			e := got[0]
			if e.Decision != tt.decision || e.ActorKind != policy.ActorAutomation || e.ActorID != RunbookActor("rb") || e.Target != "pi" {
				t.Errorf("audit entry = %+v", e)
			}
			if tt.result != "" && e.Result != tt.result {
				t.Errorf("audit result = %q, want %q", e.Result, tt.result)
			}
			var d map[string]any
			if err := json.Unmarshal(e.Detail, &d); err != nil {
				t.Fatal(err)
			}
			if d["run"] != run.ID || d["step"] != "reach" || d["check"] != "TCP connect to 10.0.0.5:5432" {
				t.Errorf("audit detail = %v", d)
			}
		})
	}
}

func TestRunbookCheckFromDeviceRetryIsDecidedAgain(t *testing.T) {
	pr := &fakeProbers{answer: offline}
	h := fromHarness(t, "0s", policy.Config{}, pr)
	id := h.start("rb")
	h.await(id, RunbookFailed)
	pr.set(up)
	h.retry(id)
	h.await(id, RunbookSucceeded)
	got := h.audited(policy.AutomationProbe)
	if len(got) != 2 {
		t.Fatalf("entries = %+v, want one per attempt", got)
	}
	for i, e := range got {
		var d map[string]any
		if err := json.Unmarshal(e.Detail, &d); err != nil {
			t.Fatal(err)
		}
		if d["attempt"] != float64(i+1) {
			t.Errorf("entry %d is of attempt %v", i, d["attempt"])
		}
	}
}

func TestRunbookCheckFromDeviceWithoutProbers(t *testing.T) {
	h := fromHarness(t, "0s", policy.Config{}, nil)
	run := h.await(h.start("rb"), RunbookFailed)
	if s := run.Steps[0]; s.Status != stepFailed || !strings.Contains(s.Error, "does not run checks from devices") {
		t.Errorf("step = %+v", s)
	}
}

func TestRunbookPlanOfACheckFromDevice(t *testing.T) {
	tests := []struct {
		name     string
		check    error
		decision string
	}{
		{"allowed", nil, policy.Allow},
		{"an offline agent may be back", errors.New("device pi: agent not connected"), policy.Allow},
		{"beyond the ceiling", fmt.Errorf("device pi: %w", policy.ErrBeyondCeiling), policy.Deny},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pr := &fakeProbers{check: tt.check, answer: up}
			h := fromHarness(t, "0s", policy.Config{}, pr)
			plan, err := h.rb.Plan(t.Context(), "rb")
			if err != nil {
				t.Fatal(err)
			}
			s := plan.Steps[0]
			if s.Action != string(policy.AutomationProbe) || s.Class != string(policy.Read) || s.Target != "pi" || s.Decision != tt.decision {
				t.Errorf("plan = %+v", s)
			}
			if s.What != "check TCP connect to 10.0.0.5:5432 from device pi" {
				t.Errorf("what = %q", s.What)
			}
			if n := len(h.audit.all()); n != 0 || len(pr.reqs) != 0 {
				t.Errorf("plan audited %d entries and sent %d probes, want none", n, len(pr.reqs))
			}
		})
	}
}
