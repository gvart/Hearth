// SPDX-License-Identifier: AGPL-3.0-only

package automation

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/gvart/hearth/internal/integrations/talos"
	"github.com/gvart/hearth/internal/policy"
)

// fakeTalos stands in for *talos.Client: it returns nodes, or err for the
// whole read. It reads only in a context policy granted talos.read, as the
// engine must give it.
type fakeTalos struct {
	nodes []talos.Node
	err   error

	mu    sync.Mutex
	reads int
}

func (f *fakeTalos) Target() string { return "lab@192.0.2.10:50000" }

func (f *fakeTalos) Read(ctx context.Context) ([]talos.Node, error) {
	if !policy.Granted(ctx, policy.TalosRead) {
		return nil, errors.New("read outside a talos.read decision")
	}
	f.mu.Lock()
	f.reads++
	f.mu.Unlock()
	return f.nodes, f.err
}

func (f *fakeTalos) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.reads
}

// talosLab is a worker at v1.12.8 and healthy, a control plane at v1.12.7
// whose etcd fails its health check, and a node that reboots: apid cannot
// reach it.
func talosLab() []talos.Node {
	running := func(id string) talos.Service {
		return talos.Service{ID: id, State: "Running", Health: talos.HealthHealthy}
	}
	return []talos.Node{
		{Address: "192.0.2.10", Hostname: "talos-cp-1", Version: "v1.12.7", Healthy: false, Services: []talos.Service{
			running("apid"), {ID: "etcd", State: "Running", Health: talos.HealthUnhealthy, Message: "no quorum"},
		}},
		{Address: "192.0.2.50", Hostname: "talos-worker-1", Version: "v1.12.8", Healthy: true, Services: []talos.Service{
			running("apid"), running("kubelet"),
		}},
		{Address: "192.0.2.51", Error: "rpc error: code = Unavailable desc = connection refused"},
		// Just rebooted: kubelet runs, its health not checked yet. The
		// Devices page counts it healthy; a talos_node check does not.
		{Address: "192.0.2.52", Hostname: "talos-worker-2", Version: "v1.12.8", Healthy: true, Services: []talos.Service{
			running("apid"),
			{ID: "kubelet", State: "Running", Health: talos.HealthUnknown},
			{ID: "dashboard", State: "Running", Health: talos.HealthUnknown},
		}},
		{Address: "192.0.2.53", Hostname: "talos-worker-3", Version: "v1.12.8", Healthy: true, Services: []talos.Service{
			running("apid"), running("kubelet"), {ID: "dashboard", State: "Running", Health: talos.HealthUnknown},
		}},
	}
}

const talosNodeYAML = `id: rb
steps:
  - id: talos
    type: check
    check: {type: talos_node, node: %s%s}
    within: %s
    every: 1s
`

func TestRunbookTalosNodeCheck(t *testing.T) {
	denyReads := policy.Config{Actors: map[string]map[policy.Class]policy.Mode{policy.ActorAutomation: {policy.Read: policy.ModeDeny}}}
	tests := []struct {
		name, node, fields, within string
		cfg                        policy.Config
		readErr                    error
		noTalos                    bool
		status, step, errIn        string
		reads                      int // -1 for polled: at least two
		decision                   string
	}{
		{
			name: "version matches, healthy", node: "192.0.2.50", fields: ", version: v1.12.8, healthy: true", within: "0s",
			status: RunbookSucceeded, step: stepOK, reads: 1, decision: policy.Allow,
		},
		{
			name: "by hostname, version without v", node: "talos-worker-1", fields: ", version: 1.12.8", within: "0s",
			status: RunbookSucceeded, step: stepOK, reads: 1, decision: policy.Allow,
		},
		{
			name: "answers: no version or health asked", node: "192.0.2.10", within: "0s",
			status: RunbookSucceeded, step: stepOK, reads: 1, decision: policy.Allow,
		},
		{
			name: "version mismatch, polled until within", node: "192.0.2.10", fields: ", version: v1.12.8", within: "2s",
			status: RunbookFailed, step: stepFailed, errIn: "runs v1.12.7, not v1.12.8", reads: -1, decision: policy.Allow,
		},
		{
			name: "unhealthy service, polled", node: "talos-cp-1", fields: ", healthy: true", within: "2s",
			status: RunbookFailed, step: stepFailed, errIn: "etcd Running unhealthy: no quorum", reads: -1, decision: policy.Allow,
		},
		{
			name: "health check not run yet, polled", node: "192.0.2.52", fields: ", version: v1.12.8, healthy: true", within: "2s",
			status: RunbookFailed, step: stepFailed, errIn: "is not healthy: kubelet Running unknown", reads: -1, decision: policy.Allow,
		},
		{
			name: "a service without a health check may be unknown", node: "192.0.2.53", fields: ", version: v1.12.8, healthy: true", within: "0s",
			status: RunbookSucceeded, step: stepOK, reads: 1, decision: policy.Allow,
		},
		{
			name: "unreachable node, polled: it may be rebooting", node: "192.0.2.51", fields: ", version: v1.12.8", within: "2s",
			status: RunbookFailed, step: stepFailed, errIn: "cannot be read: rpc error", reads: -1, decision: policy.Allow,
		},
		{
			name: "no endpoint answers, polled", node: "192.0.2.50", within: "2s", readErr: errors.New("talos Version: connection refused"),
			status: RunbookFailed, step: stepFailed, errIn: "connection refused", reads: -1, decision: policy.Allow,
		},
		{
			name: "unknown node fails, naming the nodes read", node: "192.0.2.99", within: "0s",
			status: RunbookFailed, step: stepFailed, errIn: "not among the nodes read through lab@192.0.2.10:50000", reads: 1,
			decision: policy.Allow,
		},
		{
			name: "policy denies: nothing is read", node: "192.0.2.50", within: "0s", cfg: denyReads,
			status: RunbookFailed, step: stepDenied, errIn: "denied", reads: 0, decision: policy.Deny,
		},
		{
			name: "a hub without a talosconfig fails at once", node: "192.0.2.50", within: "1m", noTalos: true,
			status: RunbookFailed, step: stepFailed, errIn: "reads no Talos nodes: start it with --talosconfig", reads: 0,
			decision: policy.Allow,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := &fakeTalos{nodes: talosLab(), err: tt.readErr}
			h := newRBHarness(t, fmt.Sprintf(talosNodeYAML, tt.node, tt.fields, tt.within), tt.cfg)
			if !tt.noTalos {
				h.talosNodes = fake
			}
			h.rb = h.engine()
			h.run(h.rb)
			run := h.await(h.start("rb"), tt.status)
			if s := run.Steps[0]; s.Status != tt.step || !strings.Contains(s.Error, tt.errIn) {
				t.Errorf("step = %s %q, want %s with %q", s.Status, s.Error, tt.step, tt.errIn)
			}
			switch reads := fake.count(); {
			case tt.reads == -1 && reads < 2:
				t.Errorf("%d reads, want the check polled", reads)
			case tt.reads >= 0 && reads != tt.reads:
				t.Errorf("%d reads, want %d", reads, tt.reads)
			}
			if got := h.audited(policy.RunbookCheck); len(got) != 0 {
				t.Errorf("runbook.check entries = %+v, want none", got)
			}
			got := h.audited(policy.TalosRead)
			if len(got) != 1 {
				t.Fatalf("talos.read entries = %+v, want exactly one", got)
			}
			if e := got[0]; e.Decision != tt.decision || e.ActorKind != policy.ActorAutomation ||
				e.ActorID != RunbookActor("rb") || e.Target != tt.node {
				t.Errorf("audit entry = %+v", e)
			}
		})
	}
}

func TestRunbookTalosNodeCheckPlan(t *testing.T) {
	h := newRBHarness(t, fmt.Sprintf(talosNodeYAML, "192.0.2.50", ", version: v1.12.8, healthy: true", "1m"), policy.Config{})
	plan, err := h.rb.Plan(t.Context(), "rb")
	if err != nil {
		t.Fatal(err)
	}
	s := plan.Steps[0]
	if s.Action != string(policy.TalosRead) || s.Class != string(policy.Read) || s.Target != "192.0.2.50" ||
		s.Decision != policy.Allow || !strings.Contains(s.What, "Talos node 192.0.2.50 runs v1.12.8 and is healthy") {
		t.Errorf("plan step = %+v", s)
	}
}

func TestParseRunbookTalosNodeCheckRejects(t *testing.T) {
	head := "id: rb\nsteps:\n  - type: check\n    check: "
	for _, tc := range []struct{ name, check, want string }{
		{"no node", "{type: talos_node, version: v1.12.8}", "node is required"},
		{"bad node", "{type: talos_node, node: 'a b'}", "node is required"},
		{"bad version", "{type: talos_node, node: n, version: 'v1 12'}", "Talos version"},
		{"healthy not a bool", "{type: talos_node, node: n, healthy: maybe}", "into bool"},
		{"from a device", "{type: talos_node, node: n, from: pi}", `unknown field "from"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseRunbook("rb.yaml", []byte(head+tc.check+"\n"), varsKinds())
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

// A runbook may read Talos nodes; people and MCP clients may not, through
// talos.read: they see what the hub's own reads found.
func TestTalosReadActors(t *testing.T) {
	pol := policy.NewWithConfig(nil, nil, policy.Config{})
	for actor, want := range map[string]string{
		policy.ActorHub: policy.Allow, policy.ActorAutomation: policy.Allow,
		policy.ActorWeb: policy.Deny, policy.ActorMCP: policy.Deny,
	} {
		if got, _ := pol.Check(policy.Request{ActorKind: actor, ActorID: "x", Action: policy.TalosRead, Target: "n"}); got != want {
			t.Errorf("%s: %s, want %s", actor, got, want)
		}
	}
}
