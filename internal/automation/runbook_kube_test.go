// SPDX-License-Identifier: AGPL-3.0-only

package automation

import (
	"context"
	"fmt"
	"maps"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/integrations/kubernetes"
	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

// fakeNodes is cluster lab, whose nodes answer as nodes says: nil for Ready.
// Like *kubernetes.Manager, it reads only in a context policy granted it.
type fakeNodes struct {
	loadGate
	nodes map[string]error

	mu    sync.Mutex
	reads int
}

func (f *fakeNodes) NodeReady(ctx context.Context, cluster, node string) error {
	if !policy.Granted(ctx, policy.KubeNodeReady) {
		return kubernetes.ErrNotGranted
	}
	f.mu.Lock()
	f.reads++
	f.mu.Unlock()
	if cluster != "lab" {
		return fmt.Errorf("%w named %q", kubernetes.ErrNotFound, cluster)
	}
	err, ok := f.nodes[node]
	if !ok {
		return fmt.Errorf("node %s: %w", node, kubernetes.ErrObjectNotFound)
	}
	return err
}

func (f *fakeNodes) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.reads
}

const kubeNodeYAML = `id: rb
steps:
  - id: ready
    type: check
    check: {type: kube_node, cluster: %s, node: %s}
    within: %s
    every: 1s
`

func TestRunbookKubeNodeCheck(t *testing.T) {
	notReady := fmt.Errorf("node pi-3: %w: Ready is False", kubernetes.ErrNodeNotReady)
	denyReads := policy.Config{Actors: map[string]map[policy.Class]policy.Mode{policy.ActorAutomation: {policy.Read: policy.ModeDeny}}}
	tests := []struct {
		name, cluster, node, within string
		cfg                         policy.Config
		noKube                      bool
		status, step, errIn         string
		reads                       int // -1 for polled: at least two
		decision, result            string
	}{
		{
			name: "ready", cluster: "lab", node: "pi-1", within: "0s",
			status: RunbookSucceeded, step: stepOK, reads: 1, decision: policy.Allow, result: policy.ReadAllowed,
		},
		{
			name: "not ready, polled until within", cluster: "lab", node: "pi-3", within: "2s",
			status: RunbookFailed, step: stepFailed, errIn: "not Ready", reads: -1, decision: policy.Allow,
			result: "error: " + notReady.Error(),
		},
		{
			name: "missing node, polled: it may be about to register", cluster: "lab", node: "pi-9", within: "2s",
			status: RunbookFailed, step: stepFailed, errIn: "no such object", reads: -1, decision: policy.Allow,
		},
		{
			name: "unknown cluster fails at once", cluster: "nope", node: "pi-1", within: "1m",
			status: RunbookFailed, step: stepFailed, errIn: "no such cluster", reads: 1, decision: policy.Allow,
		},
		{
			name: "policy denies: nothing is read", cluster: "lab", node: "pi-1", within: "0s", cfg: denyReads,
			status: RunbookFailed, step: stepDenied, errIn: "denied", reads: 0, decision: policy.Deny,
		},
		{
			name: "a hub without the integration", cluster: "lab", node: "pi-1", within: "1m", noKube: true,
			status: RunbookFailed, step: stepFailed, errIn: "no Kubernetes integration", reads: 0, decision: policy.Allow,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nodes := &fakeNodes{nodes: map[string]error{"pi-1": nil, "pi-3": notReady}}
			h := newRBHarness(t, fmt.Sprintf(kubeNodeYAML, tt.cluster, tt.node, tt.within), tt.cfg)
			if !tt.noKube {
				h.kubeNodes = nodes
			}
			h.rb = h.engine()
			h.run(h.rb)
			run := h.await(h.start("rb"), tt.status)
			if s := run.Steps[0]; s.Status != tt.step || !strings.Contains(s.Error, tt.errIn) {
				t.Errorf("step = %s %q, want %s with %q", s.Status, s.Error, tt.step, tt.errIn)
			}
			switch reads := nodes.count(); {
			case tt.reads == -1 && reads < 2:
				t.Errorf("%d reads, want the check polled", reads)
			case tt.reads >= 0 && reads != tt.reads:
				t.Errorf("%d reads, want %d", reads, tt.reads)
			}
			if got := h.audited(policy.RunbookCheck); len(got) != 0 {
				t.Errorf("runbook.check entries = %+v, want none", got)
			}
			got := h.audited(policy.KubeNodeReady)
			if len(got) != 1 {
				t.Fatalf("kube.node.ready entries = %+v, want exactly one", got)
			}
			e := got[0]
			if e.Decision != tt.decision || e.ActorKind != policy.ActorAutomation || e.ActorID != RunbookActor("rb") ||
				e.Target != tt.cluster+"/"+tt.node {
				t.Errorf("audit entry = %+v", e)
			}
			if tt.result != "" && e.Result != tt.result {
				t.Errorf("audit result = %q, want %q", e.Result, tt.result)
			}
		})
	}
}

// TestRunbookKubeNodeCheckWaitsForLoad: a check started while the hub is
// still loading its clusters, as right after it starts, waits for the load
// before it reads; a cluster still unknown then fails it at once.
func TestRunbookKubeNodeCheckWaitsForLoad(t *testing.T) {
	for _, tt := range []struct {
		name, cluster, status, step, errIn string
	}{
		{name: "adopted cluster", cluster: "lab", status: RunbookSucceeded, step: stepOK},
		{name: "unknown cluster", cluster: "nope", status: RunbookFailed, step: stepFailed, errIn: "no such cluster"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			nodes := &fakeNodes{loadGate: newLoadGate(), nodes: map[string]error{"pi-1": nil}}
			h := newRBHarness(t, fmt.Sprintf(kubeNodeYAML, tt.cluster, "pi-1", "1m"), policy.Config{})
			h.kubeNodes = nodes
			h.rb = h.engine()
			h.run(h.rb)
			id := h.start("rb")
			<-nodes.waiting
			if n := nodes.count(); n != 0 {
				t.Fatalf("%d reads before the clusters loaded, want none", n)
			}
			close(nodes.loaded)
			run := h.await(id, tt.status)
			if s := run.Steps[0]; s.Status != tt.step || !strings.Contains(s.Error, tt.errIn) {
				t.Errorf("step = %s %q, want %s with %q", s.Status, s.Error, tt.step, tt.errIn)
			}
			if n := nodes.count(); n != 1 {
				t.Errorf("%d reads, want 1", n)
			}
		})
	}
}

// TestRunbookKubeNodeCheckLoadWithin: the wait for the load is bounded by the
// step's within.
func TestRunbookKubeNodeCheckLoadWithin(t *testing.T) {
	nodes := &fakeNodes{loadGate: loadGate{loaded: make(chan struct{})}, nodes: map[string]error{"pi-1": nil}}
	h := newRBHarness(t, fmt.Sprintf(kubeNodeYAML, "lab", "pi-1", "0s"), policy.Config{})
	h.kubeNodes = nodes
	h.rb = h.engine()
	h.run(h.rb)
	run := h.await(h.start("rb"), RunbookFailed)
	if s := run.Steps[0]; s.Status != stepFailed || !strings.Contains(s.Error, "did not load within 0s") {
		t.Errorf("step = %s %q, want failed: did not load", s.Status, s.Error)
	}
	if n := nodes.count(); n != 0 {
		t.Errorf("%d reads, want none", n)
	}
}

// TestRunbookKubeNodeCheckLoadCancelled: a hub stopping while a check waits
// for the load ends the wait; the run is left to resume.
func TestRunbookKubeNodeCheckLoadCancelled(t *testing.T) {
	nodes := &fakeNodes{loadGate: newLoadGate(), nodes: map[string]error{"pi-1": nil}}
	h := newRBHarness(t, fmt.Sprintf(kubeNodeYAML, "lab", "pi-1", "1h"), policy.Config{})
	h.kubeNodes = nodes
	h.rb = h.engine()
	stop := h.run(h.rb)
	id := h.start("rb")
	<-nodes.waiting
	stop() // returns only once the wait has ended
	if run := h.get(id); run.Status != RunbookRunning {
		t.Errorf("run is %s, want %s: %+v", run.Status, RunbookRunning, run.Steps)
	}
	if n := nodes.count(); n != 0 {
		t.Errorf("%d reads, want none", n)
	}
}

func TestRunbookKubeNodeCheckPlan(t *testing.T) {
	h := newRBHarness(t, fmt.Sprintf(kubeNodeYAML, "lab", "pi-1", "1m"), policy.Config{})
	plan, err := h.rb.Plan(t.Context(), "rb")
	if err != nil {
		t.Fatal(err)
	}
	s := plan.Steps[0]
	if s.Action != string(policy.KubeNodeReady) || s.Class != string(policy.Read) || s.Target != "lab/pi-1" ||
		s.Decision != policy.Allow || !strings.Contains(s.What, "Kubernetes node pi-1 in cluster lab is Ready") {
		t.Errorf("plan step = %+v", s)
	}
}

func TestParseRunbookKubeNodeCheckRejects(t *testing.T) {
	head := "id: rb\nsteps:\n  - type: check\n    check: "
	for _, tc := range []struct{ name, check, want string }{
		{"no cluster", "{type: kube_node, node: pi-1}", "cluster is required"},
		{"bad node", "{type: kube_node, cluster: lab, node: Pi_1}", "node name"},
		{"from a device", "{type: kube_node, cluster: lab, node: pi-1, from: pi}", `unknown field "from"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseRunbook("rb.yaml", []byte(head+tc.check+"\n"), varsKinds())
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

const kubeNodeDeleteYAML = `id: rb
steps:
  - id: forget
    type: action
    action: {type: kube_node_delete, cluster: lab, node: pi-3}
`

func TestRunbookKubeNodeDelete(t *testing.T) {
	grant := policy.Config{DangerousAutomations: []string{RunbookActor("rb")}}
	confirm := policy.Config{Actors: map[string]map[policy.Class]policy.Mode{
		policy.ActorAutomation: {policy.Dangerous: policy.ModeConfirm},
	}}
	for _, tt := range []struct {
		name     string
		cfg      policy.Config
		approve  *bool // decide the held approval
		status   string
		step     string
		runs     int
		decision string
	}{
		{name: "granted", cfg: grant, status: RunbookSucceeded, step: stepOK, runs: 1, decision: policy.Allow},
		{name: "not granted", cfg: policy.Config{}, status: RunbookFailed, step: stepDenied, decision: policy.Deny},
		{name: "held, then approved", cfg: confirm, approve: new(true), status: RunbookSucceeded, step: stepOK, runs: 1, decision: policy.Allow},
		{name: "held, then refused", cfg: confirm, approve: new(false), status: RunbookFailed, step: stepDenied, decision: policy.Deny},
	} {
		t.Run(tt.name, func(t *testing.T) {
			kube := &fakeKube{}
			h := newRBHarness(t, kubeNodeDeleteYAML, tt.cfg)
			maps.Copy(h.kinds.Actions, kubeActions(kube))
			pol := policy.NewWithConfig(h.audit, h.st.Approvals(), tt.cfg)
			h.rb = NewRunbooks(RunbooksConfig{
				Dir: h.dir, Kinds: h.kinds, Policy: pol, Runs: h.st.RunbookRuns(), Sealer: xorSealer{}, Poll: 5 * time.Millisecond,
			})
			h.run(h.rb)
			id := h.start("rb")
			if tt.approve != nil {
				held := awaitApproval(t, h)
				if held.Action != string(policy.KubeNodeDelete) || held.Target != "lab/pi-3" {
					t.Errorf("held = %+v", held)
				}
				if _, runs := kube.calls(); len(runs) != 0 {
					t.Fatalf("ran before it was approved: %v", runs)
				}
				if err := pol.Decide(context.Background(), policy.ActorWeb, "10.0.0.1", held.ID, *tt.approve,
					func(context.Context) error { return nil }); err != nil {
					t.Fatal(err)
				}
			}
			run := h.await(id, tt.status)
			if s := run.Steps[0]; s.Status != tt.step {
				t.Errorf("step = %s %q, want %s", s.Status, s.Error, tt.step)
			}
			if _, runs := kube.calls(); len(runs) != tt.runs || (tt.runs == 1 && runs[0] != "delete_node lab //pi-3") {
				t.Errorf("runs = %q, want %d", runs, tt.runs)
			}
			got := h.audited(policy.KubeNodeDelete)
			if len(got) == 0 {
				t.Fatal("no kube.node.delete audit entry")
			}
			last := got[len(got)-1]
			if last.Decision != tt.decision || last.ActorID != RunbookActor("rb") || last.Target != "lab/pi-3" {
				t.Errorf("audit = %+v", got)
			}
		})
	}
}

// TestRunbookKubeNodeDeleteWaitsForLoad: a Kubernetes action started while
// the hub is still loading its clusters waits for the load.
func TestRunbookKubeNodeDeleteWaitsForLoad(t *testing.T) {
	kube := &fakeKube{loadGate: newLoadGate()}
	cfg := policy.Config{DangerousAutomations: []string{RunbookActor("rb")}}
	h := newRBHarness(t, kubeNodeDeleteYAML, cfg)
	maps.Copy(h.kinds.Actions, kubeActions(kube))
	h.cfg = cfg
	h.rb = h.engine()
	h.run(h.rb)
	id := h.start("rb")
	<-kube.waiting
	if _, runs := kube.calls(); len(runs) != 0 {
		t.Fatalf("ran before the clusters loaded: %v", runs)
	}
	close(kube.loaded)
	h.await(id, RunbookSucceeded)
	if _, runs := kube.calls(); len(runs) != 1 {
		t.Errorf("runs = %q, want one", runs)
	}
}

// awaitApproval waits for the one pending approval.
func awaitApproval(t *testing.T, h *rbHarness) store.Approval {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		pending, err := h.st.Approvals().List(t.Context(), store.ApprovalPending, 10)
		if err != nil {
			t.Fatal(err)
		}
		if len(pending) == 1 {
			return pending[0]
		}
		if time.Now().After(deadline) {
			t.Fatal("nothing was held for approval")
		}
		time.Sleep(5 * time.Millisecond)
	}
}
