// SPDX-License-Identifier: AGPL-3.0-only

package automation

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/gvart/hearth/internal/integrations/kubernetes"
	"github.com/gvart/hearth/internal/policy"
)

// fakeKube records the requests it gets. Like *kubernetes.Manager, it runs
// an action only in a context policy granted it.
type fakeKube struct {
	loadGate

	mu    sync.Mutex
	plans []string
	runs  []string
}

func kubeCall(cluster string, req kubernetes.ActionRequest) string {
	return fmt.Sprintf("%s %s %s/%s/%s", req.Action, cluster, req.Kind, req.Namespace, req.Name)
}

func (k *fakeKube) PlanAction(_ context.Context, cluster string, req kubernetes.ActionRequest) (kubernetes.ActionResult, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.plans = append(k.plans, kubeCall(cluster, req))
	return kubernetes.ActionResult{Summary: "Drain node " + req.Name + ".", Steps: []string{"Cordon the node"}, Warnings: []string{"lonely pod"}}, nil
}

func (k *fakeKube) RunAction(ctx context.Context, cluster string, req kubernetes.ActionRequest) (kubernetes.ActionResult, error) {
	pa, err := kubernetes.RequestPolicy(req)
	if err != nil {
		return kubernetes.ActionResult{}, err
	}
	if !policy.Granted(ctx, pa) {
		return kubernetes.ActionResult{}, kubernetes.ErrNotGranted
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	k.runs = append(k.runs, kubeCall(cluster, req))
	return kubernetes.ActionResult{Result: "done"}, nil
}

// loadGate is a hub loading its clusters: loaded at once if loaded is nil,
// else once it is closed. A wait that starts is told on waiting, if set and
// not full.
type loadGate struct {
	loaded  chan struct{}
	waiting chan struct{}
}

func (g *loadGate) WaitLoaded(ctx context.Context) error {
	if g.loaded == nil {
		return nil
	}
	select {
	case g.waiting <- struct{}{}:
	default:
	}
	select {
	case <-g.loaded:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// newLoadGate returns a gate still loading, and its waiting channel.
func newLoadGate() loadGate {
	return loadGate{loaded: make(chan struct{}), waiting: make(chan struct{}, 1)}
}

func (k *fakeKube) calls() (plans, runs []string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	return append([]string(nil), k.plans...), append([]string(nil), k.runs...)
}

func kubeAutomation(id, action string) string {
	return "id: " + id + "\ntriggers:\n  - id: go\n    type: manual\nactions:\n" + action
}

const restartAction = `  - id: restart-web
    type: kube_restart
    cluster: lab
    kind: Deployment
    namespace: default
    name: web
`

const drainAction = `  - id: drain
    type: kube_drain
    cluster: lab
    node: pi-1
    timeout: 90s
`

func TestKubeRestartAutomation(t *testing.T) {
	kube := &fakeKube{}
	rec, audit := runOnce(t, kubeAutomation("nightly-web", restartAction), ActionDeps{Kube: kube})
	if run := rec.all()[0]; run.Status != StatusSucceeded {
		t.Fatalf("run = %+v", run)
	}
	if _, runs := kube.calls(); len(runs) != 1 || runs[0] != "restart lab Deployment/default/web" {
		t.Errorf("runs = %q", runs)
	}
	es := audit.all()
	if len(es) != 1 {
		t.Fatalf("audit = %+v, want one entry", es)
	}
	e := es[0]
	if e.ActorKind != policy.ActorAutomation || e.ActorID != "nightly-web" || e.Action != string(policy.KubeWorkloadRestart) ||
		e.Target != "lab/Deployment/default/web" || e.Decision != policy.Allow || e.Result != "ok" {
		t.Errorf("audit = %+v", e)
	}
}

// A drain is dangerous: denied unless the automation is granted it, and
// then nothing reaches the cluster, not even the plan's reads.
func TestKubeDrainNeedsAGrant(t *testing.T) {
	kube := &fakeKube{}
	rec, audit := runOnce(t, kubeAutomation("drainer", drainAction), ActionDeps{Kube: kube})
	if run := rec.all()[0]; run.Status != StatusDenied {
		t.Errorf("run = %+v, want denied", run)
	}
	if plans, runs := kube.calls(); len(plans)+len(runs) != 0 {
		t.Errorf("a denied drain reached the cluster: %q %q", plans, runs)
	}
	if e := audit.all()[0]; e.Decision != policy.Deny || e.ActorID != "drainer" || e.Action != string(policy.KubeNodeDrain) {
		t.Errorf("audit = %+v", e)
	}

	rec, audit = runOnce(t, kubeAutomation("drainer", drainAction), ActionDeps{Kube: kube}, "drainer")
	if run := rec.all()[0]; run.Status != StatusSucceeded {
		t.Errorf("granted run = %+v", run)
	}
	if _, runs := kube.calls(); len(runs) != 1 || runs[0] != "drain lab //pi-1" {
		t.Errorf("runs = %q", runs)
	}
	if e := audit.all()[0]; e.Decision != policy.Allow || e.Target != "lab/pi-1" {
		t.Errorf("audit = %+v", e)
	}
}

// Outside a policy decision, the action never runs.
func TestKubeActionOutsidePolicy(t *testing.T) {
	kube := &fakeKube{}
	a, err := Parse("test.yaml", []byte(kubeAutomation("x", restartAction)), actionKinds(ActionDeps{Kube: kube}))
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Actions[0].Impl.Run(t.Context(), Event{}); !errors.Is(err, kubernetes.ErrNotGranted) {
		t.Errorf("Run outside policy = %v, want ErrNotGranted", err)
	}
}

// onceTrigger fires once, with its sample, when watched.
type onceTrigger struct{ sample map[string]any }

func (o onceTrigger) Describe() string       { return "fires once" }
func (o onceTrigger) Sample() map[string]any { return o.sample }
func (o onceTrigger) Watch(ctx context.Context, fire FireFunc) error {
	fire(o.sample)
	<-ctx.Done()
	return nil
}

func TestKubeActionTemplates(t *testing.T) {
	kube := &fakeKube{}
	kinds := actionKinds(ActionDeps{Kube: kube})
	kinds.Triggers["once"] = func(p Params) (Trigger, error) {
		return onceTrigger{sample: map[string]any{"Cluster": "lab", "Namespace": "media", "Name": "jellyfin-0"}}, p.Decode(&struct{}{})
	}
	a, err := Parse("test.yaml", []byte(`id: tmpl
triggers:
  - id: t
    type: once
actions:
  - type: kube_delete_pod
    cluster: "{{ .Trigger.Cluster }}"
    namespace: "{{ .Trigger.Namespace }}"
    name: "{{ .Trigger.Name }}"
`), kinds)
	if err != nil {
		t.Fatal(err)
	}
	if got := a.Actions[0].ID; got != "kube_delete_pod-1" {
		t.Errorf("default step id = %q", got)
	}
	rec, audit := &recorder{}, &auditLog{}
	rt := New(Config{Kinds: kinds, Policy: policy.New(audit), Runs: rec})
	ctx, cancel := context.WithCancel(t.Context())
	rt.reconcile(ctx, []*Automation{a})
	t.Cleanup(func() { cancel(); rt.reconcile(ctx, nil) })
	eventually(t, "the run recorded", func() bool { return len(rec.all()) == 1 })
	if _, runs := kube.calls(); len(runs) != 1 || runs[0] != "delete_pod lab /media/jellyfin-0" {
		t.Errorf("runs = %q", runs)
	}
	if e := audit.all()[0]; e.Target != "lab/media/jellyfin-0" || e.Action != string(policy.KubePodDelete) {
		t.Errorf("audit = %+v", e)
	}

	// A field no trigger provides is caught at load.
	_, err = Parse("test.yaml", []byte(kubeAutomation("x", `  - type: kube_cordon
    cluster: lab
    node: "{{ .Trigger.Node }}"
`)), kinds)
	if err == nil || !strings.Contains(err.Error(), ".Trigger.Node: no such field") {
		t.Errorf("unknown field = %v", err)
	}
}

func TestKubeActionInvalid(t *testing.T) {
	kinds := actionKinds(ActionDeps{})
	for want, action := range map[string]string{
		"cluster is required":        "  - type: kube_cordon\n    node: pi-1\n",
		"node is required":           "  - type: kube_drain\n    cluster: lab\n",
		"namespace is required":      "  - type: kube_delete_pod\n    cluster: lab\n    name: web-1\n",
		"kind must be Deployment":    "  - type: kube_restart\n    cluster: lab\n    kind: Job\n    namespace: default\n    name: web\n",
		"replicas must be 0 or more": "  - type: kube_scale\n    cluster: lab\n    kind: Deployment\n    namespace: default\n    name: web\n",
		"timeout_seconds must be":    "  - type: kube_drain\n    cluster: lab\n    node: pi-1\n    timeout: 1h\n",
		"name must be a Kubernetes":  "  - type: kube_uncordon\n    cluster: lab\n    node: ../etc\n",
		`unknown field "replicas"`:   "  - type: kube_restart\n    cluster: lab\n    kind: Deployment\n    namespace: default\n    name: web\n    replicas: 2\n",
	} {
		_, err := Parse("test.yaml", []byte(kubeAutomation("x", action)), kinds)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: err = %v, want %q", action, err, want)
		}
	}
	// Without a Kubernetes integration a valid file loads, and fails to run.
	a, err := Parse("test.yaml", []byte(kubeAutomation("x", restartAction)), kinds)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Actions[0].Impl.Run(t.Context(), Event{}); err == nil {
		t.Error("ran without a Kubernetes integration")
	}
}

// A dry run plans what policy would allow and runs nothing; what it would
// deny it denies without planning.
func TestKubeDryRun(t *testing.T) {
	kube := &fakeKube{}
	kinds := actionKinds(ActionDeps{Kube: kube})
	dry := func(granted ...string) *recorder {
		a, err := Parse("test.yaml", []byte(kubeAutomation("drainer", drainAction)), kinds)
		if err != nil {
			t.Fatal(err)
		}
		rec := &recorder{}
		pol := policy.NewWithConfig(&auditLog{}, nil, policy.Config{DangerousAutomations: granted})
		rt := New(Config{Kinds: kinds, Policy: pol, Runs: rec, DryRun: true})
		ctx, cancel := context.WithCancel(t.Context())
		rt.reconcile(ctx, []*Automation{a})
		defer func() { cancel(); rt.reconcile(ctx, nil) }()
		if err := rt.Fire(a.ID, "go"); err != nil {
			t.Fatal(err)
		}
		eventually(t, "the run recorded", func() bool { return len(rec.all()) == 1 })
		return rec
	}

	if run := dry().all()[0]; run.Status != StatusDenied {
		t.Errorf("ungranted dry run = %+v, want denied", run)
	}
	if plans, _ := kube.calls(); len(plans) != 0 {
		t.Errorf("a denied dry run planned: %q", plans)
	}

	run := dry("drainer").all()[0]
	st := steps(t, run)
	if run.Status != StatusSucceeded || st[1].Plan != "Drain node pi-1.\n- Cordon the node\nwarning: lonely pod" {
		t.Errorf("granted dry run = %+v, steps %+v", run, st)
	}
	if plans, runs := kube.calls(); len(plans) != 1 || len(runs) != 0 {
		t.Errorf("plans %q, runs %q; want one plan, no run", plans, runs)
	}
}

func TestKubePlan(t *testing.T) {
	a, err := Parse("test.yaml", []byte(kubeAutomation("drainer", restartAction+drainAction)), actionKinds(ActionDeps{}))
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	if err := Plan(&b, a); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"restart-web (kube_restart): rolling restart of Deployment default/web in cluster lab, as kubectl rollout restart on lab/Deployment/default/web",
		"policy: kube.workload.restart (safe), actor automation/drainer",
		"drain (kube_drain): drain node pi-1 in cluster lab: cordon it and evict its pods, honouring PodDisruptionBudgets, waiting up to 1m30s on lab/pi-1",
		"policy: kube.node.drain (dangerous), actor automation/drainer",
	} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("plan lacks %q:\n%s", want, b.String())
		}
	}
}
