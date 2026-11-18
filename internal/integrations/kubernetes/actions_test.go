// SPDX-License-Identifier: AGPL-3.0-only

package kubernetes

import (
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

const webActor = "192.0.2.1"

func ptr[T any](v T) *T { return &v }

// ownedPod is a pod on node of a controller kind/name.
func ownedPod(ns, name, node, kind, owner string) map[string]any {
	p := podObj(ns, name, true)
	p["spec"].(map[string]any)["nodeName"] = node
	if kind != "" {
		p["metadata"].(map[string]any)["ownerReferences"] = []any{
			map[string]any{"kind": kind, "name": owner, "controller": true},
		}
	}
	return p
}

// actionCluster is a connected cluster with a node, a Deployment and its
// pods.
func actionCluster(t *testing.T) (*fixture, ClusterInfo) {
	t.Helper()
	f := newFixture(t)
	f.api.put("/api/v1/nodes", nodeObj("pi-1", "192.168.2.131", true))
	f.api.put("/api/v1/nodes", nodeObj("pi-2", "192.168.2.132", true))
	f.api.put("/apis/apps/v1/deployments", map[string]any{
		"metadata": meta("default", "web"),
		"spec":     map[string]any{"replicas": 2, "strategy": map[string]any{"type": "RollingUpdate"}},
		"status":   map[string]any{"readyReplicas": 2},
	})
	f.api.put("/apis/apps/v1/daemonsets", map[string]any{
		"metadata": meta("kube-system", "proxy"),
		"status":   map[string]any{"desiredNumberScheduled": 2, "numberReady": 2},
	})
	f.api.put("/api/v1/pods", ownedPod("default", "web-1", "pi-1", "ReplicaSet", "web-abc"))
	f.api.put("/api/v1/pods", ownedPod("default", "web-2", "pi-1", "ReplicaSet", "web-abc"))
	f.api.put("/api/v1/pods", ownedPod("default", "web-3", "pi-2", "ReplicaSet", "web-abc"))
	f.api.put("/api/v1/pods", ownedPod("default", "lonely", "pi-1", "", ""))
	f.api.put("/api/v1/pods", ownedPod("kube-system", "proxy-x", "pi-1", "DaemonSet", "proxy"))
	mirror := ownedPod("kube-system", "etcd-pi-1", "pi-1", "Node", "pi-1")
	mirror["metadata"].(map[string]any)["annotations"] = map[string]any{mirrorAnnotation: "abc"}
	f.api.put("/api/v1/pods", mirror)
	f.m.evictRetry, f.m.gonePoll = 10*time.Millisecond, 10*time.Millisecond
	return f, f.addCluster(t)
}

var everyAction = []ActionRequest{
	{Action: ActionRestart, Kind: "Deployment", Namespace: "default", Name: "web"},
	{Action: ActionScale, Kind: "Deployment", Namespace: "default", Name: "web", Replicas: ptr[int32](3)},
	{Action: ActionDeletePod, Namespace: "default", Name: "web-1"},
	{Action: ActionCordon, Name: "pi-1"},
	{Action: ActionUncordon, Name: "pi-1"},
	{Action: ActionDrain, Name: "pi-1"},
}

func auditOf(t *testing.T, st *store.Store, action policy.Action) []store.AuditEntry {
	t.Helper()
	entries, err := st.Audit().List(t.Context(), 1000)
	if err != nil {
		t.Fatal(err)
	}
	var out []store.AuditEntry
	for _, e := range entries {
		if e.Action == string(action) {
			out = append(out, e)
		}
	}
	return out
}

// A denied action sends nothing to the cluster: not even the reads of its
// plan. It is audited as denied.
func TestActionDeniedHasNoSideEffect(t *testing.T) {
	f, info := actionCluster(t)
	before := f.api.object("/api/v1/nodes", "/pi-1")
	for _, req := range everyAction {
		t.Run(req.Action, func(t *testing.T) {
			_, err := f.m.Act(t.Context(), "", info.ID, req) // an anonymous actor
			if !errors.Is(err, policy.ErrDenied) {
				t.Fatalf("Act = %v, want ErrDenied", err)
			}
		})
	}
	if got := f.api.actionRequests(); len(got) != 0 {
		t.Errorf("denied actions sent %v to the cluster", got)
	}
	if after := f.api.object("/api/v1/nodes", "/pi-1"); !reflect.DeepEqual(before, after) {
		t.Errorf("node changed: %v -> %v", before, after)
	}
	if f.api.object("/api/v1/pods", "default/web-1") == nil {
		t.Error("a denied delete deleted the pod")
	}
	for _, a := range []policy.Action{policy.KubeWorkloadRestart, policy.KubeWorkloadScale, policy.KubePodDelete,
		policy.KubeNodeCordon, policy.KubeNodeUncordon, policy.KubeNodeDrain} {
		es := auditOf(t, f.st, a)
		if len(es) != 1 || es[0].Decision != policy.Deny || !strings.HasPrefix(es[0].Target, "lab/") {
			t.Errorf("audit of %s = %+v, want one denial", a, es)
		}
	}
}

// A dry run reads and plans; it writes nothing and is not audited.
func TestActionDryRun(t *testing.T) {
	f, info := actionCluster(t)
	want := map[string]struct {
		summary, step, warning string
		class                  policy.Class
	}{
		ActionRestart:   {"Restart Deployment default/web: replace its 2 pods", restartedAtAnnotation, "", policy.Safe},
		ActionScale:     {"Scale Deployment default/web from 2 to 3 replicas.", "spec.replicas to 3", "", policy.Safe},
		ActionDeletePod: {"Delete pod default/web-1 (Running, on node pi-1).", "ReplicaSet/web-abc creates a replacement", "", policy.Safe},
		ActionCordon:    {"Cordon node pi-1", "unschedulable to true", "", policy.Safe},
		ActionUncordon:  {"Node pi-1 is not cordoned: nothing changes.", "", "", policy.Safe},
		ActionDrain:     {"Drain node pi-1: cordon it, then evict its 3 pods", "Skip DaemonSet pods: kube-system/proxy-x", "No controller recreates these pods: default/lonely", policy.Dangerous},
	}
	for _, req := range everyAction {
		t.Run(req.Action, func(t *testing.T) {
			req.DryRun = true
			res, err := f.m.Act(t.Context(), webActor, info.ID, req)
			if err != nil {
				t.Fatal(err)
			}
			w := want[req.Action]
			if !res.DryRun || res.Result != "" || res.Class != string(w.class) || !strings.HasPrefix(res.Summary, w.summary) {
				t.Errorf("plan = %+v, want summary %q, class %s", res, w.summary, w.class)
			}
			if w.step != "" && !slices.ContainsFunc(res.Steps, func(s string) bool { return strings.Contains(s, w.step) }) {
				t.Errorf("steps = %q, want one with %q", res.Steps, w.step)
			}
			if w.warning != "" && !slices.Contains(res.Warnings, w.warning) {
				t.Errorf("warnings = %q, want %q", res.Warnings, w.warning)
			}
		})
	}
	for _, r := range f.api.actionRequests() {
		if !strings.HasPrefix(r, "GET ") {
			t.Errorf("a dry run sent %s", r)
		}
	}
	drain, _ := f.m.Act(t.Context(), webActor, info.ID, ActionRequest{Action: ActionDrain, Name: "pi-1", DryRun: true})
	if !slices.Contains(drain.Steps, "Skip static (mirror) pods: kube-system/etcd-pi-1") ||
		!slices.Contains(drain.Steps, "Evict default/web-1") || slices.Contains(drain.Steps, "Evict default/web-3") {
		t.Errorf("drain steps = %q", drain.Steps)
	}
	if es, _ := f.st.Audit().List(t.Context(), 100); slices.ContainsFunc(es, func(e store.AuditEntry) bool {
		return strings.HasPrefix(e.Action, "kube.workload") || strings.HasPrefix(e.Action, "kube.node")
	}) {
		t.Errorf("a dry run was audited: %+v", es)
	}
}

func TestActionsApply(t *testing.T) {
	f, info := actionCluster(t)
	act := func(req ActionRequest) ActionResult {
		t.Helper()
		res, err := f.m.Act(t.Context(), webActor, info.ID, req)
		if err != nil {
			t.Fatalf("%s: %v", req.Action, err)
		}
		if res.DryRun || res.Result == "" {
			t.Errorf("%s = %+v, want a result", req.Action, res)
		}
		return res
	}

	act(everyAction[0])
	dep := f.api.object("/apis/apps/v1/deployments", "default/web")
	ann, _ := dep["spec"].(map[string]any)["template"].(map[string]any)["metadata"].(map[string]any)["annotations"].(map[string]any)
	if _, ok := ann[restartedAtAnnotation]; !ok {
		t.Errorf("restart: template annotations = %v", ann)
	}

	act(everyAction[1])
	if r := f.api.object("/apis/apps/v1/deployments", "default/web")["spec"].(map[string]any)["replicas"]; r != 3.0 {
		t.Errorf("scale: replicas = %v, want 3", r)
	}
	if res := act(everyAction[1]); res.Result != "Nothing to do." {
		t.Errorf("scale to the same count = %+v", res)
	}

	act(everyAction[2])
	if f.api.object("/api/v1/pods", "default/web-1") != nil {
		t.Error("delete: the pod is still there")
	}

	unschedulable := func() any {
		return f.api.object("/api/v1/nodes", "/pi-2")["spec"].(map[string]any)["unschedulable"]
	}
	act(ActionRequest{Action: ActionCordon, Name: "pi-2"})
	if u := unschedulable(); u != true {
		t.Errorf("cordon: unschedulable = %v", u)
	}
	act(ActionRequest{Action: ActionUncordon, Name: "pi-2"})
	if u := unschedulable(); u != false {
		t.Errorf("uncordon: unschedulable = %v", u)
	}

	for _, a := range []policy.Action{policy.KubeWorkloadRestart, policy.KubePodDelete, policy.KubeNodeCordon, policy.KubeNodeUncordon} {
		es := auditOf(t, f.st, a)
		if len(es) != 1 || es[0].Decision != policy.Allow || es[0].Result != "ok" || es[0].ActorID != webActor {
			t.Errorf("audit of %s = %+v", a, es)
		}
	}
	if es := auditOf(t, f.st, policy.KubeWorkloadScale); len(es) != 2 || !strings.Contains(string(es[0].Detail), `"replicas":3`) {
		t.Errorf("audit of scale = %+v", es)
	}
}

// A drain cordons, evicts every pod but DaemonSet and mirror pods through
// the Eviction API and retries an eviction a PodDisruptionBudget refuses.
func TestDrainHonoursDisruptionBudgets(t *testing.T) {
	f, info := actionCluster(t)
	f.api.mu.Lock()
	f.api.refuse["default/web-2"] = 3
	f.api.mu.Unlock()

	res, err := f.m.Act(t.Context(), webActor, info.ID, ActionRequest{Action: ActionDrain, Name: "pi-1"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Result != "Drained node pi-1: evicted 3 pods." {
		t.Errorf("result = %q", res.Result)
	}
	if u := f.api.object("/api/v1/nodes", "/pi-1")["spec"].(map[string]any)["unschedulable"]; u != true {
		t.Errorf("node not cordoned: unschedulable = %v", u)
	}
	for key, want := range map[string]bool{
		"default/web-1": false, "default/web-2": false, "default/lonely": false,
		"kube-system/proxy-x": true, "kube-system/etcd-pi-1": true, "default/web-3": true,
	} {
		if got := f.api.object("/api/v1/pods", key) != nil; got != want {
			t.Errorf("pod %s there = %v, want %v", key, got, want)
		}
	}
	evictions := map[string]int{}
	for _, r := range f.api.actionRequests() {
		if strings.HasPrefix(r, "DELETE ") {
			t.Errorf("drain deleted a pod instead of evicting it: %s", r)
		}
		if p, ok := strings.CutSuffix(r, "/eviction"); ok {
			evictions[p[strings.LastIndex(p, "/")+1:]]++
		}
	}
	if want := map[string]int{"web-1": 1, "web-2": 4, "lonely": 1}; !reflect.DeepEqual(evictions, want) {
		t.Errorf("evictions = %v, want %v", evictions, want)
	}
	if es := auditOf(t, f.st, policy.KubeNodeDrain); len(es) != 1 || es[0].Result != "ok" {
		t.Errorf("audit = %+v", es)
	}
}

// A budget that never allows the eviction ends the drain at its timeout,
// with the node cordoned and the pod in place.
func TestDrainTimeout(t *testing.T) {
	f, info := actionCluster(t)
	f.api.mu.Lock()
	f.api.refuse["default/web-2"] = 1 << 30
	f.api.mu.Unlock()

	start := time.Now()
	_, err := f.m.Act(t.Context(), webActor, info.ID, ActionRequest{Action: ActionDrain, Name: "pi-1", TimeoutSeconds: 1})
	if err == nil || !strings.Contains(err.Error(), "default/web-2 (refused: Cannot evict pod as it would violate the pod's disruption budget.)") ||
		!strings.Contains(err.Error(), "timed out after 1s") {
		t.Fatalf("Act = %v, want a timeout naming the refused pod", err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("drain took %v, past its timeout", d)
	}
	if f.api.object("/api/v1/pods", "default/web-2") == nil || f.api.object("/api/v1/pods", "default/web-1") != nil {
		t.Error("want web-2 kept by its budget and web-1 evicted")
	}
	if u := f.api.object("/api/v1/nodes", "/pi-1")["spec"].(map[string]any)["unschedulable"]; u != true {
		t.Errorf("node not cordoned: unschedulable = %v", u)
	}
	if es := auditOf(t, f.st, policy.KubeNodeDrain); len(es) != 1 || !strings.HasPrefix(es[0].Result, "error: ") {
		t.Errorf("audit = %+v", es)
	}
}

func TestActionInvalid(t *testing.T) {
	f, info := actionCluster(t)
	for _, req := range []ActionRequest{
		{Action: "reboot", Name: "pi-1"},
		{Action: ActionCordon, Name: "../pi-1"},
		{Action: ActionDeletePod, Name: "web-1"},
		{Action: ActionRestart, Kind: "Job", Namespace: "default", Name: "web"},
		{Action: ActionScale, Kind: "DaemonSet", Namespace: "kube-system", Name: "proxy", Replicas: ptr[int32](1)},
		{Action: ActionScale, Kind: "Deployment", Namespace: "default", Name: "web"},
		{Action: ActionScale, Kind: "Deployment", Namespace: "default", Name: "web", Replicas: ptr[int32](-1)},
		{Action: ActionDrain, Name: "pi-1", TimeoutSeconds: 3600},
		{Action: ActionDrain, Name: "pi-1", TimeoutSeconds: -1},
	} {
		if _, err := f.m.Act(t.Context(), webActor, info.ID, req); !errors.Is(err, ErrBadAction) {
			t.Errorf("Act(%+v) = %v, want ErrBadAction", req, err)
		}
	}
	_, err := f.m.Act(t.Context(), webActor, info.ID, ActionRequest{Action: ActionCordon, Name: "pi-9", DryRun: true})
	if !errors.Is(err, ErrObjectNotFound) {
		t.Errorf("cordon of an unknown node = %v, want ErrObjectNotFound", err)
	}
	if _, err := f.m.Act(t.Context(), webActor, "nope", everyAction[0]); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown cluster = %v", err)
	}
	if got := f.api.actionRequests(); len(got) != 1 {
		t.Errorf("invalid actions sent %v", got)
	}
}
