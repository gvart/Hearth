// SPDX-License-Identifier: AGPL-3.0-only

package kubernetes

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"

	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

// fakeClients reads from a client-go fake clientset.
func fakeClients(cs *fake.Clientset) clients {
	core, apps := cs.CoreV1(), cs.AppsV1()
	lw := func(list cache.ListWithContextFunc, w cache.WatchFuncWithContext) cache.ListerWatcher {
		return cache.ToListWatcherWithWatchListSemantics(
			&cache.ListWatch{ListWithContextFunc: list, WatchFuncWithContext: w}, cs)
	}
	return clients{
		lw: map[string]cache.ListerWatcher{
			resNodes: lw(
				func(ctx context.Context, o metav1.ListOptions) (runtime.Object, error) {
					return core.Nodes().List(ctx, o)
				},
				func(ctx context.Context, o metav1.ListOptions) (watch.Interface, error) {
					return core.Nodes().Watch(ctx, o)
				}),
			resNamespaces: lw(
				func(ctx context.Context, o metav1.ListOptions) (runtime.Object, error) {
					return core.Namespaces().List(ctx, o)
				},
				func(ctx context.Context, o metav1.ListOptions) (watch.Interface, error) {
					return core.Namespaces().Watch(ctx, o)
				}),
			resPods: lw(
				func(ctx context.Context, o metav1.ListOptions) (runtime.Object, error) {
					return core.Pods("").List(ctx, o)
				},
				func(ctx context.Context, o metav1.ListOptions) (watch.Interface, error) {
					return core.Pods("").Watch(ctx, o)
				}),
			resEvents: lw(
				func(ctx context.Context, o metav1.ListOptions) (runtime.Object, error) {
					return core.Events("").List(ctx, o)
				},
				func(ctx context.Context, o metav1.ListOptions) (watch.Interface, error) {
					return core.Events("").Watch(ctx, o)
				}),
			resDeployments: lw(
				func(ctx context.Context, o metav1.ListOptions) (runtime.Object, error) {
					return apps.Deployments("").List(ctx, o)
				},
				func(ctx context.Context, o metav1.ListOptions) (watch.Interface, error) {
					return apps.Deployments("").Watch(ctx, o)
				}),
			resStatefulSets: lw(
				func(ctx context.Context, o metav1.ListOptions) (runtime.Object, error) {
					return apps.StatefulSets("").List(ctx, o)
				},
				func(ctx context.Context, o metav1.ListOptions) (watch.Interface, error) {
					return apps.StatefulSets("").Watch(ctx, o)
				}),
			resDaemonSets: lw(
				func(ctx context.Context, o metav1.ListOptions) (runtime.Object, error) {
					return apps.DaemonSets("").List(ctx, o)
				},
				func(ctx context.Context, o metav1.ListOptions) (watch.Interface, error) {
					return apps.DaemonSets("").Watch(ctx, o)
				}),
		},
		logs: func(ctx context.Context, namespace, pod string, o podLogOptions) ([]byte, error) {
			if _, err := core.Pods(namespace).Get(ctx, pod, metav1.GetOptions{}); err != nil {
				return nil, err
			}
			return core.Pods(namespace).GetLogs(pod, &corev1.PodLogOptions{Container: o.container}).DoRaw(ctx)
		},
	}
}

type fixture struct {
	m     *Manager
	st    *store.Store
	cs    *fake.Clientset
	notes <-chan Notice
}

// newFixture runs a manager whose clusters all read from one fake
// clientset seeded with objs.
func newFixture(t *testing.T, objs ...runtime.Object) *fixture {
	t.Helper()
	st, err := store.Open(t.Context(), filepath.Join(t.TempDir(), "hearth.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	sealer, err := NewSealer([]byte("test CA key"))
	if err != nil {
		t.Fatal(err)
	}
	cs := fake.NewClientset(objs...)
	m := NewManager(Config{Store: st, Sealer: sealer, Policy: policy.New(st.Audit()), SyncInterval: 50 * time.Millisecond})
	m.connect = func(*kubeconfig) (clients, error) { return fakeClients(cs), nil }
	notes, unsubscribe := m.Subscribe()
	t.Cleanup(unsubscribe)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- m.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Run: %v", err)
		}
	})
	return &fixture{m: m, st: st, cs: cs, notes: notes}
}

// waitNotice returns the first notice match accepts, failing after within.
func (f *fixture) waitNotice(t *testing.T, within time.Duration, match func(Notice) bool) Notice {
	t.Helper()
	timeout := time.After(within)
	for {
		select {
		case n, ok := <-f.notes:
			if !ok {
				t.Fatal("notice stream closed")
			}
			if match(n) {
				return n
			}
		case <-timeout:
			t.Fatalf("no matching notice within %v", within)
		}
	}
}

func (f *fixture) addCluster(t *testing.T) ClusterInfo {
	t.Helper()
	info, err := f.m.Add(t.Context(), "192.0.2.1", "", []byte(testKubeconfig))
	if err != nil {
		t.Fatal(err)
	}
	f.waitNotice(t, 5*time.Second, func(n Notice) bool {
		c, ok := n.Data.(ClusterInfo)
		return ok && c.ID == info.ID && c.State == StateConnected
	})
	return info
}

func pod(ns, name string, ready bool) *corev1.Pod {
	state := corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "ContainerCreating"}}
	phase := corev1.PodPending
	if ready {
		state, phase = corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}, corev1.PodRunning
	}
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, ManagedFields: []metav1.ManagedFieldsEntry{{Manager: "kubectl"}}},
		Spec:       corev1.PodSpec{NodeName: "pi-1", Containers: []corev1.Container{{Name: "app"}}},
		Status: corev1.PodStatus{Phase: phase, ContainerStatuses: []corev1.ContainerStatus{
			{Name: "app", Ready: ready, State: state},
		}},
	}
}

func TestManagerAddWatchRemove(t *testing.T) {
	replicas := int32(2)
	f := newFixture(t,
		&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "pi-1"}, Status: corev1.NodeStatus{
			Addresses:  []corev1.NodeAddress{{Type: corev1.NodeInternalIP, Address: "192.168.2.131"}},
			Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue}},
		}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "default"}},
		&appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "web"},
			Spec:       appsv1.DeploymentSpec{Replicas: &replicas}, Status: appsv1.DeploymentStatus{ReadyReplicas: 1},
		},
		&corev1.Event{
			ObjectMeta:     metav1.ObjectMeta{Namespace: "default", Name: "web.1", UID: "e1"},
			InvolvedObject: corev1.ObjectReference{Kind: "Pod", Name: "web-1"}, Type: "Warning", Reason: "BackOff",
		},
		pod("default", "web-1", true),
	)
	ctx := t.Context()
	if err := f.st.Devices().Upsert(ctx, device("dev-pi", "raspberrypi", "192.168.2.131/24")); err != nil {
		t.Fatal(err)
	}

	info := f.addCluster(t)
	if info.Name != "lab" || info.Server != "https://192.0.2.10:6443" {
		t.Errorf("Add = %+v, want the current context's name and server", info)
	}

	// The kubeconfig is stored sealed, never in the clear.
	stored, err := f.st.KubeClusters().List(ctx)
	if err != nil || len(stored) != 1 {
		t.Fatalf("stored clusters = %v, %v", stored, err)
	}
	if strings.Contains(string(stored[0].Sealed), "lab-secret-token") {
		t.Fatal("the stored kubeconfig holds the token in the clear")
	}

	snap, err := f.m.Snapshot(ctx, info.ID)
	if err != nil {
		t.Fatal(err)
	}
	if snap.Cluster.State != StateConnected || snap.Cluster.Nodes != 1 || snap.Cluster.Pods != 1 {
		t.Errorf("cluster = %+v", snap.Cluster)
	}
	if len(snap.Nodes) != 1 || snap.Nodes[0].DeviceID != "dev-pi" || !snap.Nodes[0].Ready {
		t.Errorf("nodes = %+v, want pi-1 linked to dev-pi", snap.Nodes)
	}
	if len(snap.Namespaces) != 1 || len(snap.Workloads) != 1 || snap.Workloads[0].Desired != 2 ||
		len(snap.Events) != 1 || snap.Events[0].Object != "pod/web-1" {
		t.Errorf("snapshot = %+v", snap)
	}
	if len(snap.Pods) != 1 || snap.Pods[0].Status != "Running" {
		t.Errorf("pods = %+v", snap.Pods)
	}

	// A pod's status change is streamed, and so are a new pod and a deletion.
	p := pod("default", "web-1", false)
	start := time.Now()
	if _, err := f.cs.CoreV1().Pods("default").UpdateStatus(ctx, p, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	n := f.waitNotice(t, 5*time.Second, func(n Notice) bool {
		c, ok := n.Data.(Change)
		return ok && c.Kind == KindPod && c.Key == "default/web-1"
	})
	t.Logf("pod status change notice after %v", time.Since(start))
	if c := n.Data.(Change); c.Op != OpUpsert || c.Object.(Pod).Status != "ContainerCreating" {
		t.Errorf("change = %+v", c)
	}
	if _, err := f.cs.CoreV1().Pods("default").Create(ctx, pod("default", "web-2", true), metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	f.waitNotice(t, 5*time.Second, func(n Notice) bool {
		c, ok := n.Data.(Change)
		return ok && c.Op == OpUpsert && c.Key == "default/web-2"
	})
	if err := f.cs.CoreV1().Pods("default").Delete(ctx, "web-1", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	f.waitNotice(t, 5*time.Second, func(n Notice) bool {
		c, ok := n.Data.(Change)
		return ok && c.Op == OpDelete && c.Key == "default/web-1"
	})

	// A node change carries its device link.
	node, _ := f.cs.CoreV1().Nodes().Get(ctx, "pi-1", metav1.GetOptions{})
	node.Spec.Unschedulable = true
	if _, err := f.cs.CoreV1().Nodes().Update(ctx, node, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	n = f.waitNotice(t, 5*time.Second, func(n Notice) bool {
		c, ok := n.Data.(Change)
		return ok && c.Kind == KindNode
	})
	if nd := n.Data.(Change).Object.(Node); !nd.Unschedulable || nd.DeviceID != "dev-pi" {
		t.Errorf("node change = %+v", nd)
	}

	// Remove stops the watch and tells subscribers.
	if err := f.m.Remove(ctx, "192.0.2.1", info.ID); err != nil {
		t.Fatal(err)
	}
	f.waitNotice(t, 5*time.Second, func(n Notice) bool {
		c, ok := n.Data.(ClusterInfo)
		return ok && c.ID == info.ID && c.Removed
	})
	if _, err := f.m.Snapshot(ctx, info.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("Snapshot after Remove = %v, want ErrNotFound", err)
	}
	if err := f.m.Remove(ctx, "192.0.2.1", info.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("second Remove = %v, want ErrNotFound", err)
	}
	if got := f.m.Clusters(); len(got) != 0 {
		t.Errorf("Clusters after Remove = %+v", got)
	}

	// Add and remove are audited; the audit never holds the credential.
	entries, err := f.st.Audit().List(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	var actions []string
	for _, e := range entries {
		actions = append(actions, e.Action+":"+e.Result)
		if strings.Contains(string(e.Detail), "secret") {
			t.Errorf("audit entry %s holds a secret: %s", e.Action, e.Detail)
		}
	}
	if got := strings.Join(actions, " "); !strings.Contains(got, "kube.cluster.add:ok") ||
		!strings.Contains(got, "kube.cluster.remove:ok") || len(actions) != 3 {
		t.Errorf("audit = %q, want an add, a remove and a failed remove", got)
	}
}

func TestManagerAddRefuses(t *testing.T) {
	f := newFixture(t)
	ctx := t.Context()
	f.addCluster(t)

	if _, err := f.m.Add(ctx, "192.0.2.1", "", []byte(testKubeconfig)); !errors.Is(err, ErrNameTaken) {
		t.Errorf("Add with a taken name = %v, want ErrNameTaken", err)
	}
	if _, err := f.m.Add(ctx, "192.0.2.1", "other", []byte("kind: Config")); !errors.Is(err, ErrInvalidKubeconfig) {
		t.Errorf("Add of an invalid kubeconfig = %v, want ErrInvalidKubeconfig", err)
	}
	if _, err := f.m.Add(ctx, "192.0.2.1", strings.Repeat("x", 64), []byte(testKubeconfig)); !errors.Is(err, ErrBadName) {
		t.Errorf("Add with a long name = %v, want ErrBadName", err)
	}
	if _, err := f.m.Add(ctx, "", "anon", []byte(testKubeconfig)); !errors.Is(err, policy.ErrDenied) {
		t.Errorf("Add by an anonymous actor = %v, want ErrDenied", err)
	}
	if got := f.m.Clusters(); len(got) != 1 {
		t.Errorf("Clusters = %+v, want only the first", got)
	}
}

func TestManagerLogs(t *testing.T) {
	f := newFixture(t, pod("default", "web-1", true))
	ctx := t.Context()
	info := f.addCluster(t)

	logs, err := f.m.Logs(ctx, "192.0.2.1", info.ID, "default", "web-1", "app", 100)
	if err != nil || logs != "fake logs" {
		t.Fatalf("Logs = %q, %v", logs, err)
	}
	if _, err := f.m.Logs(ctx, "192.0.2.1", info.ID, "default", "ghost", "app", 100); !errors.Is(err, ErrPodNotFound) {
		t.Errorf("Logs of an unknown pod = %v, want ErrPodNotFound", err)
	}
	if _, err := f.m.Logs(ctx, "192.0.2.1", "nope", "default", "web-1", "app", 100); !errors.Is(err, ErrNotFound) {
		t.Errorf("Logs of an unknown cluster = %v, want ErrNotFound", err)
	}
	if _, err := f.m.Logs(ctx, "", info.ID, "default", "web-1", "app", 100); !errors.Is(err, policy.ErrDenied) {
		t.Errorf("Logs by an anonymous actor = %v, want ErrDenied", err)
	}
	entries, err := f.st.Audit().List(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	reads := 0
	for _, e := range entries {
		if e.Action == string(policy.KubePodLogs) {
			reads++
			var d map[string]any
			_ = json.Unmarshal(e.Detail, &d)
			if e.Target != "lab/default/web-1" && e.Target != "lab/default/ghost" {
				t.Errorf("log read target = %q", e.Target)
			}
		}
	}
	if reads != 3 {
		t.Errorf("audited log reads = %d, want 3 (two allowed, one denied)", reads)
	}
}

// A cluster added through another hub of a Raft cluster reaches this hub's
// store by replication; the manager picks it up on its next sync.
func TestManagerFollowsTheStore(t *testing.T) {
	f := newFixture(t)
	sealed, err := f.m.sealer.Seal("c-remote", []byte(testKubeconfig))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.st.KubeClusters().Add(t.Context(), store.KubeCluster{
		ID: "c-remote", Name: "remote", Sealed: sealed, CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	f.waitNotice(t, 5*time.Second, func(n Notice) bool {
		c, ok := n.Data.(ClusterInfo)
		return ok && c.ID == "c-remote" && c.State == StateConnected
	})

	// A kubeconfig sealed under another key shows as an error, not a crash.
	if err := f.st.KubeClusters().Add(t.Context(), store.KubeCluster{
		ID: "c-bad", Name: "bad", Sealed: []byte("not sealed by this hub"), CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	n := f.waitNotice(t, 5*time.Second, func(n Notice) bool {
		c, ok := n.Data.(ClusterInfo)
		return ok && c.ID == "c-bad"
	})
	if c := n.Data.(ClusterInfo); c.State != StateError || !strings.Contains(c.Error, "decrypt") {
		t.Errorf("undecryptable cluster = %+v", c)
	}
}
