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

	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

type fixture struct {
	m     *Manager
	st    *store.Store
	api   *fakeAPI
	notes <-chan Notice
}

// newFixture runs a manager on a fresh store, with a fake API server.
func newFixture(t *testing.T) *fixture {
	t.Helper()
	api := newFakeAPI(t) // closed after the manager stops, which ends its watches
	st, err := store.Open(t.Context(), filepath.Join(t.TempDir(), "hearth.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	sealer, err := NewSealer([]byte("test CA key"))
	if err != nil {
		t.Fatal(err)
	}
	m := NewManager(Config{Store: st, Sealer: sealer, Policy: policy.New(st.Audit()), SyncInterval: 50 * time.Millisecond})
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
	return &fixture{m: m, st: st, api: api, notes: notes}
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

func clusterNotice(id, state string) func(Notice) bool {
	return func(n Notice) bool {
		c, ok := n.Data.(ClusterInfo)
		return ok && c.ID == id && (state == "" || c.State == state)
	}
}

func change(kind, op, key string) func(Notice) bool {
	return func(n Notice) bool {
		c, ok := n.Data.(Change)
		return ok && c.Kind == kind && c.Op == op && c.Key == key
	}
}

func (f *fixture) addCluster(t *testing.T) ClusterInfo {
	t.Helper()
	info, err := f.m.Add(t.Context(), "192.0.2.1", "", []byte(f.api.kubeconfig()))
	if err != nil {
		t.Fatal(err)
	}
	f.waitNotice(t, 5*time.Second, clusterNotice(info.ID, StateConnected))
	return info
}

func TestManagerAddWatchRemove(t *testing.T) {
	f := newFixture(t)
	api := f.api
	api.put("/api/v1/nodes", nodeObj("pi-1", "192.168.2.131", true))
	api.put("/api/v1/namespaces", map[string]any{"metadata": meta("", "default"), "status": map[string]any{"phase": "Active"}})
	api.put("/apis/apps/v1/deployments", map[string]any{
		"metadata": meta("default", "web"),
		"spec":     map[string]any{"replicas": 2}, "status": map[string]any{"readyReplicas": 1},
	})
	api.put("/api/v1/events", map[string]any{
		"metadata": meta("default", "web.1"), "type": "Warning", "reason": "BackOff",
		"involvedObject": map[string]any{"kind": "Pod", "name": "web-1"}, "lastTimestamp": "2026-11-18T10:05:00Z",
	})
	for _, name := range []string{"web-1", "web-2", "web-3"} { // more than one list page
		api.put("/api/v1/pods", podObj("default", name, true))
	}
	ctx := t.Context()
	if err := f.st.Devices().Upsert(ctx, device("dev-pi", "raspberrypi", "192.168.2.131/24")); err != nil {
		t.Fatal(err)
	}

	info := f.addCluster(t)
	if info.Name != "lab" || info.Server != api.srv.URL {
		t.Errorf("Add = %+v, want the current context's name and server", info)
	}

	// The kubeconfig is stored sealed, never in the clear.
	stored, err := f.st.KubeClusters().List(ctx)
	if err != nil || len(stored) != 1 {
		t.Fatalf("stored clusters = %v, %v", stored, err)
	}
	if strings.Contains(string(stored[0].Sealed), api.token) {
		t.Fatal("the stored kubeconfig holds the token in the clear")
	}

	snap, err := f.m.Snapshot(ctx, info.ID)
	if err != nil {
		t.Fatal(err)
	}
	if snap.Cluster.State != StateConnected || snap.Cluster.Nodes != 1 || snap.Cluster.Pods != 3 {
		t.Errorf("cluster = %+v", snap.Cluster)
	}
	if len(snap.Nodes) != 1 || snap.Nodes[0].DeviceID != "dev-pi" || !snap.Nodes[0].Ready ||
		snap.Nodes[0].CPU != "4" || snap.Nodes[0].Roles[0] != "control-plane" {
		t.Errorf("nodes = %+v, want pi-1 linked to dev-pi", snap.Nodes)
	}
	if len(snap.Namespaces) != 1 || len(snap.Workloads) != 1 || snap.Workloads[0].Desired != 2 ||
		snap.Workloads[0].Ready != 1 || len(snap.Events) != 1 || snap.Events[0].Object != "pod/web-1" {
		t.Errorf("snapshot = %+v", snap)
	}
	if len(snap.Pods) != 3 || snap.Pods[0].Status != "Running" || snap.Pods[0].Name != "web-1" {
		t.Errorf("pods = %+v", snap.Pods)
	}

	// A pod's status change is streamed, and so are a new pod and a deletion.
	start := time.Now()
	api.put("/api/v1/pods", podObj("default", "web-1", false))
	n := f.waitNotice(t, 5*time.Second, change(KindPod, OpUpsert, "default/web-1"))
	t.Logf("pod status change notice after %v", time.Since(start))
	if p, ok := n.Data.(Change).Object.(Pod); !ok || p.Status != "ContainerCreating" || p.Ready != "0/1" {
		t.Errorf("change = %+v", n.Data)
	}
	api.put("/api/v1/pods", podObj("default", "web-4", true))
	f.waitNotice(t, 5*time.Second, change(KindPod, OpUpsert, "default/web-4"))
	api.del("/api/v1/pods", podObj("default", "web-2", true))
	f.waitNotice(t, 5*time.Second, change(KindPod, OpDelete, "default/web-2"))

	// A node change carries its device link.
	cordoned := nodeObj("pi-1", "192.168.2.131", true)
	cordoned["spec"] = map[string]any{"unschedulable": true}
	api.put("/api/v1/nodes", cordoned)
	n = f.waitNotice(t, 5*time.Second, change(KindNode, OpUpsert, "pi-1"))
	if nd, ok := n.Data.(Change).Object.(Node); !ok || !nd.Unschedulable || nd.DeviceID != "dev-pi" {
		t.Errorf("node change = %+v", n.Data)
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

	// Add and remove are audited; the audit never holds the credential.
	entries, err := f.st.Audit().List(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	var actions []string
	for _, e := range entries {
		actions = append(actions, e.Action+":"+e.Result)
		if strings.Contains(string(e.Detail), api.token) {
			t.Errorf("audit entry %s holds the token: %s", e.Action, e.Detail)
		}
	}
	if got := strings.Join(actions, " "); !strings.Contains(got, "kube.cluster.add:ok") ||
		!strings.Contains(got, "kube.cluster.remove:ok") || len(actions) != 3 {
		t.Errorf("audit = %q, want an add, a remove and a failed remove", got)
	}
}

// A watch the server has compacted past (410 Gone) relists, and what
// changed meanwhile is published.
func TestManagerRelistsOnGone(t *testing.T) {
	f := newFixture(t)
	f.api.put("/api/v1/pods", podObj("default", "a", true))
	f.api.put("/api/v1/pods", podObj("default", "b", true))
	info := f.addCluster(t)
	lists := f.api.listCount("/api/v1/pods")

	// Drop every watch, after a compaction that lost a deletion of b and
	// an update of a: a watch from before it answers 410, retried or not.
	f.api.mu.Lock()
	f.api.rv++
	delete(f.api.objs["/api/v1/pods"], "default/b")
	f.api.objs["/api/v1/pods"]["default/a"] = podObj("default", "a", false)
	f.api.compacted["/api/v1/pods"] = f.api.rv
	f.api.mu.Unlock()
	f.api.srv.CloseClientConnections()

	f.waitNotice(t, 10*time.Second, change(KindPod, OpDelete, "default/b"))
	f.waitNotice(t, 5*time.Second, change(KindPod, OpUpsert, "default/a"))
	if f.api.listCount("/api/v1/pods") <= lists {
		t.Error("no relist after 410 Gone")
	}
	if snap, _ := f.m.Snapshot(t.Context(), info.ID); len(snap.Pods) != 1 || snap.Pods[0].Status != "ContainerCreating" {
		t.Errorf("pods after relist = %+v", snap.Pods)
	}
}

func TestManagerUnreachable(t *testing.T) {
	f := newFixture(t)
	f.api.token = "wrong" // the kubeconfig carries "wrong"; the server wants another
	cfg := f.api.kubeconfig()
	f.api.token = "lab-secret-token"
	info, err := f.m.Add(t.Context(), "192.0.2.1", "", []byte(cfg))
	if err != nil {
		t.Fatal(err)
	}
	n := f.waitNotice(t, 5*time.Second, clusterNotice(info.ID, StateError))
	if c, _ := n.Data.(ClusterInfo); !strings.Contains(c.Error, "Unauthorized") {
		t.Errorf("error = %q, want the API server's answer", c.Error)
	}
}

func TestManagerAddRefuses(t *testing.T) {
	f := newFixture(t)
	ctx := t.Context()
	f.addCluster(t)
	cfg := []byte(f.api.kubeconfig())

	if _, err := f.m.Add(ctx, "192.0.2.1", "", cfg); !errors.Is(err, ErrNameTaken) {
		t.Errorf("Add with a taken name = %v, want ErrNameTaken", err)
	}
	if _, err := f.m.Add(ctx, "192.0.2.1", "other", []byte("kind: Config")); !errors.Is(err, ErrInvalidKubeconfig) {
		t.Errorf("Add of an invalid kubeconfig = %v, want ErrInvalidKubeconfig", err)
	}
	if _, err := f.m.Add(ctx, "192.0.2.1", strings.Repeat("x", 64), cfg); !errors.Is(err, ErrBadName) {
		t.Errorf("Add with a long name = %v, want ErrBadName", err)
	}
	if _, err := f.m.Add(ctx, "", "anon", cfg); !errors.Is(err, policy.ErrDenied) {
		t.Errorf("Add by an anonymous actor = %v, want ErrDenied", err)
	}
	if got := f.m.Clusters(); len(got) != 1 {
		t.Errorf("Clusters = %+v, want only the first", got)
	}
}

func TestManagerLogs(t *testing.T) {
	f := newFixture(t)
	ctx := t.Context()
	f.api.logs["default/web-1/app"] = "line 1\nline 2\n"
	info := f.addCluster(t)

	logs, err := f.m.Logs(ctx, policy.ActorWeb, "192.0.2.1", info.ID, "default", "web-1", "app", 100)
	if err != nil || logs != "line 1\nline 2\n" {
		t.Fatalf("Logs = %q, %v", logs, err)
	}
	for name, args := range map[string][3]string{
		"unknown pod":       {"default", "ghost", "app"},
		"path in namespace": {"default/../../x", "web-1", "app"},
		"bad container":     {"default", "web-1", "App?x=1"},
	} {
		if _, err := f.m.Logs(ctx, policy.ActorWeb, "192.0.2.1", info.ID, args[0], args[1], args[2], 100); !errors.Is(err, ErrPodNotFound) {
			t.Errorf("Logs of %s = %v, want ErrPodNotFound", name, err)
		}
	}
	if _, err := f.m.Logs(ctx, policy.ActorWeb, "192.0.2.1", "nope", "default", "web-1", "app", 100); !errors.Is(err, ErrNotFound) {
		t.Errorf("Logs of an unknown cluster = %v, want ErrNotFound", err)
	}
	if _, err := f.m.Logs(ctx, policy.ActorWeb, "", info.ID, "default", "web-1", "app", 100); !errors.Is(err, policy.ErrDenied) {
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
			if d["container"] != "app" {
				t.Errorf("log read detail = %s", e.Detail)
			}
		}
	}
	if reads != 3 {
		t.Errorf("audited log reads = %d, want 3 (two read, one denied)", reads)
	}
}

// A cluster added through another hub of a Raft cluster reaches this hub's
// store by replication; the manager picks it up on its next sync.
func TestManagerFollowsTheStore(t *testing.T) {
	f := newFixture(t)
	sealed, err := f.m.sealer.Seal("c-remote", []byte(f.api.kubeconfig()))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.st.KubeClusters().Add(t.Context(), store.KubeCluster{
		ID: "c-remote", Name: "remote", Sealed: sealed, CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	f.waitNotice(t, 5*time.Second, clusterNotice("c-remote", StateConnected))

	// A kubeconfig sealed under another key shows as an error, not a crash.
	if err := f.st.KubeClusters().Add(t.Context(), store.KubeCluster{
		ID: "c-bad", Name: "bad", Sealed: []byte("not sealed by this hub"), CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	n := f.waitNotice(t, 5*time.Second, clusterNotice("c-bad", ""))
	if c, _ := n.Data.(ClusterInfo); c.State != StateError || !strings.Contains(c.Error, "decrypt") {
		t.Errorf("undecryptable cluster = %+v", c)
	}
}

// TestManagerWaitLoaded: WaitLoaded waits for Run's first read of the stored
// clusters, after which they are all known; with none stored, as on a hub
// without Kubernetes, it does not hang.
func TestManagerWaitLoaded(t *testing.T) {
	for _, tt := range []struct {
		name     string
		clusters int
	}{
		{"no cluster stored", 0},
		{"one cluster stored", 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			st, err := store.Open(t.Context(), filepath.Join(t.TempDir(), "hearth.db"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = st.Close() })
			sealer, err := NewSealer([]byte("test CA key"))
			if err != nil {
				t.Fatal(err)
			}
			if tt.clusters > 0 {
				api := newFakeAPI(t)
				sealed, err := sealer.Seal("c1", []byte(api.kubeconfig()))
				if err != nil {
					t.Fatal(err)
				}
				if err := st.KubeClusters().Add(t.Context(), store.KubeCluster{
					ID: "c1", Name: "lab", Sealed: sealed, CreatedAt: time.Now(),
				}); err != nil {
					t.Fatal(err)
				}
			}
			m := NewManager(Config{Store: st, Sealer: sealer, Policy: policy.New(st.Audit())})

			// Not running yet: the wait ends with its context.
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			if err := m.WaitLoaded(ctx); !errors.Is(err, context.Canceled) {
				t.Fatalf("WaitLoaded before Run = %v, want context.Canceled", err)
			}

			runCtx, stop := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() { done <- m.Run(runCtx) }()
			t.Cleanup(func() {
				stop()
				if err := <-done; err != nil {
					t.Errorf("Run: %v", err)
				}
			})
			if err := m.WaitLoaded(t.Context()); err != nil {
				t.Fatalf("WaitLoaded: %v", err)
			}
			if got := m.Clusters(); len(got) != tt.clusters {
				t.Errorf("clusters after the load = %+v, want %d", got, tt.clusters)
			}
		})
	}
}
