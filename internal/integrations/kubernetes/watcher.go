// SPDX-License-Identifier: AGPL-3.0-only

package kubernetes

import (
	"context"
	"log/slog"
	"reflect"
	"sync"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/cache"
)

// Cluster states.
const (
	StateConnecting = "connecting"
	StateConnected  = "connected"
	StateError      = "error"
)

// errorWindow is how long after its last list or watch failure a cluster
// shows as in error. The reflectors retry with a backoff well under it, so a
// cluster that stays unreachable stays in error.
const errorWindow = time.Minute

// source is one informer and how to turn its objects into API entities.
type source struct {
	kind     string
	informer cache.SharedIndexInformer
	// entity converts a cached object; key is its stable key within kind.
	entity func(obj any) (key string, v any, ok bool)
}

// typed adapts conv to the informer's untyped objects.
func typed[T any](conv func(*T) (string, any)) func(any) (string, any, bool) {
	return func(obj any) (string, any, bool) {
		t, ok := obj.(*T)
		if !ok {
			return "", nil, false
		}
		k, v := conv(t)
		return k, v, true
	}
}

// watcher keeps an informer cache of one cluster's nodes, namespaces,
// workloads, pods and events, and reports every change through publish.
type watcher struct {
	clusterID string
	c         clients
	log       *slog.Logger
	now       func() time.Time
	sources   []source
	// publish is called on informer goroutines for every change after the
	// initial list; link fills the DeviceID of a node it publishes.
	publish func(Change)
	link    func(Node) Node
	// synced is called once every informer has listed.
	synced func()

	mu        sync.Mutex
	isSynced  bool
	lastErr   string
	lastErrAt time.Time
}

func newWatcher(clusterID string, c clients, log *slog.Logger, now func() time.Time,
	publish func(Change), link func(Node) Node, synced func(),
) *watcher {
	w := &watcher{clusterID: clusterID, c: c, log: log, now: now, publish: publish, link: link, synced: synced}
	w.sources = []source{
		w.source(KindNode, &corev1.Node{}, c.lw[resNodes],
			typed(func(n *corev1.Node) (string, any) { return n.Name, nodeOf(n) })),
		w.source(KindNamespace, &corev1.Namespace{}, c.lw[resNamespaces],
			typed(func(n *corev1.Namespace) (string, any) { return n.Name, namespaceOf(n) })),
		w.source(KindPod, &corev1.Pod{}, c.lw[resPods],
			typed(func(p *corev1.Pod) (string, any) { return p.Namespace + "/" + p.Name, podOf(p) })),
		w.source(KindEvent, &corev1.Event{}, c.lw[resEvents],
			typed(func(e *corev1.Event) (string, any) { return string(e.UID), eventOf(e) })),
		w.source(KindWorkload, &appsv1.Deployment{}, c.lw[resDeployments],
			typed(func(d *appsv1.Deployment) (string, any) { wl := deploymentOf(d); return workloadKey(wl), wl })),
		w.source(KindWorkload, &appsv1.StatefulSet{}, c.lw[resStatefulSets],
			typed(func(s *appsv1.StatefulSet) (string, any) { wl := statefulSetOf(s); return workloadKey(wl), wl })),
		w.source(KindWorkload, &appsv1.DaemonSet{}, c.lw[resDaemonSets],
			typed(func(d *appsv1.DaemonSet) (string, any) { wl := daemonSetOf(d); return workloadKey(wl), wl })),
	}
	return w
}

func workloadKey(wl Workload) string { return wl.Kind + "/" + wl.Namespace + "/" + wl.Name }

// source builds an informer for one resource. Its cache drops managed
// fields and annotations, which the hub never shows and which are most of
// an object's size.
func (w *watcher) source(kind string, example runtime.Object, lw cache.ListerWatcher,
	entity func(obj any) (string, any, bool),
) source {
	inf := cache.NewSharedIndexInformer(lw, example, 0, cache.Indexers{})
	_ = inf.SetTransform(func(obj any) (any, error) {
		if m, ok := obj.(metav1.Object); ok {
			m.SetManagedFields(nil)
			m.SetAnnotations(nil)
		}
		return obj, nil
	})
	_ = inf.SetWatchErrorHandlerWithContext(func(_ context.Context, _ *cache.Reflector, err error) {
		w.mu.Lock()
		w.lastErr, w.lastErrAt = err.Error(), w.now()
		w.mu.Unlock()
		w.log.Debug("kubernetes watch failed", "cluster", w.clusterID, "kind", kind, "err", err)
	})
	s := source{kind: kind, informer: inf, entity: entity}
	_, _ = inf.AddEventHandler(cache.ResourceEventHandlerDetailedFuncs{
		AddFunc: func(obj any, initial bool) {
			if !initial {
				w.upsert(s, obj)
			}
		},
		UpdateFunc: func(oldObj, newObj any) {
			_, before, ok1 := s.entity(oldObj)
			_, after, ok2 := s.entity(newObj)
			if ok1 && ok2 && reflect.DeepEqual(before, after) {
				return // nothing the hub shows changed
			}
			w.upsert(s, newObj)
		},
		DeleteFunc: func(obj any) {
			if d, ok := obj.(cache.DeletedFinalStateUnknown); ok {
				obj = d.Obj
			}
			if key, _, ok := s.entity(obj); ok {
				w.publish(Change{Cluster: w.clusterID, Kind: s.kind, Op: OpDelete, Key: key})
			}
		},
	})
	return s
}

func (w *watcher) upsert(s source, obj any) {
	key, v, ok := s.entity(obj)
	if !ok {
		return
	}
	w.mu.Lock()
	w.lastErr = "" // the watch delivers again
	w.mu.Unlock()
	if n, ok := v.(Node); ok {
		v = w.link(n)
	}
	w.publish(Change{Cluster: w.clusterID, Kind: s.kind, Op: OpUpsert, Key: key, Object: v})
}

// run runs the informers until ctx is done.
func (w *watcher) run(ctx context.Context) {
	var wg sync.WaitGroup
	synced := make([]cache.InformerSynced, 0, len(w.sources))
	for _, s := range w.sources {
		wg.Go(func() { s.informer.RunWithContext(ctx) })
		synced = append(synced, s.informer.HasSynced)
	}
	if cache.WaitForCacheSync(ctx.Done(), synced...) {
		w.mu.Lock()
		w.isSynced, w.lastErr = true, ""
		w.mu.Unlock()
		w.synced()
	}
	wg.Wait()
}

// state is the cluster's connection state and its last error, if recent.
func (w *watcher) state() (string, string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.lastErr != "" && w.now().Sub(w.lastErrAt) < errorWindow {
		return StateError, w.lastErr
	}
	if w.isSynced {
		return StateConnected, ""
	}
	return StateConnecting, ""
}

// count is the number of cached objects of kind.
func (w *watcher) count(kind string) int {
	n := 0
	for _, s := range w.sources {
		if s.kind == kind {
			n += len(s.informer.GetStore().ListKeys())
		}
	}
	return n
}

// entities lists the cached entities of kind.
func (w *watcher) entities(kind string) []any {
	var out []any
	for _, s := range w.sources {
		if s.kind != kind {
			continue
		}
		for _, obj := range s.informer.GetStore().List() {
			if _, v, ok := s.entity(obj); ok {
				out = append(out, v)
			}
		}
	}
	return out
}
