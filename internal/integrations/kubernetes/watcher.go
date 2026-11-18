// SPDX-License-Identifier: AGPL-3.0-only

package kubernetes

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"reflect"
	"sync"
	"time"
)

// Cluster states.
const (
	StateConnecting = "connecting"
	StateConnected  = "connected"
	StateError      = "error"
)

const (
	// errorWindow is how long after its last list or watch failure a
	// cluster shows as in error. Retries back off to at most maxBackoff,
	// well under it, so a cluster that stays unreachable stays in error.
	errorWindow = time.Minute
	minBackoff  = time.Second
	maxBackoff  = 30 * time.Second
)

// decoder parses one API object into its key, resource version and entity.
type decoder func(raw json.RawMessage) (key, rv string, v any, err error)

// decodeAs adapts conv to raw JSON objects of type T.
func decodeAs[T any](meta func(*T) *objectMeta, key func(*T) string, conv func(*T) any) decoder {
	return func(raw json.RawMessage) (string, string, any, error) {
		var t T
		if err := json.Unmarshal(raw, &t); err != nil {
			return "", "", nil, err
		}
		return key(&t), meta(&t).ResourceVersion, conv(&t), nil
	}
}

func nsName(m *objectMeta) string { return m.Namespace + "/" + m.Name }

// resource is one list-and-watch of the API server and its cache of
// converted entities.
type resource struct {
	kind   string
	path   string
	decode decoder

	mu     sync.Mutex
	items  map[string]any
	synced bool
}

func resources() []*resource {
	return []*resource{
		{kind: KindNode, path: "/api/v1/nodes", decode: decodeAs(
			func(n *node) *objectMeta { return &n.Metadata },
			func(n *node) string { return n.Metadata.Name },
			func(n *node) any { return nodeOf(n) })},
		{kind: KindNamespace, path: "/api/v1/namespaces", decode: decodeAs(
			func(n *namespace) *objectMeta { return &n.Metadata },
			func(n *namespace) string { return n.Metadata.Name },
			func(n *namespace) any { return namespaceOf(n) })},
		{kind: KindPod, path: "/api/v1/pods", decode: decodeAs(
			func(p *pod) *objectMeta { return &p.Metadata },
			func(p *pod) string { return nsName(&p.Metadata) },
			func(p *pod) any { return podOf(p) })},
		{kind: KindEvent, path: "/api/v1/events", decode: decodeAs(
			func(e *event) *objectMeta { return &e.Metadata },
			func(e *event) string { return e.Metadata.UID },
			func(e *event) any { return eventOf(e) })},
		{kind: KindWorkload, path: "/apis/apps/v1/deployments", decode: decodeAs(
			func(r *replicated) *objectMeta { return &r.Metadata },
			func(r *replicated) string { return "Deployment/" + nsName(&r.Metadata) },
			func(r *replicated) any { return replicatedOf("Deployment", r) })},
		{kind: KindWorkload, path: "/apis/apps/v1/statefulsets", decode: decodeAs(
			func(r *replicated) *objectMeta { return &r.Metadata },
			func(r *replicated) string { return "StatefulSet/" + nsName(&r.Metadata) },
			func(r *replicated) any { return replicatedOf("StatefulSet", r) })},
		{kind: KindWorkload, path: "/apis/apps/v1/daemonsets", decode: decodeAs(
			func(d *daemonSet) *objectMeta { return &d.Metadata },
			func(d *daemonSet) string { return "DaemonSet/" + nsName(&d.Metadata) },
			func(d *daemonSet) any { return daemonSetOf(d) })},
	}
}

func workloadKey(wl Workload) string { return wl.Kind + "/" + wl.Namespace + "/" + wl.Name }

// watcher keeps a cache of one cluster's nodes, namespaces, workloads, pods
// and events, kept current by list and watch, and reports every change
// through publish.
type watcher struct {
	clusterID string
	c         *apiClient
	log       *slog.Logger
	now       func() time.Time
	res       []*resource
	// publish is called for every change after a resource's first list;
	// link fills the DeviceID of a node it publishes.
	publish func(Change)
	link    func(Node) Node
	// synced is called once every resource has been listed.
	synced func()

	mu        sync.Mutex
	isSynced  bool
	lastErr   string
	lastErrAt time.Time
}

func newWatcher(clusterID string, c *apiClient, log *slog.Logger, now func() time.Time,
	publish func(Change), link func(Node) Node, synced func(),
) *watcher {
	return &watcher{
		clusterID: clusterID, c: c, log: log, now: now, res: resources(),
		publish: publish, link: link, synced: synced,
	}
}

// run lists and watches every resource until ctx is done.
func (w *watcher) run(ctx context.Context) {
	var wg sync.WaitGroup
	for _, r := range w.res {
		wg.Go(func() { w.reflect(ctx, r) })
	}
	wg.Wait()
}

// errGone is a watch whose resource version is too old: relist.
var errGone = errors.New("resource version too old")

// reflect keeps r current: it lists, then watches from the list's resource
// version, watching again when a watch ends and listing again when the
// server has compacted past it. Failures back off up to maxBackoff.
func (w *watcher) reflect(ctx context.Context, r *resource) {
	backoff := minBackoff
	wait := func() bool {
		t := time.NewTimer(backoff)
		defer t.Stop()
		backoff = min(2*backoff, maxBackoff)
		select {
		case <-ctx.Done():
			return false
		case <-t.C:
			return true
		}
	}
	for ctx.Err() == nil {
		rv, err := w.relist(ctx, r)
		if err != nil {
			w.fail(ctx, r, "list", err)
			if !wait() {
				return
			}
			continue
		}
		backoff = minBackoff
		for ctx.Err() == nil {
			var delivered bool
			rv, delivered, err = w.watchOnce(ctx, r, rv)
			if delivered {
				backoff = minBackoff
			}
			if errors.Is(err, errGone) {
				break
			}
			if err != nil {
				w.fail(ctx, r, "watch", err)
				if !wait() {
					return
				}
			}
		}
	}
}

// relist replaces r's cache with a fresh list and publishes the
// differences (nothing on the first list).
func (w *watcher) relist(ctx context.Context, r *resource) (string, error) {
	raw, rv, err := w.c.list(ctx, r.path)
	if err != nil {
		return "", err
	}
	items := make(map[string]any, len(raw))
	for _, b := range raw {
		key, _, v, err := r.decode(b)
		if err != nil {
			return "", fmt.Errorf("decode %s: %w", r.path, err)
		}
		items[key] = v
	}
	r.mu.Lock()
	old, wasSynced := r.items, r.synced
	r.items, r.synced = items, true
	r.mu.Unlock()
	if wasSynced {
		for key := range old {
			if _, ok := items[key]; !ok {
				w.publish(Change{Cluster: w.clusterID, Kind: r.kind, Op: OpDelete, Key: key})
			}
		}
		for key, v := range items {
			if !reflect.DeepEqual(old[key], v) {
				w.upserted(r, key, v)
			}
		}
	}
	w.ok()
	w.checkSynced()
	return rv, nil
}

// watchEvent is one line of a watch stream.
type watchEvent struct {
	Type   string          `json:"type"`
	Object json.RawMessage `json:"object"`
}

// watchOnce applies one watch request's events to r until it ends. It
// returns the newest resource version seen and whether the watch was
// established.
func (w *watcher) watchOnce(ctx context.Context, r *resource, rv string) (string, bool, error) {
	body, err := w.c.watch(ctx, r.path, rv)
	if hasCode(err, http.StatusGone) {
		return rv, false, errGone
	}
	if err != nil {
		return rv, false, err
	}
	defer body.Close()
	w.ok()
	dec := json.NewDecoder(body)
	for {
		var ev watchEvent
		if err := dec.Decode(&ev); err != nil {
			if ctx.Err() != nil || errors.Is(err, context.Canceled) {
				return rv, true, nil
			}
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return rv, true, nil // the server ended the watch (timeoutSeconds)
			}
			return rv, true, fmt.Errorf("watch %s: %w", r.path, err)
		}
		switch ev.Type {
		case "ADDED", "MODIFIED", "DELETED":
			key, objRV, v, err := r.decode(ev.Object)
			if err != nil {
				return rv, true, fmt.Errorf("decode %s: %w", r.path, err)
			}
			rv = objRV
			w.apply(r, ev.Type, key, v)
		case "BOOKMARK":
			var b struct {
				Metadata listMeta `json:"metadata"`
			}
			if json.Unmarshal(ev.Object, &b) == nil && b.Metadata.ResourceVersion != "" {
				rv = b.Metadata.ResourceVersion
			}
		case "ERROR":
			var st status
			_ = json.Unmarshal(ev.Object, &st)
			if st.Code == http.StatusGone {
				return rv, true, errGone
			}
			return rv, true, &apiError{Code: st.Code, Message: st.Message}
		}
	}
}

// apply applies one watch event to r's cache and publishes it if it
// changed anything the hub shows.
func (w *watcher) apply(r *resource, typ, key string, v any) {
	r.mu.Lock()
	old, had := r.items[key]
	if typ == "DELETED" {
		delete(r.items, key)
	} else {
		r.items[key] = v
	}
	r.mu.Unlock()
	switch {
	case typ == "DELETED":
		if had {
			w.publish(Change{Cluster: w.clusterID, Kind: r.kind, Op: OpDelete, Key: key})
		}
	case !had || !reflect.DeepEqual(old, v):
		w.upserted(r, key, v)
	}
}

func (w *watcher) upserted(r *resource, key string, v any) {
	if n, ok := v.(Node); ok {
		v = w.link(n)
	}
	w.publish(Change{Cluster: w.clusterID, Kind: r.kind, Op: OpUpsert, Key: key, Object: v})
}

func (w *watcher) fail(ctx context.Context, r *resource, op string, err error) {
	if ctx.Err() != nil {
		return
	}
	w.mu.Lock()
	w.lastErr, w.lastErrAt = err.Error(), w.now()
	w.mu.Unlock()
	w.log.DebugContext(ctx, "kubernetes "+op+" failed", "cluster", w.clusterID, "path", r.path, "err", err)
}

// ok clears the last error: the API server answers again.
func (w *watcher) ok() {
	w.mu.Lock()
	w.lastErr = ""
	w.mu.Unlock()
}

// checkSynced calls synced the first time every resource has been listed.
func (w *watcher) checkSynced() {
	for _, r := range w.res {
		r.mu.Lock()
		s := r.synced
		r.mu.Unlock()
		if !s {
			return
		}
	}
	w.mu.Lock()
	first := !w.isSynced
	w.isSynced = true
	w.mu.Unlock()
	if first {
		w.synced()
	}
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

// count is the number of cached entities of kind.
func (w *watcher) count(kind string) int {
	n := 0
	for _, r := range w.res {
		if r.kind == kind {
			r.mu.Lock()
			n += len(r.items)
			r.mu.Unlock()
		}
	}
	return n
}

// entities lists the cached entities of kind.
func (w *watcher) entities(kind string) []any {
	var out []any
	for _, r := range w.res {
		if r.kind != kind {
			continue
		}
		r.mu.Lock()
		for _, v := range r.items {
			out = append(out, v)
		}
		r.mu.Unlock()
	}
	return out
}
