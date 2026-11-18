// SPDX-License-Identifier: AGPL-3.0-only

package kubernetes

import (
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// fakeAPI is a minimal Kubernetes API server over TLS with a bearer token:
// list (with pagination), watch and pod logs, for the resources the hub
// reads. Watches stream the changes made after they start.
type fakeAPI struct {
	srv   *httptest.Server
	token string

	mu       sync.Mutex
	rv       int
	objs     map[string]map[string]map[string]any // path -> key -> object
	watchers map[string][]chan watchEvent
	history  map[string][]fakeEvent // every change by path, to replay a watch from a resource version
	logs     map[string]string      // namespace/pod/container -> log
	// gone makes the next watch of a path answer 410 Gone.
	gone   map[string]bool
	lists  map[string]int // list requests by path
	pageSz int
	// actions are the requests of the Kubernetes actions: everything but
	// the watchers' lists and watches.
	actions []string
	// refuse makes the next n evictions of a pod (namespace/name) answer
	// 429, as a PodDisruptionBudget does.
	refuse map[string]int
}

var fakePaths = []string{
	"/api/v1/nodes", "/api/v1/namespaces", "/api/v1/pods", "/api/v1/events",
	"/apis/apps/v1/deployments", "/apis/apps/v1/statefulsets", "/apis/apps/v1/daemonsets",
}

func newFakeAPI(t *testing.T) *fakeAPI {
	t.Helper()
	f := &fakeAPI{
		token: "lab-secret-token", objs: map[string]map[string]map[string]any{},
		watchers: map[string][]chan watchEvent{}, history: map[string][]fakeEvent{}, logs: map[string]string{}, gone: map[string]bool{}, lists: map[string]int{}, pageSz: 2,
		refuse: map[string]int{},
	}
	for _, p := range fakePaths {
		f.objs[p] = map[string]map[string]any{}
	}
	f.srv = httptest.NewUnstartedServer(http.HandlerFunc(f.serve))
	f.srv.Config.ErrorLog = log.New(io.Discard, "", 0) // dropped connections are part of the tests
	f.srv.StartTLS()
	t.Cleanup(f.srv.Close)
	return f
}

// kubeconfig trusts the fake's certificate and carries its token.
func (f *fakeAPI) kubeconfig() string {
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.srv.Certificate().Raw})
	return fmt.Sprintf(`apiVersion: v1
kind: Config
current-context: lab
clusters:
- name: lab
  cluster: {server: %q, certificate-authority-data: %s}
contexts:
- name: lab
  context: {cluster: lab, user: admin}
users:
- name: admin
  user: {token: %s}
`, f.srv.URL, base64.StdEncoding.EncodeToString(ca), f.token)
}

func objKey(o map[string]any) string {
	m, _ := o["metadata"].(map[string]any)
	ns, _ := m["namespace"].(string)
	name, _ := m["name"].(string)
	return ns + "/" + name
}

// put adds or replaces an object and tells the watchers of path.
func (f *fakeAPI) put(path string, o map[string]any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rv++
	o["metadata"].(map[string]any)["resourceVersion"] = strconv.Itoa(f.rv)
	typ := "MODIFIED"
	if _, ok := f.objs[path][objKey(o)]; !ok {
		typ = "ADDED"
	}
	f.objs[path][objKey(o)] = o
	f.notify(path, typ, o)
}

func (f *fakeAPI) del(path string, o map[string]any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rv++
	delete(f.objs[path], objKey(o))
	f.notify(path, "DELETED", o)
}

func (f *fakeAPI) notify(path, typ string, o map[string]any) {
	b, _ := json.Marshal(o)
	ev := watchEvent{Type: typ, Object: b}
	f.history[path] = append(f.history[path], fakeEvent{rv: f.rv, ev: ev})
	for _, ch := range f.watchers[path] {
		ch <- ev
	}
}

func (f *fakeAPI) listCount(path string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lists[path]
}

func writeStatus(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(status{Code: code, Message: msg})
}

func (f *fakeAPI) serve(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer "+f.token {
		writeStatus(w, http.StatusUnauthorized, "Unauthorized")
		return
	}
	if strings.HasSuffix(r.URL.Path, "/log") {
		parts := strings.Split(r.URL.Path, "/") // "", api, v1, namespaces, ns, pods, pod, log
		f.mu.Lock()
		logs, ok := f.logs[parts[4]+"/"+parts[6]+"/"+r.URL.Query().Get("container")]
		f.mu.Unlock()
		if !ok {
			writeStatus(w, http.StatusNotFound, `pods "`+parts[6]+`" not found`)
			return
		}
		_, _ = fmt.Fprint(w, logs)
		return
	}
	f.mu.Lock()
	if _, list := f.objs[r.URL.Path]; !list || r.URL.Query().Get("fieldSelector") != "" {
		f.actions = append(f.actions, r.Method+" "+r.URL.Path)
	}
	f.mu.Unlock()
	if f.serveObject(w, r) {
		return
	}
	f.mu.Lock()
	objs, ok := f.objs[r.URL.Path]
	if !ok {
		f.mu.Unlock()
		writeStatus(w, http.StatusNotFound, "not found")
		return
	}
	if r.URL.Query().Get("watch") == "1" {
		if f.gone[r.URL.Path] {
			delete(f.gone, r.URL.Path)
			f.mu.Unlock()
			writeStatus(w, http.StatusGone, "too old resource version")
			return
		}
		// Replay what changed after the requested version, as the API
		// server does, then stream what changes next.
		ch := make(chan watchEvent, 256)
		from, _ := strconv.Atoi(r.URL.Query().Get("resourceVersion"))
		for _, e := range f.history[r.URL.Path] {
			if e.rv > from {
				ch <- e.ev
			}
		}
		f.watchers[r.URL.Path] = append(f.watchers[r.URL.Path], ch)
		f.mu.Unlock()
		defer func() {
			f.mu.Lock()
			defer f.mu.Unlock()
			ws := f.watchers[r.URL.Path]
			for i, c := range ws {
				if c == ch {
					f.watchers[r.URL.Path] = append(ws[:i], ws[i+1:]...)
				}
			}
		}()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		enc := json.NewEncoder(w)
		for {
			select {
			case <-r.Context().Done():
				return
			case ev := <-ch:
				_ = enc.Encode(ev)
				w.(http.Flusher).Flush()
			}
		}
	}
	// A list, paged by pageSz with the offset as continue token.
	f.lists[r.URL.Path]++
	keys := make([]string, 0, len(objs))
	nodeName, byNode := strings.CutPrefix(r.URL.Query().Get("fieldSelector"), "spec.nodeName=")
	for k, o := range objs {
		if spec, _ := o["spec"].(map[string]any); !byNode || spec["nodeName"] == nodeName {
			keys = append(keys, k)
		}
	}
	slices.Sort(keys)
	from, _ := strconv.Atoi(r.URL.Query().Get("continue"))
	to := min(from+f.pageSz, len(keys))
	page := listPage{}
	page.Metadata.ResourceVersion = strconv.Itoa(f.rv)
	if to < len(keys) {
		page.Metadata.Continue = strconv.Itoa(to)
	}
	for _, k := range keys[from:to] {
		b, _ := json.Marshal(objs[k])
		page.Items = append(page.Items, b)
	}
	f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(page)
}

type fakeEvent struct {
	rv int
	ev watchEvent
}

// Test objects, as the API server serves them.

func meta(ns, name string) map[string]any {
	return map[string]any{
		"namespace": ns, "name": name, "uid": "uid-" + ns + "-" + name,
		"creationTimestamp": "2026-11-18T10:00:00Z", "managedFields": []any{map[string]any{"manager": "kubectl"}},
	}
}

func nodeObj(name, ip string, ready bool) map[string]any {
	st := "False"
	if ready {
		st = "True"
	}
	m := meta("", name)
	m["labels"] = map[string]any{"node-role.kubernetes.io/control-plane": ""}
	return map[string]any{"metadata": m, "status": map[string]any{
		"conditions": []any{map[string]any{"type": "Ready", "status": st}},
		"addresses":  []any{map[string]any{"type": "InternalIP", "address": ip}, map[string]any{"type": "Hostname", "address": name}},
		"capacity":   map[string]any{"cpu": "4", "memory": "8Gi"},
		"nodeInfo":   map[string]any{"kubeletVersion": "v1.34.1", "architecture": "arm64"},
	}}
}

func podObj(ns, name string, ready bool) map[string]any {
	state := map[string]any{"waiting": map[string]any{"reason": "ContainerCreating"}}
	phase := "Pending"
	if ready {
		state, phase = map[string]any{"running": map[string]any{"startedAt": "2026-11-18T10:00:01Z"}}, "Running"
	}
	return map[string]any{
		"metadata": meta(ns, name),
		"spec":     map[string]any{"nodeName": "pi-1", "containers": []any{map[string]any{"name": "app"}}},
		"status": map[string]any{"phase": phase, "containerStatuses": []any{
			map[string]any{"name": "app", "ready": ready, "restartCount": 0, "state": state},
		}},
	}
}
