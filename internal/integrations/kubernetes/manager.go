// SPDX-License-Identifier: AGPL-3.0-only

package kubernetes

import (
	"cmp"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

// Change operations.
const (
	OpUpsert = "upsert"
	OpDelete = "delete"
)

// Notice types, as the hub's event stream names them.
const (
	// NoticeObject carries a Change.
	NoticeObject = "kube.object"
	// NoticeCluster carries a ClusterInfo whose state changed, or that was
	// added or removed (Removed set).
	NoticeCluster = "kube.cluster"
)

// Change is one entity added, updated or deleted in a cluster.
type Change struct {
	Cluster string `json:"cluster"`
	Kind    string `json:"kind"`
	Op      string `json:"op"`
	// Key identifies the entity within Kind: a node or namespace name,
	// namespace/name for a pod, kind/namespace/name for a workload, the
	// UID of an event.
	Key    string `json:"key"`
	Object any    `json:"object,omitempty"`
}

// Notice is one item of the live stream: Data is a Change (NoticeObject)
// or a ClusterInfo (NoticeCluster).
type Notice struct {
	Type string
	Data any
}

// ClusterInfo describes an adopted cluster and its connection.
type ClusterInfo struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Server    string    `json:"server"`
	Context   string    `json:"context"`
	State     string    `json:"state"`
	Error     string    `json:"error"`
	CreatedAt time.Time `json:"created_at"`
	Nodes     int       `json:"nodes"`
	Pods      int       `json:"pods"`
	Removed   bool      `json:"removed,omitempty"`
}

// Snapshot is the current state of one cluster.
type Snapshot struct {
	Cluster    ClusterInfo `json:"cluster"`
	Nodes      []Node      `json:"nodes"`
	Namespaces []Namespace `json:"namespaces"`
	Workloads  []Workload  `json:"workloads"`
	Pods       []Pod       `json:"pods"`
	// Events are the newest events first, at most maxEvents.
	Events []Event `json:"events"`
}

const (
	maxEvents = 200
	// DefaultSyncInterval is how often the manager rereads the cluster list
	// from the store, which picks up clusters added or removed through
	// another hub of a Raft cluster.
	DefaultSyncInterval = 5 * time.Second
	// MaxLogLines caps one pod log request.
	MaxLogLines   = 5000
	maxLogBytes   = 1 << 20
	logsTimeout   = 15 * time.Second
	maxNameLength = 63
)

// Errors of the manager's API.
var (
	ErrNotFound  = errors.New("no such cluster")
	ErrNameTaken = errors.New("a cluster with that name exists")
	ErrBadName   = errors.New("cluster name must be 1 to 63 printable characters")
	// ErrPodNotFound is returned for logs of an unknown pod or container.
	ErrPodNotFound = errors.New("no such pod or container")
)

// Config holds the manager's dependencies.
type Config struct {
	Store  *store.Store
	Sealer *Sealer
	Policy *policy.Engine
	Log    *slog.Logger
	// SyncInterval defaults to DefaultSyncInterval.
	SyncInterval time.Duration
	// Now defaults to time.Now.
	Now func() time.Time
}

// Manager adopts Kubernetes clusters. It keeps one watcher per cluster
// stored in the hub, serves their state and streams their changes, and
// carries out the few Kubernetes actions (see Act).
//
// Every hub of a Raft cluster runs its own Manager and watches every
// cluster itself: Kubernetes state is a cache of the API server, never
// written to the store, so each hub serves its own UI from its own watch.
type Manager struct {
	store   *store.Store
	sealer  *Sealer
	policy  *policy.Engine
	log     *slog.Logger
	every   time.Duration
	now     func() time.Time
	connect func(*kubeconfig) (*apiClient, error)
	// evictRetry and gonePoll pace a drain.
	evictRetry, gonePoll time.Duration

	kick chan struct{}
	bus  bus

	mu       sync.Mutex
	watchers map[string]*running
}

// running is one cluster the manager watches.
type running struct {
	info   ClusterInfo // ID, Name, Server, Context, CreatedAt
	w      *watcher    // nil if the kubeconfig could not be used
	err    string      // why w is nil
	cancel context.CancelFunc
	done   chan struct{}
	// last is the state last published.
	last [2]string
}

// NewManager returns a manager. Call Run to start watching.
func NewManager(cfg Config) *Manager {
	m := &Manager{
		store: cfg.Store, sealer: cfg.Sealer, policy: cfg.Policy, log: cfg.Log,
		every: cfg.SyncInterval, now: cfg.Now, connect: newAPIClient,
		evictRetry: defaultEvictRetry, gonePoll: defaultGonePoll,
		kick: make(chan struct{}, 1), watchers: map[string]*running{},
	}
	if m.every <= 0 {
		m.every = DefaultSyncInterval
	}
	if m.now == nil {
		m.now = time.Now
	}
	if m.log == nil {
		m.log = slog.New(slog.DiscardHandler)
	}
	return m
}

// Run watches every stored cluster until ctx is done, rereading the list
// every SyncInterval and at once after a local Add or Remove.
func (m *Manager) Run(ctx context.Context) error {
	t := time.NewTicker(m.every)
	defer t.Stop()
	defer m.stopAll()
	for {
		m.sync(ctx)
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		case <-m.kick:
		}
	}
}

// Subscribe returns a channel of notices and a function that ends the
// subscription. The channel is closed when the subscriber falls behind; it
// should then refetch and resubscribe.
func (m *Manager) Subscribe() (<-chan Notice, func()) { return m.bus.subscribe() }

func (m *Manager) sync(ctx context.Context) {
	stored, err := m.store.KubeClusters().List(ctx)
	if err != nil {
		if ctx.Err() == nil {
			m.log.ErrorContext(ctx, "list kubernetes clusters", "err", err)
		}
		return
	}
	want := map[string]store.KubeCluster{}
	for _, c := range stored {
		want[c.ID] = c
	}
	m.mu.Lock()
	var stop []*running
	for id, r := range m.watchers {
		if _, ok := want[id]; !ok {
			stop = append(stop, r)
			delete(m.watchers, id)
		}
	}
	for id, c := range want {
		if _, ok := m.watchers[id]; !ok {
			m.watchers[id] = m.start(ctx, c)
		}
	}
	var changed []ClusterInfo
	for _, r := range m.watchers {
		info := m.infoLocked(r)
		if s := [2]string{info.State, info.Error}; s != r.last {
			r.last = s
			changed = append(changed, info)
		}
	}
	m.mu.Unlock()
	for _, r := range stop {
		r.cancel()
		<-r.done
		info := r.info
		info.Removed = true
		m.bus.publish(Notice{Type: NoticeCluster, Data: info})
		m.log.InfoContext(ctx, "stopped watching kubernetes cluster", "cluster", r.info.Name)
	}
	for _, info := range changed {
		m.bus.publish(Notice{Type: NoticeCluster, Data: info})
	}
}

// start begins watching c. mu is held.
func (m *Manager) start(ctx context.Context, c store.KubeCluster) *running {
	r := &running{
		info: ClusterInfo{ID: c.ID, Name: c.Name, CreatedAt: c.CreatedAt},
		done: make(chan struct{}),
	}
	ctx, r.cancel = context.WithCancel(ctx)
	fail := func(msg string, err error) *running {
		m.log.ErrorContext(ctx, msg, "cluster", c.Name, "err", err)
		r.err = msg
		close(r.done)
		return r
	}
	raw, err := m.sealer.Open(c.ID, c.Sealed)
	if err != nil {
		return fail("cannot decrypt the kubeconfig", err)
	}
	kc, err := parseKubeconfig(raw)
	if err != nil {
		return fail("invalid kubeconfig", err)
	}
	r.info.Server, r.info.Context = kc.server, kc.context
	cl, err := m.connect(kc)
	if err != nil {
		return fail("cannot build a client from the kubeconfig", err)
	}
	r.w = newWatcher(c.ID, cl, m.log, m.now,
		func(ch Change) { m.bus.publish(Notice{Type: NoticeObject, Data: ch}) },
		m.linker(ctx),
		m.kickSync)
	go func() {
		defer close(r.done)
		r.w.run(ctx)
	}()
	m.log.InfoContext(ctx, "watching kubernetes cluster", "cluster", c.Name, "server", kc.server)
	return r
}

// linker links a node to its device, reading the device list on each call.
func (m *Manager) linker(ctx context.Context) func(Node) Node {
	return func(n Node) Node {
		devs, err := m.store.Devices().List(ctx)
		if err != nil {
			return n
		}
		n.DeviceID = newDeviceIndex(devs).link(n)
		return n
	}
}

func (m *Manager) kickSync() {
	select {
	case m.kick <- struct{}{}:
	default:
	}
}

func (m *Manager) stopAll() {
	m.mu.Lock()
	all := m.watchers
	m.watchers = map[string]*running{}
	m.mu.Unlock()
	for _, r := range all {
		r.cancel()
		<-r.done
	}
}

// infoLocked fills r's state and counts. mu is held.
func (m *Manager) infoLocked(r *running) ClusterInfo {
	info := r.info
	if r.w == nil {
		info.State, info.Error = StateError, r.err
		return info
	}
	info.State, info.Error = r.w.state()
	info.Nodes, info.Pods = r.w.count(KindNode), r.w.count(KindPod)
	return info
}

// Clusters lists the clusters this hub watches, by name. A cluster added
// on another hub of a Raft cluster appears within SyncInterval.
func (m *Manager) Clusters() []ClusterInfo {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]ClusterInfo, 0, len(m.watchers))
	for _, r := range m.watchers {
		out = append(out, m.infoLocked(r))
	}
	slices.SortFunc(out, func(a, b ClusterInfo) int { return cmp.Compare(a.Name, b.Name) })
	return out
}

func (m *Manager) get(id string) (*running, ClusterInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.watchers[id]
	if !ok {
		return nil, ClusterInfo{}, ErrNotFound
	}
	return r, m.infoLocked(r), nil
}

// getNamed is get by the cluster's name.
func (m *Manager) getNamed(name string) (*running, ClusterInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range m.watchers {
		if r.info.Name == name {
			return r, m.infoLocked(r), nil
		}
	}
	return nil, ClusterInfo{}, fmt.Errorf("%w named %q", ErrNotFound, name)
}

// Snapshot returns the current state of cluster id.
func (m *Manager) Snapshot(ctx context.Context, id string) (Snapshot, error) {
	r, info, err := m.get(id)
	if err != nil {
		return Snapshot{}, err
	}
	s := Snapshot{Cluster: info, Nodes: []Node{}, Namespaces: []Namespace{}, Workloads: []Workload{}, Pods: []Pod{}, Events: []Event{}}
	if r.w == nil {
		return s, nil
	}
	var idx deviceIndex
	if devs, err := m.store.Devices().List(ctx); err == nil {
		idx = newDeviceIndex(devs)
	}
	s.Nodes = entitiesOf[Node](r.w, KindNode)
	for i := range s.Nodes {
		s.Nodes[i].DeviceID = idx.link(s.Nodes[i])
	}
	s.Namespaces = entitiesOf[Namespace](r.w, KindNamespace)
	s.Workloads = entitiesOf[Workload](r.w, KindWorkload)
	s.Pods = entitiesOf[Pod](r.w, KindPod)
	s.Events = entitiesOf[Event](r.w, KindEvent)
	slices.SortFunc(s.Nodes, func(a, b Node) int { return cmp.Compare(a.Name, b.Name) })
	slices.SortFunc(s.Namespaces, func(a, b Namespace) int { return cmp.Compare(a.Name, b.Name) })
	slices.SortFunc(s.Workloads, func(a, b Workload) int { return cmp.Compare(workloadKey(a), workloadKey(b)) })
	slices.SortFunc(s.Pods, func(a, b Pod) int {
		return cmp.Or(cmp.Compare(a.Namespace, b.Namespace), cmp.Compare(a.Name, b.Name))
	})
	slices.SortFunc(s.Events, func(a, b Event) int { return b.Last.Compare(a.Last) })
	if len(s.Events) > maxEvents {
		s.Events = s.Events[:maxEvents]
	}
	return s, nil
}

func entitiesOf[T any](w *watcher, kind string) []T {
	vs := w.entities(kind)
	out := make([]T, 0, len(vs))
	for _, v := range vs {
		if t, ok := v.(T); ok {
			out = append(out, t)
		}
	}
	return out
}

// Add adopts the cluster of kubeconfig raw under name (its current
// context's name if empty), on behalf of a web session from actorID. The
// kubeconfig is reduced to its current context and sealed before it is
// stored. It is a policy action, audited.
func (m *Manager) Add(ctx context.Context, actorID, name string, raw []byte) (ClusterInfo, error) {
	kc, err := parseKubeconfig(raw)
	if err != nil {
		return ClusterInfo{}, err
	}
	name = strings.TrimSpace(name)
	if name == "" {
		name = kc.context
	}
	if !validName(name) {
		return ClusterInfo{}, ErrBadName
	}
	id, err := newID()
	if err != nil {
		return ClusterInfo{}, err
	}
	now := m.now().UTC().Truncate(time.Millisecond)
	err = m.policy.Do(ctx, policy.Request{
		ActorKind: policy.ActorWeb, ActorID: actorID, Action: policy.KubeClusterAdd, Target: name,
		Detail: map[string]any{"id": id, "server": kc.server, "context": kc.context},
	}, func(ctx context.Context) error {
		existing, err := m.store.KubeClusters().List(ctx)
		if err != nil {
			return err
		}
		for _, c := range existing {
			if c.Name == name {
				return ErrNameTaken
			}
		}
		sealed, err := m.sealer.Seal(id, kc.raw)
		if err != nil {
			return err
		}
		return m.store.KubeClusters().Add(ctx, store.KubeCluster{ID: id, Name: name, Sealed: sealed, CreatedAt: now})
	})
	if err != nil {
		return ClusterInfo{}, err
	}
	m.kickSync()
	return ClusterInfo{ID: id, Name: name, Server: kc.server, Context: kc.context, State: StateConnecting, CreatedAt: now}, nil
}

// Remove forgets cluster id and its kubeconfig. It is a policy action,
// audited.
func (m *Manager) Remove(ctx context.Context, actorID, id string) error {
	target := id
	if _, info, err := m.get(id); err == nil {
		target = info.Name
	}
	err := m.policy.Do(ctx, policy.Request{
		ActorKind: policy.ActorWeb, ActorID: actorID, Action: policy.KubeClusterRemove, Target: target,
		Detail: map[string]any{"id": id},
	}, func(ctx context.Context) error {
		return m.store.KubeClusters().Remove(ctx, id)
	})
	if errors.Is(err, store.ErrNotFound) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	m.kickSync()
	return nil
}

// Logs returns up to tail of the last lines of a pod container's log
// (the pod's only container if container is empty), on behalf of a web
// session from actorID. Reading logs is a policy action, audited.
func (m *Manager) Logs(ctx context.Context, actorID, id, namespace, pod, container string, tail int) (string, error) {
	r, info, err := m.get(id)
	if err != nil {
		return "", err
	}
	if r.w == nil {
		return "", fmt.Errorf("cluster %s: %s", info.Name, r.err)
	}
	for _, n := range []string{namespace, pod, container} {
		if n != "" && !validObjectName(n) {
			return "", ErrPodNotFound
		}
	}
	tail = max(1, min(tail, MaxLogLines))
	var out []byte
	err = m.policy.Do(ctx, policy.Request{
		ActorKind: policy.ActorWeb, ActorID: actorID, Action: policy.KubePodLogs,
		Target: info.Name + "/" + namespace + "/" + pod,
		Detail: map[string]any{"container": container, "tail": tail},
	}, func(ctx context.Context) error {
		ctx, cancel := context.WithTimeout(ctx, logsTimeout)
		defer cancel()
		out, err = r.w.c.logs(ctx, namespace, pod, podLogOptions{
			container: container, tailLines: int64(tail), limitBytes: maxLogBytes,
		})
		return err
	})
	if err != nil {
		if hasCode(err, http.StatusNotFound) {
			return "", ErrPodNotFound
		}
		return "", fmt.Errorf("logs of %s/%s: %w", namespace, pod, err)
	}
	return string(out), nil
}

// validObjectName reports whether s can be a Kubernetes namespace, pod or
// container name (a DNS subdomain or label): it is put in a URL path as is.
func validObjectName(s string) bool {
	if s == "" || len(s) > 253 || s[0] == '-' || s[0] == '.' || s[len(s)-1] == '-' || s[len(s)-1] == '.' {
		return false
	}
	for _, r := range s {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' && r != '.' {
			return false
		}
	}
	return !strings.Contains(s, "..")
}

func validName(s string) bool {
	if s == "" || len(s) > maxNameLength {
		return false
	}
	for _, r := range s {
		if !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

func newID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("new cluster ID: %w", err)
	}
	return hex.EncodeToString(b), nil
}
