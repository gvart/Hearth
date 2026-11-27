// SPDX-License-Identifier: AGPL-3.0-only

package openwrt

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/gvart/hearth/internal/discovery"
	"github.com/gvart/hearth/internal/integrations/kubernetes"
	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

// SealInfo names the key that seals connections: it is theirs alone.
const SealInfo = "hearth openwrt connection seal v1"

// Router states.
const (
	StateConnecting  = "connecting"
	StateConnected   = "connected"
	StateUnavailable = "unavailable"
)

const (
	// DefaultPollInterval is how often the hub reads each router.
	DefaultPollInterval = 15 * time.Second
	// DefaultSyncInterval is how often the manager rereads the router list
	// from the store, which picks up routers added or removed through
	// another hub of the cluster.
	DefaultSyncInterval = 5 * time.Second
	maxNameLength       = 63
)

// Errors of the manager's API.
var (
	ErrNotFound  = errors.New("no such openwrt router")
	ErrNameTaken = errors.New("an openwrt router with that name exists")
	ErrBadName   = errors.New("router name must be 1 to 63 printable characters")
	// ErrUnavailable is returned for an action on a router the hub cannot
	// read at the moment.
	ErrUnavailable = errors.New("the openwrt router is unavailable")
)

// RouterInfo describes an adopted router and its connection. It never holds
// the password.
type RouterInfo struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	URL  string `json:"url"`
	// Username is the rpcd login.
	Username string `json:"username"`
	// TLS is how the router is reached: none (http), system or fingerprint.
	TLS       string    `json:"tls"`
	State     string    `json:"state"`
	Error     string    `json:"error"`
	CreatedAt time.Time `json:"created_at"`
	// What the last read found.
	Hostname string `json:"hostname"`
	Model    string `json:"model"`
	Release  string `json:"release"`
	Clients  int    `json:"clients"`
}

// Snapshot is the current state of one router.
type Snapshot struct {
	Router     RouterInfo  `json:"router"`
	System     System      `json:"system"`
	Interfaces []Interface `json:"interfaces"`
	Clients    []Client    `json:"clients"`
	// Missing names what the last read could not get, and why.
	Missing []string `json:"missing"`
	// RestartClass is the policy class of restarting dnsmasq.
	RestartClass string `json:"restart_class"`
}

// AddRequest adopts a router.
type AddRequest struct {
	Name        string `json:"name"`
	URL         string `json:"url"`
	Username    string `json:"username"`
	Password    string `json:"password"`
	Fingerprint string `json:"fingerprint"`
}

// ActionResult says what the router did.
type ActionResult struct {
	Action string `json:"action"`
	Class  string `json:"class"`
	Target string `json:"target"`
	Result string `json:"result"`
}

// Config holds the manager's dependencies.
type Config struct {
	Store  *store.Store
	Sealer *kubernetes.Sealer
	Policy *policy.Engine
	Log    *slog.Logger
	// PollInterval defaults to DefaultPollInterval.
	PollInterval time.Duration
	// SyncInterval defaults to DefaultSyncInterval.
	SyncInterval time.Duration
	// Now defaults to time.Now.
	Now func() time.Time
}

// Manager adopts OpenWrt routers. It keeps one poller per router stored in
// the hub, serves their state, gives their clients to network discovery (it
// is a discovery.Source) and restarts dnsmasq (see RestartDNS).
//
// Every master of the cluster reads every router itself: the state is a
// cache of the routers, never written to the store but through discovery.
type Manager struct {
	store  *store.Store
	sealer *kubernetes.Sealer
	policy *policy.Engine
	log    *slog.Logger
	poll   time.Duration
	every  time.Duration
	now    func() time.Time
	kick   chan struct{}

	mu      sync.Mutex
	routers map[string]*running
}

// running is one router the manager reads. Its fields after cancel are
// guarded by the manager's mu.
type running struct {
	info    RouterInfo // ID, Name, URL, Username, TLS, CreatedAt
	client  *client    // nil if the connection could not be used
	cancel  context.CancelFunc
	done    chan struct{}
	refresh chan struct{}

	state  string
	err    string
	last   reading
	readAt time.Time
}

// NewManager returns a manager. Call Run to start reading routers; nothing
// connects before that.
func NewManager(cfg Config) *Manager {
	m := &Manager{
		store: cfg.Store, sealer: cfg.Sealer, policy: cfg.Policy, log: cfg.Log,
		poll: cfg.PollInterval, every: cfg.SyncInterval, now: cfg.Now,
		kick: make(chan struct{}, 1), routers: map[string]*running{},
	}
	if m.poll <= 0 {
		m.poll = DefaultPollInterval
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

// Run reads every stored router until ctx is done, rereading the list every
// SyncInterval and at once after a local Add or Remove. A router that cannot
// be reached shows as unavailable; it never ends Run.
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

func (m *Manager) sync(ctx context.Context) {
	stored, err := m.store.OpenWrtRouters().List(ctx)
	if err != nil {
		if ctx.Err() == nil {
			m.log.ErrorContext(ctx, "list openwrt routers", "err", err)
		}
		return
	}
	want := map[string]store.OpenWrtRouter{}
	for _, s := range stored {
		want[s.ID] = s
	}
	m.mu.Lock()
	var stop []*running
	for id, r := range m.routers {
		if _, ok := want[id]; !ok {
			stop = append(stop, r)
			delete(m.routers, id)
		}
	}
	for id, s := range want {
		if _, ok := m.routers[id]; !ok {
			m.routers[id] = m.start(ctx, s)
		}
	}
	m.mu.Unlock()
	for _, r := range stop {
		r.stop()
		m.log.InfoContext(ctx, "stopped reading openwrt router", "router", r.info.Name)
	}
}

func (r *running) stop() {
	r.cancel()
	<-r.done
	if r.client != nil {
		r.client.close()
	}
}

// start begins reading s. mu is held.
func (m *Manager) start(ctx context.Context, s store.OpenWrtRouter) *running {
	r := &running{
		info:    RouterInfo{ID: s.ID, Name: s.Name, CreatedAt: s.CreatedAt},
		state:   StateConnecting,
		done:    make(chan struct{}),
		refresh: make(chan struct{}, 1),
	}
	ctx, r.cancel = context.WithCancel(ctx)
	fail := func(msg string, err error) *running {
		m.log.ErrorContext(ctx, msg, "router", s.Name, "err", err)
		r.state, r.err = StateUnavailable, msg
		close(r.done)
		return r
	}
	raw, err := m.sealer.Open(s.ID, s.Sealed)
	if err != nil {
		return fail("cannot decrypt the connection", err)
	}
	var conn Connection
	if err := json.Unmarshal(raw, &conn); err != nil {
		// The error of a failed decode could quote the plaintext.
		return fail("invalid stored connection", errors.New("undecodable"))
	}
	r.info.URL, r.info.Username, r.info.TLS = conn.URL, conn.Username, conn.tlsMode()
	if r.client, err = newClient(conn); err != nil {
		return fail("invalid stored connection", err)
	}
	go func() {
		defer close(r.done)
		m.pollLoop(ctx, r)
	}()
	m.log.InfoContext(ctx, "reading openwrt router", "router", s.Name, "url", conn.URL, "tls", conn.tlsMode())
	return r
}

func (m *Manager) pollLoop(ctx context.Context, r *running) {
	t := time.NewTicker(m.poll)
	defer t.Stop()
	for {
		m.read(ctx, r)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-r.refresh:
		}
	}
}

// read polls the router once and publishes what it found.
func (m *Manager) read(ctx context.Context, r *running) {
	got, err := r.client.read(ctx)
	if ctx.Err() != nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err != nil {
		if r.err != err.Error() {
			m.log.WarnContext(ctx, "openwrt router unavailable", "router", r.info.Name, "err", err)
		}
		// What was read before may no longer be true: show none of it.
		r.state, r.err, r.last = StateUnavailable, err.Error(), reading{}
		return
	}
	if r.state != StateConnected {
		m.log.InfoContext(ctx, "openwrt router connected", "router", r.info.Name, "clients", len(got.clients))
	}
	r.state, r.err, r.last, r.readAt = StateConnected, "", got, m.now()
}

func (m *Manager) stopAll() {
	m.mu.Lock()
	all := m.routers
	m.routers = map[string]*running{}
	m.mu.Unlock()
	for _, r := range all {
		r.stop()
	}
}

// infoLocked fills r's state and what it read. mu is held.
func infoLocked(r *running) RouterInfo {
	info := r.info
	info.State, info.Error = r.state, r.err
	info.Hostname, info.Model, info.Release = r.last.system.Hostname, r.last.system.Model, r.last.system.Release
	info.Clients = len(r.last.clients)
	return info
}

// Routers lists the routers this hub reads, by name.
func (m *Manager) Routers() []RouterInfo {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]RouterInfo, 0, len(m.routers))
	for _, r := range m.routers {
		out = append(out, infoLocked(r))
	}
	slices.SortFunc(out, func(a, b RouterInfo) int { return cmp.Compare(a.Name, b.Name) })
	return out
}

// Snapshot returns the current state of router id.
func (m *Manager) Snapshot(id string) (Snapshot, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.routers[id]
	if !ok {
		return Snapshot{}, ErrNotFound
	}
	s := Snapshot{
		Router: infoLocked(r), System: r.last.system,
		Interfaces: slices.Clone(r.last.interfaces), Clients: slices.Clone(r.last.clients),
		Missing: slices.Clone(r.last.missing), RestartClass: restartClass(),
	}
	if s.Interfaces == nil {
		s.Interfaces = []Interface{}
	}
	if s.Clients == nil {
		s.Clients = []Client{}
	}
	if s.Missing == nil {
		s.Missing = []string{}
	}
	return s, nil
}

func restartClass() string {
	class, _ := policy.ClassOf(policy.OpenWrtDNSRestart)
	return string(class)
}

// ActionRestartDNS names the action of RestartDNS.
const ActionRestartDNS = "restart_dnsmasq"

// RestartDNS restarts dnsmasq, the router's DNS and DHCP server, on behalf
// of actorKind/actorID: one rc init call. Policy decides first, after
// precheck (the web UI's re-authentication), and audits the decision.
func (m *Manager) RestartDNS(ctx context.Context, actorKind, actorID, id string, precheck func(context.Context) error) (ActionResult, error) {
	resolve := func() (*running, error) {
		m.mu.Lock()
		defer m.mu.Unlock()
		r, ok := m.routers[id]
		if !ok {
			return nil, ErrNotFound
		}
		if r.state != StateConnected || r.client == nil {
			return nil, ErrUnavailable
		}
		return r, nil
	}
	r, err := resolve()
	if err != nil {
		return ActionResult{}, err
	}
	target := r.info.Name + "/dnsmasq"
	err = m.policy.Do(ctx, policy.Request{
		ActorKind: actorKind, ActorID: actorID, Action: policy.OpenWrtDNSRestart, Target: target,
		Detail: map[string]any{"router_id": id, "service": "dnsmasq", "action": "restart"}, Precheck: precheck,
	}, func(ctx context.Context) error {
		// An approval can be minutes old: the router may be gone.
		r, err := resolve()
		if err != nil {
			return err
		}
		return r.client.batch().call(ctx, "rc", "init", map[string]any{"name": "dnsmasq", "action": "restart"}, nil)
	})
	if err != nil {
		return ActionResult{}, fmt.Errorf("restart %s: %w", target, err)
	}
	select {
	case r.refresh <- struct{}{}:
	default:
	}
	return ActionResult{
		Action: ActionRestartDNS, Class: restartClass(), Target: target,
		Result: "dnsmasq restarted on " + r.info.Name,
	}, nil
}

// Add adopts a router on behalf of a web session from actorID, without
// connecting to it: one that cannot be reached yet shows as unavailable. The
// connection is sealed before it is stored. It is a policy action, audited;
// the password is never in the audit entry.
func (m *Manager) Add(ctx context.Context, actorID string, req AddRequest) (RouterInfo, error) {
	name := strings.TrimSpace(req.Name)
	if !validName(name) {
		return RouterInfo{}, ErrBadName
	}
	conn, err := Connection{URL: req.URL, Username: req.Username, Password: req.Password, Fingerprint: req.Fingerprint}.normalize()
	if err != nil {
		return RouterInfo{}, err
	}
	// The id is derived from the name, so two hubs adding the same name
	// make one router.
	id := store.OpenWrtRouterID(name)
	now := m.now().UTC().Truncate(time.Millisecond)
	err = m.policy.Do(ctx, policy.Request{
		ActorKind: policy.ActorWeb, ActorID: actorID, Action: policy.OpenWrtRouterAdd, Target: name,
		Detail: map[string]any{"id": id, "url": conn.URL, "username": conn.Username, "tls": conn.tlsMode()},
	}, func(ctx context.Context) error {
		existing, err := m.store.OpenWrtRouters().List(ctx)
		if err != nil {
			return err
		}
		for _, s := range existing {
			if s.Name == name {
				return ErrNameTaken
			}
		}
		raw, err := json.Marshal(conn) //nolint:gosec // sealed before it is stored
		if err != nil {
			return errors.New("encode connection")
		}
		sealed, err := m.sealer.Seal(id, raw)
		if err != nil {
			return err
		}
		return m.store.OpenWrtRouters().Add(ctx, store.OpenWrtRouter{ID: id, Name: name, Sealed: sealed, CreatedAt: now})
	})
	if err != nil {
		return RouterInfo{}, err
	}
	m.kickSync()
	return RouterInfo{
		ID: id, Name: name, URL: conn.URL, Username: conn.Username, TLS: conn.tlsMode(),
		State: StateConnecting, CreatedAt: now,
	}, nil
}

// Remove forgets router id and its password. It is a policy action, audited.
func (m *Manager) Remove(ctx context.Context, actorID, id string) error {
	target := id
	m.mu.Lock()
	if r, ok := m.routers[id]; ok {
		target = r.info.Name
	}
	m.mu.Unlock()
	err := m.policy.Do(ctx, policy.Request{
		ActorKind: policy.ActorWeb, ActorID: actorID, Action: policy.OpenWrtRouterRemove, Target: target,
		Detail: map[string]any{"id": id},
	}, func(ctx context.Context) error {
		return m.store.OpenWrtRouters().Remove(ctx, id)
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

func (m *Manager) kickSync() {
	select {
	case m.kick <- struct{}{}:
	default:
	}
}

// Name implements discovery.Source.
func (*Manager) Name() string { return store.SourceOpenWrt }

// Target implements discovery.Source.
func (*Manager) Target() string { return "openwrt" }

// Idle implements discovery's idle source: with no router read, an import
// has nothing to take from it.
func (m *Manager) Idle() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range m.routers {
		if r.state == StateConnected {
			return false
		}
	}
	return true
}

// Records implements discovery.Source: the clients of every router as the
// last read saw them, with no request to a router. A lease's hostname is
// the one its client sent; a wireless client was seen when the radio last
// heard it.
func (m *Manager) Records(context.Context) ([]discovery.Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []discovery.Record
	for _, r := range m.routers {
		if r.state != StateConnected {
			continue
		}
		for _, c := range r.last.clients {
			if c.IP == "" {
				continue // a wireless client with no lease has no address to merge
			}
			rec := discovery.Record{MAC: c.MAC, IP: c.IP, Hostname: c.Hostname, Lease: c.Lease}
			if c.Wireless {
				rec.Seen = r.readAt.Add(-time.Duration(c.Inactive) * time.Millisecond)
			}
			out = append(out, rec)
		}
	}
	return out, nil
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
