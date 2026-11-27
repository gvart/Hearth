// SPDX-License-Identifier: AGPL-3.0-only

package opnsense

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
const SealInfo = "hearth opnsense connection seal v1"

// Firewall states.
const (
	StateConnecting  = "connecting"
	StateConnected   = "connected"
	StateUnavailable = "unavailable"
)

const (
	// DefaultPollInterval is how often the hub reads each firewall.
	DefaultPollInterval = 15 * time.Second
	// DefaultSyncInterval is how often the manager rereads the firewall list
	// from the store, which picks up firewalls added or removed through
	// another hub of the cluster.
	DefaultSyncInterval = 5 * time.Second
	maxNameLength       = 63
)

// Errors of the manager's API.
var (
	ErrNotFound  = errors.New("no such opnsense firewall")
	ErrNameTaken = errors.New("an opnsense firewall with that name exists")
	ErrBadName   = errors.New("firewall name must be 1 to 63 printable characters")
	// ErrUnavailable is returned for an action on a firewall the hub cannot
	// read at the moment.
	ErrUnavailable = errors.New("the opnsense firewall is unavailable")
)

// FirewallInfo describes an adopted firewall and its connection. It never holds
// the API key or secret.
type FirewallInfo struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	URL  string `json:"url"`
	// TLS is how the firewall's certificate is verified: system or fingerprint.
	TLS       string    `json:"tls"`
	State     string    `json:"state"`
	Error     string    `json:"error"`
	CreatedAt time.Time `json:"created_at"`
	// What the last read found.
	Hostname string `json:"hostname"`
	// Version is the product version, such as "OPNsense 25.7.4-amd64".
	Version string `json:"version"`
	Clients int    `json:"clients"`
}

// Snapshot is the current state of one firewall.
type Snapshot struct {
	Firewall   FirewallInfo `json:"firewall"`
	System     System       `json:"system"`
	Firmware   Firmware     `json:"firmware"`
	Interfaces []Interface  `json:"interfaces"`
	Clients    []Client     `json:"clients"`
	// Missing names what the last read could not get, and why.
	Missing []string `json:"missing"`
	// RestartClass is the policy class of restarting Unbound.
	RestartClass string `json:"restart_class"`
}

// AddRequest adopts a firewall.
type AddRequest struct {
	Name        string `json:"name"`
	URL         string `json:"url"`
	Key         string `json:"key"`
	Secret      string `json:"secret"`
	Fingerprint string `json:"fingerprint"`
}

// ActionResult says what the firewall did.
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

// Manager adopts OPNsense firewalls. It keeps one poller per firewall stored in
// the hub, serves their state, gives their clients to network discovery (it
// is a discovery.Source) and restarts Unbound (see RestartDNS).
//
// Every master of the cluster reads every firewall itself: the state is a
// cache of the firewalls, never written to the store but through discovery.
type Manager struct {
	store  *store.Store
	sealer *kubernetes.Sealer
	policy *policy.Engine
	log    *slog.Logger
	poll   time.Duration
	every  time.Duration
	now    func() time.Time
	kick   chan struct{}

	mu        sync.Mutex
	firewalls map[string]*running
}

// running is one firewall the manager reads. Its fields after cancel are
// guarded by the manager's mu.
type running struct {
	info    FirewallInfo // ID, Name, URL, TLS, CreatedAt
	client  *client      // nil if the connection could not be used
	cancel  context.CancelFunc
	done    chan struct{}
	refresh chan struct{}

	state  string
	err    string
	last   reading
	readAt time.Time
}

// NewManager returns a manager. Call Run to start reading firewalls; nothing
// connects before that.
func NewManager(cfg Config) *Manager {
	m := &Manager{
		store: cfg.Store, sealer: cfg.Sealer, policy: cfg.Policy, log: cfg.Log,
		poll: cfg.PollInterval, every: cfg.SyncInterval, now: cfg.Now,
		kick: make(chan struct{}, 1), firewalls: map[string]*running{},
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

// Run reads every stored firewall until ctx is done, rereading the list every
// SyncInterval and at once after a local Add or Remove. A firewall that cannot
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
	stored, err := m.store.OPNsenseFirewalls().List(ctx)
	if err != nil {
		if ctx.Err() == nil {
			m.log.ErrorContext(ctx, "list opnsense firewalls", "err", err)
		}
		return
	}
	want := map[string]store.OPNsenseFirewall{}
	for _, s := range stored {
		want[s.ID] = s
	}
	m.mu.Lock()
	var stop []*running
	for id, r := range m.firewalls {
		if _, ok := want[id]; !ok {
			stop = append(stop, r)
			delete(m.firewalls, id)
		}
	}
	for id, s := range want {
		if _, ok := m.firewalls[id]; !ok {
			m.firewalls[id] = m.start(ctx, s)
		}
	}
	m.mu.Unlock()
	for _, r := range stop {
		r.stop()
		m.log.InfoContext(ctx, "stopped reading opnsense firewall", "firewall", r.info.Name)
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
func (m *Manager) start(ctx context.Context, s store.OPNsenseFirewall) *running {
	r := &running{
		info:    FirewallInfo{ID: s.ID, Name: s.Name, CreatedAt: s.CreatedAt},
		state:   StateConnecting,
		done:    make(chan struct{}),
		refresh: make(chan struct{}, 1),
	}
	ctx, r.cancel = context.WithCancel(ctx)
	fail := func(msg string, err error) *running {
		m.log.ErrorContext(ctx, msg, "firewall", s.Name, "err", err)
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
	r.info.URL, r.info.TLS = conn.URL, conn.tlsMode()
	if r.client, err = newClient(conn); err != nil {
		return fail("invalid stored connection", err)
	}
	go func() {
		defer close(r.done)
		m.pollLoop(ctx, r)
	}()
	m.log.InfoContext(ctx, "reading opnsense firewall", "firewall", s.Name, "url", conn.URL, "tls", conn.tlsMode())
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

// read polls the firewall once and publishes what it found.
func (m *Manager) read(ctx context.Context, r *running) {
	got, err := r.client.read(ctx)
	if ctx.Err() != nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err != nil {
		if r.err != err.Error() {
			m.log.WarnContext(ctx, "opnsense firewall unavailable", "firewall", r.info.Name, "err", err)
		}
		// What was read before may no longer be true: show none of it.
		r.state, r.err, r.last = StateUnavailable, err.Error(), reading{}
		return
	}
	if r.state != StateConnected {
		m.log.InfoContext(ctx, "opnsense firewall connected", "firewall", r.info.Name, "clients", len(got.clients))
	}
	r.state, r.err, r.last, r.readAt = StateConnected, "", got, m.now()
}

func (m *Manager) stopAll() {
	m.mu.Lock()
	all := m.firewalls
	m.firewalls = map[string]*running{}
	m.mu.Unlock()
	for _, r := range all {
		r.stop()
	}
}

// infoLocked fills r's state and what it read. mu is held.
func infoLocked(r *running) FirewallInfo {
	info := r.info
	info.State, info.Error = r.state, r.err
	info.Hostname = r.last.system.Hostname
	if len(r.last.system.Versions) > 0 {
		info.Version = r.last.system.Versions[0]
	}
	info.Clients = len(r.last.clients)
	return info
}

// Firewalls lists the firewalls this hub reads, by name.
func (m *Manager) Firewalls() []FirewallInfo {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]FirewallInfo, 0, len(m.firewalls))
	for _, r := range m.firewalls {
		out = append(out, infoLocked(r))
	}
	slices.SortFunc(out, func(a, b FirewallInfo) int { return cmp.Compare(a.Name, b.Name) })
	return out
}

// Snapshot returns the current state of firewall id.
func (m *Manager) Snapshot(id string) (Snapshot, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.firewalls[id]
	if !ok {
		return Snapshot{}, ErrNotFound
	}
	s := Snapshot{
		Firewall: infoLocked(r), System: r.last.system, Firmware: r.last.firmware,
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
	class, _ := policy.ClassOf(policy.OPNsenseUnboundRestart)
	return string(class)
}

// ActionRestartDNS names the action of RestartDNS.
const ActionRestartDNS = "restart_unbound"

// RestartDNS restarts Unbound, the firewall's DNS resolver, on behalf of
// actorKind/actorID: one API call. Policy decides first, after
// precheck (the web UI's re-authentication), and audits the decision.
func (m *Manager) RestartDNS(ctx context.Context, actorKind, actorID, id string, precheck func(context.Context) error) (ActionResult, error) {
	resolve := func() (*running, error) {
		m.mu.Lock()
		defer m.mu.Unlock()
		r, ok := m.firewalls[id]
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
	target := r.info.Name + "/unbound"
	err = m.policy.Do(ctx, policy.Request{
		ActorKind: actorKind, ActorID: actorID, Action: policy.OPNsenseUnboundRestart, Target: target,
		Detail: map[string]any{"firewall_id": id, "service": "unbound", "action": "restart"}, Precheck: precheck,
	}, func(ctx context.Context) error {
		// An approval can be minutes old: the firewall may be gone.
		r, err := resolve()
		if err != nil {
			return err
		}
		return r.client.restartUnbound(ctx)
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
		Result: "Unbound restarted on " + r.info.Name,
	}, nil
}

// Add adopts a firewall on behalf of a web session from actorID, without
// connecting to it: one that cannot be reached yet shows as unavailable. The
// connection is sealed before it is stored. It is a policy action, audited;
// the password is never in the audit entry.
func (m *Manager) Add(ctx context.Context, actorID string, req AddRequest) (FirewallInfo, error) {
	name := strings.TrimSpace(req.Name)
	if !validName(name) {
		return FirewallInfo{}, ErrBadName
	}
	conn, err := Connection{URL: req.URL, Key: req.Key, Secret: req.Secret, Fingerprint: req.Fingerprint}.normalize()
	if err != nil {
		return FirewallInfo{}, err
	}
	// The id is derived from the name, so two hubs adding the same name
	// make one firewall.
	id := store.OPNsenseFirewallID(name)
	now := m.now().UTC().Truncate(time.Millisecond)
	err = m.policy.Do(ctx, policy.Request{
		ActorKind: policy.ActorWeb, ActorID: actorID, Action: policy.OPNsenseFirewallAdd, Target: name,
		Detail: map[string]any{"id": id, "url": conn.URL, "tls": conn.tlsMode()},
	}, func(ctx context.Context) error {
		existing, err := m.store.OPNsenseFirewalls().List(ctx)
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
		return m.store.OPNsenseFirewalls().Add(ctx, store.OPNsenseFirewall{ID: id, Name: name, Sealed: sealed, CreatedAt: now})
	})
	if err != nil {
		return FirewallInfo{}, err
	}
	m.kickSync()
	return FirewallInfo{
		ID: id, Name: name, URL: conn.URL, TLS: conn.tlsMode(),
		State: StateConnecting, CreatedAt: now,
	}, nil
}

// Remove forgets firewall id and its password. It is a policy action, audited.
func (m *Manager) Remove(ctx context.Context, actorID, id string) error {
	target := id
	m.mu.Lock()
	if r, ok := m.firewalls[id]; ok {
		target = r.info.Name
	}
	m.mu.Unlock()
	err := m.policy.Do(ctx, policy.Request{
		ActorKind: policy.ActorWeb, ActorID: actorID, Action: policy.OPNsenseFirewallRemove, Target: target,
		Detail: map[string]any{"id": id},
	}, func(ctx context.Context) error {
		return m.store.OPNsenseFirewalls().Remove(ctx, id)
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
func (*Manager) Name() string { return store.SourceOPNsense }

// Target implements discovery.Source.
func (*Manager) Target() string { return "opnsense" }

// Idle implements discovery's idle source: with no firewall read, an import
// has nothing to take from it.
func (m *Manager) Idle() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range m.firewalls {
		if r.state == StateConnected {
			return false
		}
	}
	return true
}

// Records implements discovery.Source: the clients of every firewall as the
// last read saw them, with no request to a firewall. A lease's hostname is
// the one its client sent; a client in the ARP table was seen at the read.
// The NDP table's IPv6 addresses stay on the firewall's page: discovery
// merges IPv4 only.
func (m *Manager) Records(context.Context) ([]discovery.Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []discovery.Record
	for _, r := range m.firewalls {
		if r.state != StateConnected {
			continue
		}
		for _, c := range r.last.clients {
			if c.IP == "" {
				continue // a client known from the NDP table only has no IPv4 to merge
			}
			rec := discovery.Record{MAC: c.MAC, IP: c.IP, Hostname: c.Hostname, Vendor: c.Vendor, Lease: c.Lease}
			if c.ARP {
				rec.Seen = r.readAt
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
