// SPDX-License-Identifier: AGPL-3.0-only

package unifi

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
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
const SealInfo = "hearth unifi connection seal v1"

// Controller states.
const (
	StateConnecting  = "connecting"
	StateConnected   = "connected"
	StateUnavailable = "unavailable"
)

const (
	// DefaultPollInterval is how often the hub reads each controller.
	DefaultPollInterval = 15 * time.Second
	// DefaultSyncInterval is how often the manager rereads the controller
	// list from the store, which picks up controllers added or removed
	// through another hub of the cluster.
	DefaultSyncInterval = 5 * time.Second
	maxNameLength       = 63
)

// Errors of the manager's API.
var (
	ErrNotFound  = errors.New("no such unifi controller")
	ErrNameTaken = errors.New("a unifi controller with that name exists")
	ErrBadName   = errors.New("controller name must be 1 to 63 printable characters")
	// ErrUnavailable is returned for an action on a controller the hub
	// cannot read at the moment.
	ErrUnavailable = errors.New("the unifi controller is unavailable")
	// ErrNoSuchAP is returned for a restart of a MAC that is no access
	// point of the site, as the last read saw it.
	ErrNoSuchAP = errors.New("no access point with that MAC on this controller")
)

// ControllerInfo describes an adopted controller and its connection. It
// never holds the password or the API key.
type ControllerInfo struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	URL  string `json:"url"`
	// Kind is unifi_os or classic; Site the site's short name.
	Kind string `json:"kind"`
	Site string `json:"site"`
	// Auth is api_key or password; Username is the local login's.
	Auth      string    `json:"auth"`
	Username  string    `json:"username"`
	TLS       string    `json:"tls"`
	State     string    `json:"state"`
	Error     string    `json:"error"`
	CreatedAt time.Time `json:"created_at"`
	// What the last read found.
	Devices int `json:"devices"`
	Clients int `json:"clients"`
}

// Snapshot is the current state of one controller's site.
type Snapshot struct {
	Controller ControllerInfo `json:"controller"`
	Devices    []Device       `json:"devices"`
	Clients    []Client       `json:"clients"`
	Health     []Health       `json:"health"`
	// Missing names what the last read could not get, and why.
	Missing []string `json:"missing"`
	// RestartClass is the policy class of restarting an access point.
	RestartClass string `json:"restart_class"`
}

// AddRequest adopts a controller.
type AddRequest struct {
	Name        string `json:"name"`
	URL         string `json:"url"`
	Kind        string `json:"kind"`
	Site        string `json:"site"`
	APIKey      string `json:"api_key"`
	Username    string `json:"username"`
	Password    string `json:"password"`
	Fingerprint string `json:"fingerprint"`
}

// ActionResult says what the controller did.
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

// Manager adopts UniFi controllers. It keeps one poller per controller
// stored in the hub, serves their state, gives their clients to network
// discovery (it is a discovery.Source) and restarts access points (see
// RestartAP).
//
// Every master of the cluster reads every controller itself: the state is a
// cache of the controllers, never written to the store but through
// discovery.
type Manager struct {
	store  *store.Store
	sealer *kubernetes.Sealer
	policy *policy.Engine
	log    *slog.Logger
	poll   time.Duration
	every  time.Duration
	now    func() time.Time
	kick   chan struct{}

	mu          sync.Mutex
	controllers map[string]*running
}

// running is one controller the manager reads. Its fields after cancel are
// guarded by the manager's mu.
type running struct {
	info    ControllerInfo // ID, Name, URL, Kind, Site, Auth, Username, TLS, CreatedAt
	client  *client        // nil if the connection could not be used
	cancel  context.CancelFunc
	done    chan struct{}
	refresh chan struct{}

	state  string
	err    string
	last   reading
	readAt time.Time
}

// NewManager returns a manager. Call Run to start reading controllers;
// nothing connects before that.
func NewManager(cfg Config) *Manager {
	m := &Manager{
		store: cfg.Store, sealer: cfg.Sealer, policy: cfg.Policy, log: cfg.Log,
		poll: cfg.PollInterval, every: cfg.SyncInterval, now: cfg.Now,
		kick: make(chan struct{}, 1), controllers: map[string]*running{},
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

// Run reads every stored controller until ctx is done, rereading the list
// every SyncInterval and at once after a local Add or Remove. A controller
// that cannot be reached shows as unavailable; it never ends Run.
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
	stored, err := m.store.UniFiControllers().List(ctx)
	if err != nil {
		if ctx.Err() == nil {
			m.log.ErrorContext(ctx, "list unifi controllers", "err", err)
		}
		return
	}
	want := map[string]store.UniFiController{}
	for _, s := range stored {
		want[s.ID] = s
	}
	m.mu.Lock()
	var stop []*running
	for id, r := range m.controllers {
		if _, ok := want[id]; !ok {
			stop = append(stop, r)
			delete(m.controllers, id)
		}
	}
	for id, s := range want {
		if _, ok := m.controllers[id]; !ok {
			m.controllers[id] = m.start(ctx, s)
		}
	}
	m.mu.Unlock()
	for _, r := range stop {
		r.stop()
		m.log.InfoContext(ctx, "stopped reading unifi controller", "controller", r.info.Name)
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
func (m *Manager) start(ctx context.Context, s store.UniFiController) *running {
	r := &running{
		info:    ControllerInfo{ID: s.ID, Name: s.Name, CreatedAt: s.CreatedAt},
		state:   StateConnecting,
		done:    make(chan struct{}),
		refresh: make(chan struct{}, 1),
	}
	ctx, r.cancel = context.WithCancel(ctx)
	fail := func(msg string, err error) *running {
		m.log.ErrorContext(ctx, msg, "controller", s.Name, "err", err)
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
	r.info = infoOf(r.info, conn)
	if r.client, err = newClient(conn); err != nil {
		return fail("invalid stored connection", err)
	}
	go func() {
		defer close(r.done)
		m.pollLoop(ctx, r)
	}()
	m.log.InfoContext(ctx, "reading unifi controller", "controller", s.Name, "url", conn.URL, "kind", conn.Kind,
		"site", conn.Site, "auth", conn.authMode(), "tls", conn.tlsMode())
	return r
}

// infoOf fills info with what conn says, leaving its secrets out.
func infoOf(info ControllerInfo, conn Connection) ControllerInfo {
	info.URL, info.Kind, info.Site, info.Auth, info.TLS = conn.URL, conn.Kind, conn.Site, conn.authMode(), conn.tlsMode()
	info.Username = conn.Username
	return info
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

// read polls the controller once and publishes what it found.
func (m *Manager) read(ctx context.Context, r *running) {
	got, err := r.client.read(ctx)
	if ctx.Err() != nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err != nil {
		if r.err != err.Error() {
			m.log.WarnContext(ctx, "unifi controller unavailable", "controller", r.info.Name, "err", err)
		}
		// What was read before may no longer be true: show none of it.
		r.state, r.err, r.last = StateUnavailable, err.Error(), reading{}
		return
	}
	if r.state != StateConnected {
		m.log.InfoContext(ctx, "unifi controller connected", "controller", r.info.Name,
			"devices", len(got.devices), "clients", len(got.clients))
	}
	r.state, r.err, r.last, r.readAt = StateConnected, "", got, m.now()
}

func (m *Manager) stopAll() {
	m.mu.Lock()
	all := m.controllers
	m.controllers = map[string]*running{}
	m.mu.Unlock()
	for _, r := range all {
		r.stop()
	}
}

// infoLocked fills r's state and what it read. mu is held.
func infoLocked(r *running) ControllerInfo {
	info := r.info
	info.State, info.Error = r.state, r.err
	info.Devices, info.Clients = len(r.last.devices), len(r.last.clients)
	return info
}

// Controllers lists the controllers this hub reads, by name.
func (m *Manager) Controllers() []ControllerInfo {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]ControllerInfo, 0, len(m.controllers))
	for _, r := range m.controllers {
		out = append(out, infoLocked(r))
	}
	slices.SortFunc(out, func(a, b ControllerInfo) int { return cmp.Compare(a.Name, b.Name) })
	return out
}

// Snapshot returns the current state of controller id.
func (m *Manager) Snapshot(id string) (Snapshot, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.controllers[id]
	if !ok {
		return Snapshot{}, ErrNotFound
	}
	s := Snapshot{
		Controller: infoLocked(r), Devices: slices.Clone(r.last.devices), Clients: slices.Clone(r.last.clients),
		Health: slices.Clone(r.last.health), Missing: slices.Clone(r.last.missing), RestartClass: restartClass(),
	}
	if s.Devices == nil {
		s.Devices = []Device{}
	}
	if s.Clients == nil {
		s.Clients = []Client{}
	}
	if s.Health == nil {
		s.Health = []Health{}
	}
	if s.Missing == nil {
		s.Missing = []string{}
	}
	return s, nil
}

func restartClass() string {
	class, _ := policy.ClassOf(policy.UniFiAPRestart)
	return string(class)
}

// ActionRestartAP names the action of RestartAP.
const ActionRestartAP = "restart_ap"

// RestartAP restarts the access point mac of controller id on behalf of
// actorKind/actorID: one devmgr restart command. Only an access point the
// last read saw can be restarted, never a gateway or a switch. Policy
// decides first, after precheck (the web UI's re-authentication), and
// audits the decision.
func (m *Manager) RestartAP(ctx context.Context, actorKind, actorID, id, mac string, precheck func(context.Context) error) (ActionResult, error) {
	mac, ok := hostMAC(mac)
	if !ok {
		return ActionResult{}, ErrNoSuchAP
	}
	resolve := func() (*running, Device, error) {
		m.mu.Lock()
		defer m.mu.Unlock()
		r, ok := m.controllers[id]
		if !ok {
			return nil, Device{}, ErrNotFound
		}
		if r.state != StateConnected || r.client == nil {
			return nil, Device{}, ErrUnavailable
		}
		for _, d := range r.last.devices {
			if d.MAC == mac && d.Kind == DeviceAccessPoint {
				return r, d, nil
			}
		}
		return nil, Device{}, ErrNoSuchAP
	}
	r, ap, err := resolve()
	if err != nil {
		return ActionResult{}, err
	}
	target := r.info.Name + "/" + ap.Name
	err = m.policy.Do(ctx, policy.Request{
		ActorKind: actorKind, ActorID: actorID, Action: policy.UniFiAPRestart, Target: target,
		Detail: map[string]any{"controller_id": id, "site": r.info.Site, "mac": mac, "model": ap.Model}, Precheck: precheck,
	}, func(ctx context.Context) error {
		// An approval can be minutes old: the controller or the AP may be gone.
		r, _, err := resolve()
		if err != nil {
			return err
		}
		return r.client.batch().call(ctx, http.MethodPost, "/cmd/devmgr", map[string]any{"cmd": "restart", "mac": mac}, nil)
	})
	if err != nil {
		return ActionResult{}, fmt.Errorf("restart %s: %w", target, err)
	}
	select {
	case r.refresh <- struct{}{}:
	default:
	}
	return ActionResult{
		Action: ActionRestartAP, Class: restartClass(), Target: target,
		Result: ap.Name + " is restarting: its clients reconnect in a minute or two",
	}, nil
}

// Add adopts a controller on behalf of a web session from actorID, without
// connecting to it: one that cannot be reached yet shows as unavailable.
// The connection is sealed before it is stored. It is a policy action,
// audited; the password and the API key are never in the audit entry.
func (m *Manager) Add(ctx context.Context, actorID string, req AddRequest) (ControllerInfo, error) {
	name := strings.TrimSpace(req.Name)
	if !validName(name) {
		return ControllerInfo{}, ErrBadName
	}
	conn, err := Connection{
		URL: req.URL, Kind: req.Kind, Site: req.Site, APIKey: req.APIKey,
		Username: req.Username, Password: req.Password, Fingerprint: req.Fingerprint,
	}.normalize()
	if err != nil {
		return ControllerInfo{}, err
	}
	// The id is derived from the name, so two hubs adding the same name
	// make one controller.
	id := store.UniFiControllerID(name)
	now := m.now().UTC().Truncate(time.Millisecond)
	err = m.policy.Do(ctx, policy.Request{
		ActorKind: policy.ActorWeb, ActorID: actorID, Action: policy.UniFiControllerAdd, Target: name,
		Detail: map[string]any{
			"id": id, "url": conn.URL, "kind": conn.Kind, "site": conn.Site, "auth": conn.authMode(),
			"username": conn.Username, "tls": conn.tlsMode(),
		},
	}, func(ctx context.Context) error {
		existing, err := m.store.UniFiControllers().List(ctx)
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
		return m.store.UniFiControllers().Add(ctx, store.UniFiController{ID: id, Name: name, Sealed: sealed, CreatedAt: now})
	})
	if err != nil {
		return ControllerInfo{}, err
	}
	m.kickSync()
	info := infoOf(ControllerInfo{ID: id, Name: name, CreatedAt: now}, conn)
	info.State = StateConnecting
	return info, nil
}

// Remove forgets controller id and its credentials. It is a policy action,
// audited.
func (m *Manager) Remove(ctx context.Context, actorID, id string) error {
	target := id
	m.mu.Lock()
	if r, ok := m.controllers[id]; ok {
		target = r.info.Name
	}
	m.mu.Unlock()
	err := m.policy.Do(ctx, policy.Request{
		ActorKind: policy.ActorWeb, ActorID: actorID, Action: policy.UniFiControllerRemove, Target: target,
		Detail: map[string]any{"id": id},
	}, func(ctx context.Context) error {
		return m.store.UniFiControllers().Remove(ctx, id)
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
func (*Manager) Name() string { return store.SourceUniFi }

// Target implements discovery.Source.
func (*Manager) Target() string { return "unifi" }

// Idle implements discovery's idle source: with no controller read, an
// import has nothing to take from it.
func (m *Manager) Idle() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range m.controllers {
		if r.state == StateConnected {
			return false
		}
	}
	return true
}

// Records implements discovery.Source: the clients of every controller as
// the last read saw them, with no request to a controller. They are
// connected clients, not leases: each was seen when the controller last
// heard of it, and its name is the alias set in UniFi or the one it sent.
func (m *Manager) Records(context.Context) ([]discovery.Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []discovery.Record
	for _, r := range m.controllers {
		if r.state != StateConnected {
			continue
		}
		for _, c := range r.last.clients {
			if c.IP == "" {
				continue // no address to merge
			}
			seen := r.readAt
			if c.LastSeen > 0 {
				seen = time.Unix(c.LastSeen, 0)
			}
			out = append(out, discovery.Record{MAC: c.MAC, IP: c.IP, Hostname: c.Hostname, Vendor: c.Vendor, Seen: seen})
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
