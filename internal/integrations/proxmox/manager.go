// SPDX-License-Identifier: AGPL-3.0-only

package proxmox

import (
	"cmp"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/gvart/hearth/internal/integrations/kubernetes"
	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

// SealInfo names the key that seals connections: it is theirs alone.
const SealInfo = "hearth proxmox connection seal v1"

// Server states.
const (
	StateConnecting  = "connecting"
	StateConnected   = "connected"
	StateUnavailable = "unavailable"
)

// Guest kinds, as the API paths name them.
const (
	KindVM  = "qemu"
	KindLXC = "lxc"
)

// Actions of Act.
const (
	ActionStart  = "start"
	ActionStop   = "stop"
	ActionReboot = "reboot"
)

const (
	// DefaultPollInterval is how often the hub reads each server.
	DefaultPollInterval = 15 * time.Second
	// DefaultSyncInterval is how often the manager rereads the server list
	// from the store, which picks up servers added or removed through
	// another hub of a Raft cluster.
	DefaultSyncInterval = 5 * time.Second
	maxNameLength       = 63
	// maxFieldLength caps a name or other text the server reports: Proxmox VE
	// keeps its own names far shorter.
	maxFieldLength = 255
)

// Errors of the manager's API.
var (
	ErrNotFound      = errors.New("no such proxmox server")
	ErrNameTaken     = errors.New("a proxmox server with that name exists")
	ErrBadName       = errors.New("server name must be 1 to 63 printable characters")
	ErrBadAction     = errors.New("invalid action: want start, stop or reboot")
	ErrGuestNotFound = errors.New("no such guest on this server")
	// ErrGuestChanged is returned when the VMID of an approved action now
	// names another guest.
	ErrGuestChanged = errors.New("the guest changed since the action was requested")
	// ErrUnavailable is returned for an action on a server the hub cannot
	// read at the moment.
	ErrUnavailable = errors.New("the proxmox server is unavailable")
)

// ServerInfo describes an adopted server and its connection. It never holds
// the token.
type ServerInfo struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	URL  string `json:"url"`
	// TLS is how the server's certificate is verified: system, ca or
	// fingerprint.
	TLS       string    `json:"tls"`
	State     string    `json:"state"`
	Error     string    `json:"error"`
	CreatedAt time.Time `json:"created_at"`
	Nodes     int       `json:"nodes"`
	Guests    int       `json:"guests"`
}

// Node is a Proxmox VE host.
type Node struct {
	Name string `json:"name"`
	// Status is online, offline or unknown.
	Status  string  `json:"status"`
	CPU     float64 `json:"cpu"`
	MaxCPU  int     `json:"max_cpu"`
	Mem     int64   `json:"mem"`
	MaxMem  int64   `json:"max_mem"`
	Disk    int64   `json:"disk"`
	MaxDisk int64   `json:"max_disk"`
	Uptime  int64   `json:"uptime"`
}

// Guest is a VM or an LXC container. Templates are left out: they cannot run.
type Guest struct {
	VMID int `json:"vmid"`
	// Kind is qemu or lxc.
	Kind string `json:"kind"`
	Name string `json:"name"`
	Node string `json:"node"`
	// Status is running, stopped, paused or unknown.
	Status string  `json:"status"`
	CPU    float64 `json:"cpu"`
	MaxCPU int     `json:"max_cpu"`
	Mem    int64   `json:"mem"`
	MaxMem int64   `json:"max_mem"`
	Uptime int64   `json:"uptime"`
}

// Storage is one storage as one node sees it.
type Storage struct {
	Name string `json:"name"`
	Node string `json:"node"`
	// Type is the storage plugin: dir, lvmthin, nfs, zfspool, ...
	Type    string `json:"type"`
	Status  string `json:"status"`
	Content string `json:"content"`
	Shared  bool   `json:"shared"`
	Used    int64  `json:"used"`
	Total   int64  `json:"total"`
}

// Snapshot is the current state of one server.
type Snapshot struct {
	Server  ServerInfo `json:"server"`
	Nodes   []Node     `json:"nodes"`
	Guests  []Guest    `json:"guests"`
	Storage []Storage  `json:"storage"`
	// ActionClasses is the policy class of each guest action.
	ActionClasses map[string]string `json:"action_classes"`
}

// AddRequest adopts a server.
type AddRequest struct {
	Name string `json:"name"`
	URL  string `json:"url"`
	// Token is the API token, USER@REALM!TOKENID=SECRET.
	Token string `json:"token"`
	// CAPEM and Fingerprint are the two ways to trust a self-signed
	// certificate; with neither, the system roots verify it.
	CAPEM       string `json:"ca_pem"`
	Fingerprint string `json:"fingerprint"`
}

// ActionRequest is an action on one guest. The hub finds the guest's node and
// kind itself: they are not the client's to say.
type ActionRequest struct {
	Action string `json:"action"`
	VMID   int    `json:"vmid"`
}

// ActionResult says what the server accepted. The action runs as a task on
// the server: its outcome shows in the guest's status.
type ActionResult struct {
	Action string `json:"action"`
	Class  string `json:"class"`
	Target string `json:"target"`
	Result string `json:"result"`
	// Task is the ID of the server's task.
	Task string `json:"task"`
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

// Manager adopts Proxmox VE servers. It keeps one poller per server stored in
// the hub, serves their state and carries out guest actions (see Act).
//
// Every hub of a Raft cluster reads every server itself: the state is a cache
// of the Proxmox API, never written to the store.
type Manager struct {
	store  *store.Store
	sealer *kubernetes.Sealer
	policy *policy.Engine
	log    *slog.Logger
	poll   time.Duration
	every  time.Duration
	// readTimeout bounds the read that confirms a guest before an action; a
	// poll gets as long, so a server that shows as connected can be acted on.
	readTimeout time.Duration
	now         func() time.Time
	kick        chan struct{}
	// toEntities is convert; tests replace it.
	toEntities func([]resource) ([]Node, []Guest, []Storage)

	mu      sync.Mutex
	servers map[string]*running
}

// running is one server the manager reads. Its fields after cancel are
// guarded by the manager's mu.
type running struct {
	info   ServerInfo // ID, Name, URL, TLS, CreatedAt
	client *client    // nil if the connection could not be used
	cancel context.CancelFunc
	done   chan struct{}
	// refresh asks the poller to read the server now.
	refresh chan struct{}

	state   string
	err     string
	nodes   []Node
	guests  []Guest
	storage []Storage
}

// NewManager returns a manager. Call Run to start reading servers; nothing
// connects before that.
func NewManager(cfg Config) *Manager {
	m := &Manager{
		store: cfg.Store, sealer: cfg.Sealer, policy: cfg.Policy, log: cfg.Log,
		poll: cfg.PollInterval, every: cfg.SyncInterval, now: cfg.Now,
		kick: make(chan struct{}, 1), servers: map[string]*running{}, toEntities: convert,
		readTimeout: requestTimeout,
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

// Run reads every stored server until ctx is done, rereading the list every
// SyncInterval and at once after a local Add or Remove. A server that cannot
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
	stored, err := m.store.ProxmoxServers().List(ctx)
	if err != nil {
		if ctx.Err() == nil {
			m.log.ErrorContext(ctx, "list proxmox servers", "err", err)
		}
		return
	}
	want := map[string]store.ProxmoxServer{}
	for _, s := range stored {
		want[s.ID] = s
	}
	m.mu.Lock()
	var stop []*running
	for id, r := range m.servers {
		if _, ok := want[id]; !ok {
			stop = append(stop, r)
			delete(m.servers, id)
		}
	}
	for id, s := range want {
		if _, ok := m.servers[id]; !ok {
			m.servers[id] = m.start(ctx, s)
		}
	}
	m.mu.Unlock()
	for _, r := range stop {
		r.stop()
		m.log.InfoContext(ctx, "stopped reading proxmox server", "server", r.info.Name)
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
func (m *Manager) start(ctx context.Context, s store.ProxmoxServer) *running {
	r := &running{
		info:    ServerInfo{ID: s.ID, Name: s.Name, CreatedAt: s.CreatedAt},
		state:   StateConnecting,
		done:    make(chan struct{}),
		refresh: make(chan struct{}, 1),
	}
	ctx, r.cancel = context.WithCancel(ctx)
	fail := func(msg string, err error) *running {
		m.log.ErrorContext(ctx, msg, "server", s.Name, "err", err)
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
	m.log.InfoContext(ctx, "reading proxmox server", "server", s.Name, "url", conn.URL)
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

// read polls the server once and publishes what it found.
func (m *Manager) read(ctx context.Context, r *running) {
	res, err := r.client.resources(ctx)
	if ctx.Err() != nil {
		return
	}
	var (
		nodes   []Node
		guests  []Guest
		storage []Storage
	)
	if err == nil {
		nodes, guests, storage = m.toEntities(res)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err != nil {
		if r.err != err.Error() {
			m.log.WarnContext(ctx, "proxmox server unavailable", "server", r.info.Name, "err", err)
		}
		// What was read before may no longer be true: show none of it.
		r.state, r.err = StateUnavailable, err.Error()
		r.nodes, r.guests, r.storage = nil, nil, nil
		return
	}
	if r.state != StateConnected {
		m.log.InfoContext(ctx, "proxmox server connected", "server", r.info.Name)
	}
	r.state, r.err = StateConnected, ""
	r.nodes, r.guests, r.storage = nodes, guests, storage
}

// convert sorts the API's resources into entities, leaving out templates and
// the kinds Hearth does not show (pools, SDN zones, ...).
func convert(res []resource) ([]Node, []Guest, []Storage) {
	nodes, guests, storage := []Node{}, []Guest{}, []Storage{}
	for _, e := range res {
		// Text this long is no real entry, and would end up in audit rows.
		if !fieldsFit(e.Node, e.Status, e.Name, e.Storage, e.PluginType, e.Content) {
			continue
		}
		switch e.Type {
		case "node":
			nodes = append(nodes, Node{
				Name: e.Node, Status: e.Status, CPU: float64(e.CPU), MaxCPU: int(e.MaxCPU),
				Mem: int64(e.Mem), MaxMem: int64(e.MaxMem), Disk: int64(e.Disk), MaxDisk: int64(e.MaxDisk),
				Uptime: int64(e.Uptime),
			})
		case KindVM, KindLXC:
			if e.Template != 0 {
				continue
			}
			guests = append(guests, Guest{
				VMID: int(e.VMID), Kind: e.Type, Name: e.Name, Node: e.Node, Status: e.Status,
				CPU: float64(e.CPU), MaxCPU: int(e.MaxCPU), Mem: int64(e.Mem), MaxMem: int64(e.MaxMem),
				Uptime: int64(e.Uptime),
			})
		case "storage":
			storage = append(storage, Storage{
				Name: e.Storage, Node: e.Node, Type: e.PluginType, Status: e.Status, Content: e.Content,
				Shared: e.Shared != 0, Used: int64(e.Disk), Total: int64(e.MaxDisk),
			})
		}
	}
	slices.SortFunc(nodes, func(a, b Node) int { return cmp.Compare(a.Name, b.Name) })
	slices.SortFunc(guests, func(a, b Guest) int { return cmp.Compare(a.VMID, b.VMID) })
	slices.SortFunc(storage, func(a, b Storage) int {
		return cmp.Or(cmp.Compare(a.Name, b.Name), cmp.Compare(a.Node, b.Node))
	})
	return nodes, guests, storage
}

// fieldsFit reports whether every field is within maxFieldLength.
func fieldsFit(fields ...string) bool {
	for _, f := range fields {
		if len(f) > maxFieldLength {
			return false
		}
	}
	return true
}

func (m *Manager) stopAll() {
	m.mu.Lock()
	all := m.servers
	m.servers = map[string]*running{}
	m.mu.Unlock()
	for _, r := range all {
		r.stop()
	}
}

// infoLocked fills r's state and counts. mu is held.
func infoLocked(r *running) ServerInfo {
	info := r.info
	info.State, info.Error = r.state, r.err
	info.Nodes, info.Guests = len(r.nodes), len(r.guests)
	return info
}

// Servers lists the servers this hub reads, by name.
func (m *Manager) Servers() []ServerInfo {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]ServerInfo, 0, len(m.servers))
	for _, r := range m.servers {
		out = append(out, infoLocked(r))
	}
	slices.SortFunc(out, func(a, b ServerInfo) int { return cmp.Compare(a.Name, b.Name) })
	return out
}

// Snapshot returns the current state of server id.
func (m *Manager) Snapshot(id string) (Snapshot, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.servers[id]
	if !ok {
		return Snapshot{}, ErrNotFound
	}
	s := Snapshot{
		Server:  infoLocked(r),
		Nodes:   slices.Clone(r.nodes),
		Guests:  slices.Clone(r.guests),
		Storage: slices.Clone(r.storage),
		ActionClasses: map[string]string{
			ActionStart: classOf(ActionStart), ActionStop: classOf(ActionStop), ActionReboot: classOf(ActionReboot),
		},
	}
	if s.Nodes == nil {
		s.Nodes = []Node{}
	}
	if s.Guests == nil {
		s.Guests = []Guest{}
	}
	if s.Storage == nil {
		s.Storage = []Storage{}
	}
	return s, nil
}

// policyAction is the policy action of a guest action; "" for an unknown one.
func policyAction(action string) policy.Action {
	switch action {
	case ActionStart:
		return policy.ProxmoxGuestStart
	case ActionStop:
		return policy.ProxmoxGuestStop
	case ActionReboot:
		return policy.ProxmoxGuestReboot
	}
	return ""
}

func classOf(action string) string {
	class, _ := policy.ClassOf(policyAction(action))
	return string(class)
}

// resolve finds the guest with vmid on server id, as the last read saw it.
func (m *Manager) resolve(id string, vmid int) (*running, Guest, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.servers[id]
	if !ok {
		return nil, Guest{}, ErrNotFound
	}
	if r.state != StateConnected || r.client == nil {
		return nil, Guest{}, ErrUnavailable
	}
	i := slices.IndexFunc(r.guests, func(g Guest) bool { return g.VMID == vmid })
	if i < 0 {
		return nil, Guest{}, ErrGuestNotFound
	}
	return r, r.guests[i], nil
}

// readGuest asks the server what guest vmid is right now. It fails with
// ErrUnavailable if the server does not answer within timeout, and with
// ErrGuestNotFound if there is no such guest.
func readGuest(ctx context.Context, c *client, vmid int, timeout time.Duration) (Guest, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	res, err := c.resources(ctx)
	if err != nil {
		return Guest{}, fmt.Errorf("%w: cannot confirm guest %d: %w", ErrUnavailable, vmid, err)
	}
	_, guests, _ := convert(res)
	i := slices.IndexFunc(guests, func(g Guest) bool { return g.VMID == vmid })
	if i < 0 {
		return Guest{}, ErrGuestNotFound
	}
	return guests[i], nil
}

// Act starts, stops or reboots a guest of server id on behalf of
// actorKind/actorID. Policy decides before anything is sent to the server,
// and audits the decision; an action it holds for approval is sent only once
// approved.
func (m *Manager) Act(ctx context.Context, actorKind, actorID, id string, req ActionRequest) (ActionResult, error) {
	action := policyAction(req.Action)
	if action == "" {
		return ActionResult{}, ErrBadAction
	}
	r, g, err := m.resolve(id, req.VMID)
	if err != nil {
		return ActionResult{}, err
	}
	target := fmt.Sprintf("%s/%s/%d", r.info.Name, g.Kind, g.VMID)
	detail := map[string]any{"server_id": id, "node": g.Node, "kind": g.Kind, "vmid": g.VMID, "name": g.Name}
	var task string
	err = m.policy.Do(ctx, policy.Request{
		ActorKind: actorKind, ActorID: actorID, Action: action, Target: target, Detail: detail,
	}, func(ctx context.Context) error {
		r, _, err := m.resolve(id, req.VMID)
		if err != nil {
			return err
		}
		// The last poll or an approval can be minutes old: the guest may have
		// moved or gone, and its VMID may now belong to another guest.
		now, err := readGuest(ctx, r.client, req.VMID, m.readTimeout)
		if err != nil {
			return err
		}
		if now.Kind != g.Kind || now.Name != g.Name {
			return fmt.Errorf("%w: VMID %d is now %s %q", ErrGuestChanged, now.VMID, now.Kind, now.Name)
		}
		if now.Node != g.Node {
			// A migration: the audit entry names the node actually used.
			detail["node"], detail["approved_node"] = now.Node, g.Node
		}
		task, err = r.client.guestAction(ctx, now, req.Action)
		return err
	})
	if err != nil {
		return ActionResult{}, fmt.Errorf("%s %s: %w", req.Action, target, err)
	}
	select {
	case r.refresh <- struct{}{}:
	default:
	}
	return ActionResult{
		Action: req.Action, Class: classOf(req.Action), Target: target, Task: task,
		Result: fmt.Sprintf("Proxmox accepted the %s of %s", req.Action, target),
	}, nil
}

// Add adopts a server on behalf of a web session from actorID, without
// connecting to it: one that cannot be reached yet shows as unavailable. The
// connection is sealed before it is stored. It is a policy action, audited.
func (m *Manager) Add(ctx context.Context, actorID string, req AddRequest) (ServerInfo, error) {
	name := strings.TrimSpace(req.Name)
	if !validName(name) {
		return ServerInfo{}, ErrBadName
	}
	conn, err := Connection{URL: req.URL, Token: req.Token, CAPEM: req.CAPEM, Fingerprint: req.Fingerprint}.normalize()
	if err != nil {
		return ServerInfo{}, err
	}
	id, err := newID()
	if err != nil {
		return ServerInfo{}, err
	}
	now := m.now().UTC().Truncate(time.Millisecond)
	err = m.policy.Do(ctx, policy.Request{
		ActorKind: policy.ActorWeb, ActorID: actorID, Action: policy.ProxmoxServerAdd, Target: name,
		Detail: map[string]any{"id": id, "url": conn.URL, "tls": conn.tlsMode()},
	}, func(ctx context.Context) error {
		existing, err := m.store.ProxmoxServers().List(ctx)
		if err != nil {
			return err
		}
		for _, s := range existing {
			if s.Name == name {
				return ErrNameTaken
			}
		}
		raw, err := json.Marshal(conn)
		if err != nil {
			return errors.New("encode connection")
		}
		sealed, err := m.sealer.Seal(id, raw)
		if err != nil {
			return err
		}
		return m.store.ProxmoxServers().Add(ctx, store.ProxmoxServer{ID: id, Name: name, Sealed: sealed, CreatedAt: now})
	})
	if err != nil {
		return ServerInfo{}, err
	}
	m.kickSync()
	return ServerInfo{ID: id, Name: name, URL: conn.URL, TLS: conn.tlsMode(), State: StateConnecting, CreatedAt: now}, nil
}

// Remove forgets server id and its token. It is a policy action, audited.
func (m *Manager) Remove(ctx context.Context, actorID, id string) error {
	target := id
	m.mu.Lock()
	if r, ok := m.servers[id]; ok {
		target = r.info.Name
	}
	m.mu.Unlock()
	err := m.policy.Do(ctx, policy.Request{
		ActorKind: policy.ActorWeb, ActorID: actorID, Action: policy.ProxmoxServerRemove, Target: target,
		Detail: map[string]any{"id": id},
	}, func(ctx context.Context) error {
		return m.store.ProxmoxServers().Remove(ctx, id)
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
		return "", fmt.Errorf("new server ID: %w", err)
	}
	return hex.EncodeToString(b), nil
}
