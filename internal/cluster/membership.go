// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"maps"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/memberlist"

	"github.com/gvart/hearth/internal/pki"
)

// Member states, as `hearth cluster status` shows them.
const (
	MemberAlive   = "alive"
	MemberSuspect = "suspect"
	MemberDead    = "dead"
	MemberLeft    = "left"
)

const (
	defaultGossipRefresh = 10 * time.Second
	gossipLeaveTimeout   = 2 * time.Second
)

// MembershipConfig configures a Membership.
type MembershipConfig struct {
	// NodeID is this member's name in the gossip, its hub node ID.
	NodeID string
	// Roles are this host's roles and Allowed its --allow-roles; Roles must
	// lie within Allowed and include storage or master: node-only hosts do
	// not gossip.
	Roles, Allowed RoleSet
	// Listen is the cluster address, e.g. ":7444". Listener, if set, is
	// already bound to it; the membership closes it when it stops.
	Listen   string
	Listener net.Listener
	// Advertise is the host:port other members dial; empty means the
	// listener's address. A host name is resolved to an IP at start.
	Advertise string
	// Seeds returns gossip addresses (host:port) of other members to join.
	// Membership calls it at start and on every refresh, and joins those it
	// does not see alive, so members find each other again after a restart.
	Seeds func() []string
	// Schema returns this member's store schema version.
	Schema func(context.Context) (int64, error)
	// ConfigDigest returns a digest of this member's configuration.
	ConfigDigest func() string
	// Written, if set, returns the cluster's written schema as this member
	// knows it, gossiped with its metadata (apschema.go).
	Written func() int64
	// CheckSchema, if set, refuses a peer by the schema it supports: one
	// too old for the cluster's written schema.
	CheckSchema func(id string, supported int64) error
	// Log receives the membership's logs, memberlist's included.
	Log *slog.Logger

	// CA, Cert and Check authenticate peers: both ends present a hub node
	// certificate from CA (Cert returns this member's at each handshake),
	// and Check refuses a peer's, e.g. a revoked one.
	CA    *pki.CA
	Cert  func() *tls.Certificate
	Check func(*x509.Certificate) error

	// Tuning; zero values use memberlist's LAN defaults. Tests shorten them.
	ProbeInterval    time.Duration
	ProbeTimeout     time.Duration
	GossipInterval   time.Duration
	PushPullInterval time.Duration
	SuspicionMult    int
	TCPTimeout       time.Duration
	// RefreshEvery is how often the metadata is refreshed and the seeds
	// joined; zero means 10 s.
	RefreshEvery time.Duration

	// Replica, if set, serves the replication connections of a sharded
	// cluster that other members open on the gossip port, with the hub
	// node ID their certificate names. It owns the connection.
	Replica func(c net.Conn, peer string)
	// Master, if set, serves the connections other masters open for HTTP
	// between masters (masterlink.go), as Replica does.
	Master func(c net.Conn, peer string)
	// Message, if set, receives the messages other members Broadcast.
	Message func(b []byte)
	// Removed, if set, reports whether a member was removed from the
	// cluster for good (`hearth cluster remove`: every hub certificate of it
	// revoked). Removed members are left out of Members; Run checks the
	// members it knows every refresh.
	Removed func(id string) bool
}

// LocalState is what a member says of its roles on the gossip: its roles,
// and a role change under way.
type LocalState struct {
	Roles RoleSet
	// Syncing: promoted to storage, still copying its rows.
	Syncing bool
	// Draining: being demoted from storage, handing its rows off; Progress
	// is the share of its buckets handed off, in percent.
	Draining bool
	Progress int
}

// Membership is this host's place in the cluster's gossip membership
// (hashicorp/memberlist, SWIM) among storage and master members, over a
// mutual-TLS TCP transport (gossiptransport.go). Each member's metadata
// carries its roles, allowed roles, schema version, clock and config digest.
type Membership struct {
	cfg MembershipConfig
	log *slog.Logger

	// meta is this member's encoded metadata, which memberlist reads.
	meta  atomic.Pointer[[]byte]
	ml    atomic.Pointer[memberlist.Memberlist]
	trans atomic.Pointer[gossipTransport]
	// updateMu serializes UpdateNode: memberlist reads this member's own
	// node outside its lock there, so two calls at once race.
	updateMu sync.Mutex

	// mu guards live and gone, the members memberlist reported alive and
	// those it reported dead or left. They are copies made in memberlist's
	// event callbacks: the nodes memberlist.Members returns change under
	// its lock, so they cannot be read outside it.
	mu   sync.Mutex
	live map[string]liveMember
	gone map[string]MemberInfo
	// removed are the members removed from the cluster for good: never
	// listed, until one joins again with a valid certificate.
	removed map[string]bool
	// local is this member's roles and role change under way.
	local atomic.Pointer[LocalState]
	// ca is this member's side of a hub CA rotation (SetCA).
	ca atomic.Pointer[CAMeta]

	// broadcasts queues the messages Broadcast sends on the gossip.
	broadcasts *memberlist.TransmitLimitedQueue
	// changed is signalled whenever a member joins, leaves or changes.
	changeMu sync.Mutex
	changed  []chan struct{}
	// started is when Run started the gossip.
	started atomic.Pointer[time.Time]
	// schemaRefused are the peers already logged as refused for their
	// schema.
	schemaRefused sync.Map
	// refusedLogged is set once the refusal of this member's certificate
	// is logged, until a join succeeds again.
	refusedLogged atomic.Bool
}

// NewMembership checks cfg and returns a Membership; Run starts it.
func NewMembership(cfg MembershipConfig) (*Membership, error) {
	if err := ValidNodeID(cfg.NodeID); err != nil {
		return nil, err
	}
	if err := CheckCeiling(cfg.Roles, cfg.Allowed); err != nil {
		return nil, err
	}
	switch {
	case !cfg.Roles.Gossips():
		return nil, fmt.Errorf("membership: roles %s: only storage and master members gossip", cfg.Roles)
	case cfg.Listen == "" && cfg.Listener == nil:
		return nil, errors.New("membership: no listen address")
	case cfg.CA == nil || cfg.Cert == nil:
		return nil, errors.New("membership: no CA or certificate")
	}
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.DiscardHandler)
	}
	if cfg.RefreshEvery <= 0 {
		cfg.RefreshEvery = defaultGossipRefresh
	}
	m := &Membership{
		cfg: cfg, log: cfg.Log.With("component", "gossip"),
		live: map[string]liveMember{}, gone: map[string]MemberInfo{}, removed: map[string]bool{},
	}
	m.local.Store(&LocalState{Roles: cfg.Roles})
	m.broadcasts = &memberlist.TransmitLimitedQueue{
		NumNodes: func() int {
			m.mu.Lock()
			defer m.mu.Unlock()
			return max(len(m.live), 1)
		},
		RetransmitMult: 3,
	}
	return m, nil
}

// Changes returns a channel signalled (without blocking) whenever a member
// joins, leaves or updates its metadata, and a function that stops it.
func (m *Membership) Changes() (<-chan struct{}, func()) {
	ch := make(chan struct{}, 1)
	m.changeMu.Lock()
	m.changed = append(m.changed, ch)
	m.changeMu.Unlock()
	return ch, func() {
		m.changeMu.Lock()
		defer m.changeMu.Unlock()
		m.changed = slices.DeleteFunc(m.changed, func(c chan struct{}) bool { return c == ch })
	}
}

func (m *Membership) notifyChange() {
	m.changeMu.Lock()
	defer m.changeMu.Unlock()
	for _, ch := range m.changed {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

// Broadcast sends b to every member on the gossip, within a few gossip
// rounds, to be handed to their MembershipConfig.Message. b must fit in a
// gossip packet (about 1 KB).
func (m *Membership) Broadcast(b []byte) {
	m.broadcasts.QueueBroadcast(rawBroadcast(slices.Clone(b)))
}

// rawBroadcast is a message queued for the gossip.
type rawBroadcast []byte

func (b rawBroadcast) Invalidates(memberlist.Broadcast) bool { return false }
func (b rawBroadcast) Message() []byte                       { return b }
func (b rawBroadcast) Finished()                             {}

// LastContact is when this member last heard from any other member over
// the gossip port, or when its gossip started if it has heard from none
// since: zero before Run.
func (m *Membership) LastContact() time.Time {
	started := m.started.Load()
	t := m.trans.Load()
	if started == nil || t == nil {
		return time.Time{}
	}
	if last := t.latestSeen(m.cfg.NodeID); last.After(*started) {
		return last
	}
	return *started
}

// digestOf folds a hub's config digests (by item) into one.
func digestOf(digests map[string]string) string {
	if len(digests) == 0 {
		return ""
	}
	h := sha256.New()
	for _, k := range slices.Sorted(maps.Keys(digests)) {
		_, _ = fmt.Fprintf(h, "%s=%s\n", k, digests[k])
	}
	return hex.EncodeToString(h.Sum(nil))
}

// memberMeta is a member's gossip metadata. It must stay within
// memberlist.MetaMaxSize (512 bytes), hence the short keys.
type memberMeta struct {
	Roles   RoleSet `json:"r"`
	Allowed RoleSet `json:"a"`
	Schema  int64   `json:"s"`
	// Written is the cluster's written schema as the member knows it.
	Written int64 `json:"w,omitempty"`
	// Clock is the member's wall clock in Unix ms when it last refreshed
	// its metadata; a placeholder until the HLC lands (impl item 3).
	Clock  uint64 `json:"c"`
	Digest string `json:"d,omitempty"`
	// Leaving is set just before the member leaves, so the others show it
	// as left rather than dead.
	Leaving bool `json:"l,omitempty"`
	// Syncing: promoted to storage and still copying its rows.
	Syncing bool `json:"y,omitempty"`
	// Drain is 1 + the percentage handed off while a demotion from storage
	// drains the member; 0 when none is under way.
	Drain int `json:"dr,omitempty"`
	// CA is the member's side of a hub CA rotation.
	CA *CAMeta `json:"ca,omitempty"`
}

// CAMeta is a member's side of a hub CA rotation, as it says on the gossip
// (apcarotation.go): the CAs by the first 16 hex digits of their
// fingerprints (shortFP), whether it holds the next CA's key and a node
// certificate of it, and whether it cut over to it.
type CAMeta struct {
	Serving  string `json:"s"`
	Next     string `json:"n,omitempty"`
	NextKey  bool   `json:"k,omitempty"`
	NextCert bool   `json:"c,omitempty"`
	CutOver  bool   `json:"o,omitempty"`
}

func decodeMeta(b []byte) (memberMeta, error) {
	var m memberMeta
	if err := json.Unmarshal(b, &m); err != nil {
		return memberMeta{}, fmt.Errorf("member metadata: %w", err)
	}
	return m, nil
}

// localState is this member's state: its configured roles until SetLocal.
func (m *Membership) localState() LocalState {
	if ls := m.local.Load(); ls != nil {
		return *ls
	}
	return LocalState{Roles: m.cfg.Roles}
}

func (m *Membership) setMeta(ctx context.Context, leaving bool) error {
	ls := m.localState()
	meta := memberMeta{
		Roles: ls.Roles, Allowed: m.cfg.Allowed, Leaving: leaving,
		Clock: uint64(time.Now().UnixMilli()), Syncing: ls.Syncing,
	}
	if ls.Draining {
		meta.Drain = 1 + min(max(ls.Progress, 0), 100)
	}
	if m.cfg.Schema != nil {
		if v, err := m.cfg.Schema(ctx); err == nil {
			meta.Schema = v
		}
	}
	if m.cfg.ConfigDigest != nil {
		meta.Digest = m.cfg.ConfigDigest()
	}
	meta.CA = m.ca.Load()
	if m.cfg.Written != nil {
		meta.Written = m.cfg.Written()
	}
	b, err := json.Marshal(meta)
	if err != nil {
		return err
	}
	if len(b) > memberlist.MetaMaxSize {
		return fmt.Errorf("member metadata of %d bytes exceeds %d", len(b), memberlist.MetaMaxSize)
	}
	m.meta.Store(&b)
	return nil
}

// Run joins the gossip and keeps this member's metadata fresh until ctx
// ends; then it leaves the gossip and stops. It returns an error only if
// membership could not start.
func (m *Membership) Run(ctx context.Context) error {
	ml, err := m.start(ctx)
	if err != nil {
		return err
	}
	t := time.NewTicker(m.cfg.RefreshEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			m.leave()
			return nil
		case <-t.C:
			if err := m.setMeta(ctx, false); err != nil {
				m.log.WarnContext(ctx, "refresh member metadata", "err", err)
			} else if err := m.updateNode(ml, m.cfg.RefreshEvery); err != nil {
				m.log.DebugContext(ctx, "announce member metadata", "err", err)
			}
			m.joinSeeds(ctx)
			m.pruneRemoved()
		}
	}
}

// start starts the transport and memberlist and joins the seeds.
func (m *Membership) start(ctx context.Context) (*memberlist.Memberlist, error) {
	if err := m.setMeta(ctx, false); err != nil {
		return nil, fmt.Errorf("membership: %w", err)
	}
	dialTimeout := m.cfg.TCPTimeout
	if dialTimeout <= 0 {
		dialTimeout = memberlist.DefaultLANConfig().TCPTimeout
	}
	trans, err := newGossipTransport(ctx, m.cfg.Listener, m.cfg.Listen, m.cfg.Advertise, m.cfg.Cert, m.cfg.CA,
		peerCheck(m.cfg.Check), dialTimeout, m.log)
	if err != nil {
		return nil, fmt.Errorf("membership: %w", err)
	}
	if m.cfg.Replica != nil {
		trans.replica.Store(&m.cfg.Replica)
	}
	if m.cfg.Master != nil {
		trans.master.Store(&m.cfg.Master)
	}
	m.trans.Store(trans)
	ml, err := memberlist.Create(m.memberlistConfig(trans))
	if err != nil {
		_ = trans.Shutdown()
		return nil, fmt.Errorf("membership: %w", err)
	}
	m.ml.Store(ml)
	now := time.Now()
	m.started.Store(&now)
	m.log.InfoContext(ctx, "gossip membership started", "advertise", net.JoinHostPort(trans.ip.String(), strconv.Itoa(trans.port)),
		"roles", m.Local().Roles.String())
	m.joinSeeds(ctx)
	return ml, nil
}

func (m *Membership) memberlistConfig(trans *gossipTransport) *memberlist.Config {
	c := memberlist.DefaultLANConfig()
	c.Name = m.cfg.NodeID
	c.Transport = trans
	c.BindPort, c.AdvertisePort = trans.port, trans.port
	c.Delegate, c.Events, c.Alive, c.Merge = m, m, m, m
	c.Logger = log.New(memberlistLog{m.log}, "", 0)
	setIfNonZero(&c.ProbeInterval, m.cfg.ProbeInterval)
	setIfNonZero(&c.ProbeTimeout, m.cfg.ProbeTimeout)
	setIfNonZero(&c.GossipInterval, m.cfg.GossipInterval)
	setIfNonZero(&c.PushPullInterval, m.cfg.PushPullInterval)
	setIfNonZero(&c.SuspicionMult, m.cfg.SuspicionMult)
	setIfNonZero(&c.TCPTimeout, m.cfg.TCPTimeout)
	return c
}

// joinSeeds joins the seeds that are not live members yet.
func (m *Membership) joinSeeds(ctx context.Context) {
	ml := m.ml.Load()
	if ml == nil || m.cfg.Seeds == nil {
		return
	}
	known := map[string]bool{}
	m.mu.Lock()
	for _, l := range m.live {
		known[l.info.Address] = true
	}
	m.mu.Unlock()
	var todo []string
	for _, s := range m.cfg.Seeds() {
		if !known[s] && !m.isSelf(s) {
			todo = append(todo, s)
		}
	}
	if len(todo) == 0 {
		return
	}
	n, err := ml.Join(todo)
	if n > 0 {
		m.refusedLogged.Store(false)
		m.log.DebugContext(ctx, "joined gossip peers", "contacted", n)
		return
	}
	// A peer refuses this member's certificate in the handshake, which is
	// all a member removed while it was down hears of it.
	if err != nil && strings.Contains(err.Error(), "tls: bad certificate") && !m.refusedLogged.Swap(true) {
		m.log.ErrorContext(ctx, "the cluster's members refuse this hub's certificate: it was most likely removed "+
			"from the cluster (`hearth cluster remove`, or automatically after --member-dead-after). To bring it "+
			"back, stop it, wipe its data dir and join again with a new join token "+
			"(`hearth cluster token create` on a master, then `hearth hub --join`)", "seeds", todo)
	}
	m.log.DebugContext(ctx, "no gossip peer reachable yet", "seeds", todo, "err", err)
}

// isSelf reports whether a seed address is this member's.
func (m *Membership) isSelf(addr string) bool {
	t := m.trans.Load()
	host, port, err := net.SplitHostPort(addr)
	if t == nil || err != nil || port != strconv.Itoa(t.port) {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.Equal(t.ip)
}

// leave announces that this member leaves, leaves the gossip and stops.
func (m *Membership) leave() {
	ml := m.ml.Load()
	if err := m.setMeta(context.Background(), true); err == nil {
		_ = m.updateNode(ml, gossipLeaveTimeout)
	}
	if err := ml.Leave(gossipLeaveTimeout); err != nil {
		m.log.Debug("leave the gossip", "err", err)
	}
	if err := ml.Shutdown(); err != nil {
		m.log.Debug("stop the gossip", "err", err)
	}
}

// closeRevoked closes the open gossip connections of revoked peers.
func (m *Membership) closeRevoked(revoked func(*x509.Certificate) bool) int {
	if t := m.trans.Load(); t != nil {
		return t.closeRevoked(revoked)
	}
	return 0
}

// MemberInfo is one member as this host sees it.
type MemberInfo struct {
	ID           string  `json:"id"`
	Address      string  `json:"address"`
	Roles        RoleSet `json:"roles"`
	AllowedRoles RoleSet `json:"allowed_roles"`
	// State is alive, suspect, dead or left. A member is suspect while the
	// gossip holds it alive but nothing came from it directly for longer
	// than about two probe rounds.
	State  string `json:"state"`
	Schema int64  `json:"schema"`
	// Written is the cluster's written schema as the member knows it.
	Written      int64  `json:"written_schema,omitempty"`
	ClockMS      uint64 `json:"clock_ms,omitempty"`
	ConfigDigest string `json:"config_digest,omitempty"`
	// Syncing: promoted to storage, still copying its rows; it serves no
	// reads yet.
	Syncing bool `json:"syncing,omitempty"`
	// Draining: being demoted from storage, handing its rows off; Progress
	// is how far, in percent.
	Draining bool `json:"draining,omitempty"`
	Progress int  `json:"progress,omitempty"`
	// CA is the member's side of a hub CA rotation; nil if it says none.
	CA *CAMeta `json:"ca,omitempty"`
	// AutoRemoveAt is when a member down is removed automatically
	// (--member-dead-after), if it stays down; set by APNode.Status.
	AutoRemoveAt *time.Time `json:"auto_remove_at,omitempty"`
}

func memberInfo(n *memberlist.Node, state string) MemberInfo {
	mi := MemberInfo{ID: n.Name, Address: n.Address(), State: state}
	if meta, err := decodeMeta(n.Meta); err == nil {
		mi.Roles, mi.AllowedRoles, mi.Schema, mi.ClockMS, mi.ConfigDigest =
			meta.Roles, meta.Allowed, meta.Schema, meta.Clock, meta.Digest
		mi.Syncing, mi.CA, mi.Written = meta.Syncing, meta.CA, meta.Written
		if meta.Drain > 0 {
			mi.Draining, mi.Progress = true, meta.Drain-1
		}
	}
	return mi
}

// liveMember is a member memberlist holds alive, and when it was learnt of.
type liveMember struct {
	info   MemberInfo
	joined time.Time
}

// Members returns the members this host knows, itself included, by ID. It
// is empty before Run starts the gossip.
func (m *Membership) Members() []MemberInfo {
	t := m.trans.Load()
	if t == nil {
		return nil
	}
	probe := m.cfg.ProbeInterval
	if probe <= 0 {
		probe = memberlist.DefaultLANConfig().ProbeInterval
	}
	now := time.Now()
	m.mu.Lock()
	defer m.mu.Unlock()
	// Each member probes every other once per round of len(live) probe
	// intervals, so a live peer is heard from at least once a round.
	quiet := time.Duration(3*max(len(m.live), 2)) * probe
	out := make([]MemberInfo, 0, len(m.live)+len(m.gone))
	for id, l := range m.live {
		if m.removed[id] {
			continue
		}
		mi := l.info
		if id == m.cfg.NodeID {
			// This member's own state is the newest it set, whether or not
			// memberlist has passed it on yet.
			ls := m.localState()
			mi.Roles, mi.Syncing, mi.Draining, mi.Progress = ls.Roles, ls.Syncing, ls.Draining, 0
			if ls.Draining {
				mi.Progress = ls.Progress
			}
			mi.CA = m.ca.Load()
		} else {
			last := t.lastSeen(id)
			if l.joined.After(last) {
				last = l.joined
			}
			if now.Sub(last) > quiet {
				mi.State = MemberSuspect
			}
		}
		out = append(out, mi)
	}
	for id, g := range m.gone {
		if !m.removed[id] {
			out = append(out, g)
		}
	}
	slices.SortFunc(out, func(a, b MemberInfo) int { return strings.Compare(a.ID, b.ID) })
	return out
}

// Local returns what this member says of its roles.
func (m *Membership) Local() LocalState { return m.localState() }

// SetLocal changes what this member says of its roles, at once in Members
// and on the gossip within a round. The roles must lie within the host's
// allowed roles and include storage or master.
func (m *Membership) SetLocal(ls LocalState) error {
	if err := CheckCeiling(ls.Roles, m.cfg.Allowed); err != nil {
		return err
	}
	if !ls.Roles.Gossips() {
		return fmt.Errorf("membership: roles %s: only storage and master members gossip", ls.Roles)
	}
	m.local.Store(&ls)
	if err := m.setMeta(context.Background(), false); err != nil {
		return err
	}
	if ml := m.ml.Load(); ml != nil {
		if err := m.updateNode(ml, m.cfg.RefreshEvery); err != nil {
			m.log.Debug("announce member metadata", "err", err)
		}
	}
	m.notifyChange()
	return nil
}

// SetCA changes what this member says of its side of a hub CA rotation, at
// once in Members and on the gossip.
func (m *Membership) SetCA(c CAMeta) {
	if cur := m.ca.Load(); cur != nil && *cur == c {
		return
	}
	m.ca.Store(&c)
	if err := m.setMeta(context.Background(), false); err != nil {
		m.log.Warn("member metadata", "err", err)
		return
	}
	if ml := m.ml.Load(); ml != nil {
		if err := m.updateNode(ml, m.cfg.RefreshEvery); err != nil {
			m.log.Debug("announce member metadata", "err", err)
		}
	}
	m.notifyChange()
}

// PeerCerts returns the certificates member id presented on the open
// gossip connections this member dialed to it, as its certificate names it.
func (m *Membership) PeerCerts(id string) []*x509.Certificate {
	t := m.trans.Load()
	if t == nil {
		return nil
	}
	var out []*x509.Certificate
	for _, mi := range m.Members() {
		if mi.ID != id || mi.Address == "" {
			continue
		}
		for _, c := range t.stream.dialedPeers(mi.Address) {
			if peer, err := pki.HubNodeID(c); err == nil && peer == id {
				out = append(out, c)
			}
		}
	}
	return out
}

// Forget drops member id from Members for good: it was removed from the
// cluster. It is listed again only once it joins again with a certificate
// that is not revoked.
func (m *Membership) Forget(id string) {
	if id == "" || id == m.cfg.NodeID {
		return
	}
	m.mu.Lock()
	m.removed[id] = true
	delete(m.gone, id)
	m.mu.Unlock()
	m.notifyChange()
}

// pruneRemoved forgets the members Removed reports removed, and lists again
// those that joined back.
func (m *Membership) pruneRemoved() {
	if m.cfg.Removed == nil {
		return
	}
	m.mu.Lock()
	ids, live := map[string]bool{}, map[string]bool{}
	for id := range m.live {
		ids[id], live[id] = m.removed[id], true
	}
	for id := range m.gone {
		ids[id] = m.removed[id]
	}
	for id := range m.removed {
		ids[id] = true
	}
	m.mu.Unlock()
	changed := false
	for id, wasRemoved := range ids {
		if id == m.cfg.NodeID {
			continue
		}
		removed := m.cfg.Removed(id)
		// A member forgotten is listed again only once it gossips again
		// with a certificate that is not revoked: not while the revocation
		// is still on its way here.
		if removed == wasRemoved || (!removed && !live[id]) {
			continue
		}
		m.mu.Lock()
		if removed {
			m.removed[id] = true
			delete(m.gone, id)
		} else {
			delete(m.removed, id)
		}
		m.mu.Unlock()
		changed = true
	}
	if changed {
		m.notifyChange()
	}
}

// NodeMeta implements memberlist.Delegate.
func (m *Membership) NodeMeta(int) []byte {
	if b := m.meta.Load(); b != nil {
		return *b
	}
	return nil
}

// NotifyMsg implements memberlist.Delegate: a message another member
// Broadcast.
func (m *Membership) NotifyMsg(b []byte) {
	if m.cfg.Message != nil && len(b) > 0 {
		m.cfg.Message(slices.Clone(b))
	}
}

// GetBroadcasts implements memberlist.Delegate.
func (m *Membership) GetBroadcasts(overhead, limit int) [][]byte {
	return m.broadcasts.GetBroadcasts(overhead, limit)
}

// LocalState implements memberlist.Delegate.
func (m *Membership) LocalState(bool) []byte { return nil }

// MergeRemoteState implements memberlist.Delegate.
func (m *Membership) MergeRemoteState([]byte, bool) {}

// NotifyJoin implements memberlist.EventDelegate.
func (m *Membership) NotifyJoin(n *memberlist.Node) {
	m.mu.Lock()
	delete(m.gone, n.Name)
	m.live[n.Name] = liveMember{info: memberInfo(n, MemberAlive), joined: time.Now()}
	m.mu.Unlock()
	m.notifyChange()
	if n.Name != m.cfg.NodeID {
		m.log.Info("gossip member joined", "member", n.Name, "address", n.Address())
	}
}

// NotifyLeave implements memberlist.EventDelegate: the member failed, or
// left if its last metadata said it was leaving.
func (m *Membership) NotifyLeave(n *memberlist.Node) {
	state := MemberDead
	if meta, err := decodeMeta(n.Meta); err == nil && meta.Leaving {
		state = MemberLeft
	}
	m.mu.Lock()
	m.gone[n.Name] = memberInfo(n, state)
	delete(m.live, n.Name)
	m.mu.Unlock()
	m.notifyChange()
	m.log.Info("gossip member "+state, "member", n.Name, "address", n.Address())
}

// NotifyUpdate implements memberlist.EventDelegate: a member's metadata or
// address changed.
func (m *Membership) NotifyUpdate(n *memberlist.Node) {
	m.mu.Lock()
	if l, ok := m.live[n.Name]; ok {
		l.info = memberInfo(n, MemberAlive)
		m.live[n.Name] = l
	}
	m.mu.Unlock()
	m.notifyChange()
}

// NotifyAlive implements memberlist.AliveDelegate: it refuses a peer whose
// name is not a node ID, whose metadata claims a role outside its own
// allowed roles or no gossiping role, or whose name is not the hub that owns
// its address (see checkOwner).
//
// memberlist calls it under its node lock, so it never dials: an address
// whose owner is not known yet is refused and verified in the background,
// and a later alive message or push/pull about the member is accepted.
func (m *Membership) NotifyAlive(peer *memberlist.Node) error {
	if peer.Name == m.cfg.NodeID {
		return m.checkSelf(peer)
	}
	if err := ValidNodeID(peer.Name); err != nil {
		return err
	}
	meta, err := decodeMeta(peer.Meta)
	if err != nil {
		return fmt.Errorf("member %s: %w", peer.Name, err)
	}
	if err := CheckCeiling(meta.Roles, meta.Allowed); err != nil {
		return fmt.Errorf("member %s: %w", peer.Name, err)
	}
	if !meta.Roles.Gossips() {
		return fmt.Errorf("member %s: roles %s do not gossip", peer.Name, meta.Roles)
	}
	if m.cfg.CheckSchema != nil {
		if err := m.cfg.CheckSchema(peer.Name, meta.Schema); err != nil {
			if _, logged := m.schemaRefused.LoadOrStore(peer.Name, true); !logged {
				m.log.Error("refusing a member too old for the cluster", "err", err)
			}
			return err
		}
	}
	return m.checkOwner(peer, false)
}

// NotifyMerge implements memberlist.MergeDelegate, which memberlist calls,
// outside its locks, with the members a peer knows when it joins this one
// or this one joins it. It verifies the owner of each live member's address,
// dialing it if needed, and cancels the merge if any is claimed under a name
// that is not its owner's. An address that cannot be dialed is left to
// NotifyAlive, which refuses it until it is verified.
func (m *Membership) NotifyMerge(peers []*memberlist.Node) error {
	for _, p := range peers {
		if p.State != memberlist.StateAlive && p.State != memberlist.StateSuspect {
			continue
		}
		var err error
		if p.Name == m.cfg.NodeID {
			err = m.checkSelf(p)
		} else {
			err = m.checkOwner(p, true)
		}
		if errors.Is(err, errNameNotOwned) {
			return err
		}
	}
	return nil
}

// errNameNotOwned is a member claimed under a name that is not the name of
// the hub certificate presented at its address.
var errNameNotOwned = errors.New("member name is not its certificate's hub")

// checkOwner binds a member's name to its certificate: the hub that
// presented its certificate when this member dialed the peer's address must
// carry the peer's name. With dial unset an unknown owner is not dialed but
// verified in the background, and the peer is refused for now.
//
// This guarantees that a member is only added, or kept, under a name at an
// address where that hub answers. It does not authenticate who relayed the
// message: any hub of the cluster can gossip metadata, incarnations and
// suspect or dead claims about another; those are memberlist's to refute.
func (m *Membership) checkOwner(peer *memberlist.Node, dial bool) error {
	t := m.trans.Load()
	if t == nil {
		return errors.New("gossip transport not started")
	}
	addr := peer.Address()
	id, ok := t.ownerOf(addr)
	if !ok && !dial {
		t.verifyLater(addr)
		return fmt.Errorf("member %s: the hub at %s is not verified yet", peer.Name, addr)
	}
	if !ok {
		var err error
		if id, err = t.verifyOwner(addr); err != nil {
			return fmt.Errorf("member %s: verify the hub at %s: %w", peer.Name, addr, err)
		}
	}
	if id != peer.Name {
		return fmt.Errorf("member %s at %s: the hub there is %s: %w", peer.Name, addr, id, errNameNotOwned)
	}
	return nil
}

// checkSelf refuses a claim of this member's name at another address.
func (m *Membership) checkSelf(peer *memberlist.Node) error {
	t := m.trans.Load()
	if t == nil || (peer.Addr.Equal(t.ip) && int(peer.Port) == t.port) {
		return nil
	}
	return fmt.Errorf("member %s claimed at %s: %w", peer.Name, peer.Address(), errNameNotOwned)
}

// memberlistLog writes memberlist's "[LEVEL] memberlist: msg" lines to slog.
type memberlistLog struct{ log *slog.Logger }

func (w memberlistLog) Write(p []byte) (int, error) {
	msg := strings.TrimSpace(string(p))
	level := slog.LevelInfo
	for prefix, l := range map[string]slog.Level{
		"[DEBUG]": slog.LevelDebug, "[INFO]": slog.LevelInfo, "[WARN]": slog.LevelWarn, "[ERR]": slog.LevelError,
	} {
		if rest, ok := strings.CutPrefix(msg, prefix); ok {
			msg, level = strings.TrimSpace(rest), l
			break
		}
	}
	w.log.Log(context.Background(), level, strings.TrimPrefix(msg, "memberlist: "))
	return len(p), nil
}

// updateNode announces this member's metadata through ml (UpdateNode), one
// call at a time.
func (m *Membership) updateNode(ml *memberlist.Memberlist, timeout time.Duration) error {
	m.updateMu.Lock()
	defer m.updateMu.Unlock()
	return ml.UpdateNode(timeout)
}

// setIfNonZero sets *dst to v unless v is the zero value.
func setIfNonZero[T comparable](dst *T, v T) {
	var zero T
	if v != zero {
		*dst = v
	}
}
