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

// DefaultGossipPort is the default port of membership gossip. Raft keeps
// 7444 until it is removed (docs/impl/ap-cluster.md, item 8).
const DefaultGossipPort = "7445"

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
	// Listen is the gossip address, e.g. ":7445". Listener, if set, is
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
	// Log receives the membership's logs, memberlist's included.
	Log *slog.Logger

	// CA, Cert and Check authenticate peers: both ends present a hub node
	// certificate from CA (Cert returns this member's at each handshake),
	// and Check refuses a peer's, e.g. a revoked one. Node.NewMembership
	// sets them to the Raft transport's.
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
}

// Membership is this host's place in the cluster's gossip membership
// (hashicorp/memberlist, SWIM) among storage and master members, over a
// mutual-TLS TCP transport (gossiptransport.go). Each member's metadata
// carries its roles, allowed roles, schema version, clock and config digest.
// It runs alongside Raft and changes nothing about it.
type Membership struct {
	cfg MembershipConfig
	log *slog.Logger

	// meta is this member's encoded metadata, which memberlist reads.
	meta  atomic.Pointer[[]byte]
	ml    atomic.Pointer[memberlist.Memberlist]
	trans atomic.Pointer[gossipTransport]

	// mu guards live and gone, the members memberlist reported alive and
	// those it reported dead or left. They are copies made in memberlist's
	// event callbacks: the nodes memberlist.Members returns change under
	// its lock, so they cannot be read outside it.
	mu   sync.Mutex
	live map[string]liveMember
	gone map[string]MemberInfo
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
	return &Membership{
		cfg: cfg, log: cfg.Log.With("component", "gossip"),
		live: map[string]liveMember{}, gone: map[string]MemberInfo{},
	}, nil
}

// NewMembership returns the membership of this hub, authenticated like the
// Raft transport: it presents the node's current hub node certificate and
// refuses revoked hub certificates. Unset Schema, ConfigDigest and Seeds come
// from the node: its store's schema, its config digests (SetConfigSource)
// and the hosts of the Raft peers at this member's gossip port. Call it after
// Start; Status then lists the members.
func (n *Node) NewMembership(cfg MembershipConfig) (*Membership, error) {
	if n.stream == nil {
		return nil, errors.New("membership: node not started")
	}
	cfg.NodeID, cfg.CA, cfg.Cert, cfg.Check = n.cfg.NodeID, n.cfg.CA, n.stream.currentCert, n.refuseRevoked
	if cfg.Schema == nil {
		cfg.Schema = func(ctx context.Context) (int64, error) { return n.store.SchemaVersion(ctx) }
	}
	if cfg.ConfigDigest == nil {
		cfg.ConfigDigest = func() string { return digestOf(n.localDigests()) }
	}
	if cfg.Seeds == nil {
		cfg.Seeds = n.gossipSeeds(cfg.Listen, cfg.Advertise)
	}
	m, err := NewMembership(cfg)
	if err != nil {
		return nil, err
	}
	n.membership.Store(m)
	return m, nil
}

// gossipSeeds returns the Raft peers' hosts at this member's gossip port:
// until gossip and Raft share a port (item 8), every member is expected to
// gossip on the same port.
func (n *Node) gossipSeeds(listen, advertise string) func() []string {
	port := DefaultGossipPort
	for _, a := range []string{advertise, listen} {
		if _, p, err := net.SplitHostPort(a); err == nil && p != "" && p != "0" {
			port = p
			break
		}
	}
	return func() []string {
		st, err := n.Status()
		if err != nil {
			return nil
		}
		var out []string
		for _, p := range st.Peers {
			if p.ID == n.cfg.NodeID {
				continue
			}
			if host, _, err := net.SplitHostPort(p.Address); err == nil {
				out = append(out, net.JoinHostPort(host, port))
			}
		}
		return out
	}
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
	// Clock is the member's wall clock in Unix ms when it last refreshed
	// its metadata; a placeholder until the HLC lands (impl item 3).
	Clock  uint64 `json:"c"`
	Digest string `json:"d,omitempty"`
	// Leaving is set just before the member leaves, so the others show it
	// as left rather than dead.
	Leaving bool `json:"l,omitempty"`
}

func decodeMeta(b []byte) (memberMeta, error) {
	var m memberMeta
	if err := json.Unmarshal(b, &m); err != nil {
		return memberMeta{}, fmt.Errorf("member metadata: %w", err)
	}
	return m, nil
}

func (m *Membership) setMeta(ctx context.Context, leaving bool) error {
	meta := memberMeta{
		Roles: m.cfg.Roles, Allowed: m.cfg.Allowed, Leaving: leaving,
		Clock: uint64(time.Now().UnixMilli()), //nolint:gosec // after 1970
	}
	if m.cfg.Schema != nil {
		if v, err := m.cfg.Schema(ctx); err == nil {
			meta.Schema = v
		}
	}
	if m.cfg.ConfigDigest != nil {
		meta.Digest = m.cfg.ConfigDigest()
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
			} else if err := ml.UpdateNode(m.cfg.RefreshEvery); err != nil {
				m.log.DebugContext(ctx, "announce member metadata", "err", err)
			}
			m.joinSeeds(ctx)
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
	m.trans.Store(trans)
	ml, err := memberlist.Create(m.memberlistConfig(trans))
	if err != nil {
		_ = trans.Shutdown()
		return nil, fmt.Errorf("membership: %w", err)
	}
	m.ml.Store(ml)
	m.log.InfoContext(ctx, "gossip membership started", "advertise", net.JoinHostPort(trans.ip.String(), strconv.Itoa(trans.port)),
		"roles", m.cfg.Roles.String())
	m.joinSeeds(ctx)
	return ml, nil
}

func (m *Membership) memberlistConfig(trans *gossipTransport) *memberlist.Config {
	c := memberlist.DefaultLANConfig()
	c.Name = m.cfg.NodeID
	c.Transport = trans
	c.BindPort, c.AdvertisePort = trans.port, trans.port
	c.Delegate, c.Events, c.Alive = m, m, m
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
		m.log.DebugContext(ctx, "joined gossip peers", "contacted", n)
		return
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
		_ = ml.UpdateNode(gossipLeaveTimeout)
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
	State        string `json:"state"`
	Schema       int64  `json:"schema"`
	ClockMS      uint64 `json:"clock_ms,omitempty"`
	ConfigDigest string `json:"config_digest,omitempty"`
}

func memberInfo(n *memberlist.Node, state string) MemberInfo {
	mi := MemberInfo{ID: n.Name, Address: n.Address(), State: state}
	if meta, err := decodeMeta(n.Meta); err == nil {
		mi.Roles, mi.AllowedRoles, mi.Schema, mi.ClockMS, mi.ConfigDigest =
			meta.Roles, meta.Allowed, meta.Schema, meta.Clock, meta.Digest
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
		mi := l.info
		if id != m.cfg.NodeID {
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
	for _, g := range m.gone {
		out = append(out, g)
	}
	slices.SortFunc(out, func(a, b MemberInfo) int { return strings.Compare(a.ID, b.ID) })
	return out
}

// NodeMeta implements memberlist.Delegate.
func (m *Membership) NodeMeta(int) []byte {
	if b := m.meta.Load(); b != nil {
		return *b
	}
	return nil
}

// NotifyMsg implements memberlist.Delegate; members send no user messages.
func (m *Membership) NotifyMsg([]byte) {}

// GetBroadcasts implements memberlist.Delegate.
func (m *Membership) GetBroadcasts(int, int) [][]byte { return nil }

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
	m.log.Info("gossip member "+state, "member", n.Name, "address", n.Address())
}

// NotifyUpdate implements memberlist.EventDelegate: a member's metadata or
// address changed.
func (m *Membership) NotifyUpdate(n *memberlist.Node) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if l, ok := m.live[n.Name]; ok {
		l.info = memberInfo(n, MemberAlive)
		m.live[n.Name] = l
	}
}

// NotifyAlive implements memberlist.AliveDelegate: it refuses a peer whose
// name is not a node ID or whose metadata claims a role outside its own
// allowed roles, or no gossiping role.
func (m *Membership) NotifyAlive(peer *memberlist.Node) error {
	if peer.Name == m.cfg.NodeID {
		return nil
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
	return nil
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
