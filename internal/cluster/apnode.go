// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import (
	"cmp"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"connectrpc.com/connect"
	"golang.org/x/sync/errgroup"

	"github.com/gvart/hearth/internal/pki"
	"github.com/gvart/hearth/internal/policy"
	clusterv1 "github.com/gvart/hearth/internal/proto/hearth/cluster/v1"
	"github.com/gvart/hearth/internal/proto/hearth/cluster/v1/clusterv1connect"
	"github.com/gvart/hearth/internal/store"
)

// A hub in the cluster (docs/cluster.md). Its identity is a hub node
// certificate from the cluster CA, in DataDir/cluster, its membership is the
// gossip, and its store is sharded by the Replicator. A hub alone is a
// cluster of one, N = 1, not highly available.

// Files of a member, in DataDir/cluster.
const (
	// lastContactFile records when the member last reached the cluster.
	lastContactFile = "last-contact"
	// seedsFile keeps the gossip addresses this member learnt, so it finds
	// the cluster again after a restart.
	seedsFile = "gossip-seeds"
)

// APConfig configures an APNode.
type APConfig struct {
	DataDir string
	NodeID  string
	CA      *pki.CA
	// Allowed is the host's --allow-roles, the ceiling of its roles. The
	// roles themselves are recorded in the data dir (LoadLocalRoles).
	Allowed RoleSet
	// Listen, Listener and Advertise are the gossip address (see
	// MembershipConfig).
	Listen    string
	Listener  net.Listener
	Advertise string
	// Seeds are gossip addresses of other members to join.
	Seeds []string
	// Replicas is N (--replicas); zero means min(2, storage members).
	Replicas int
	// AgentURL is this hub's agent-facing URL (https://host:port), which
	// agents are sent to fail over to; empty if unknown.
	AgentURL string
	// ConfigSource, if set, reports this host's configuration digests
	// (HostFlagsSource), gossiped so members compare their host flags.
	ConfigSource ConfigSource
	Log          *slog.Logger
	// Tuning for tests; zero uses the defaults.
	Gossip ReplicatorConfig
	// RolesEvery is how often a drain or a catch-up after a promotion
	// runs a round; zero means 2 s.
	RolesEvery time.Duration
	// CAReconcileEvery is how often the member brings its CA to the hub CA
	// rotation's stage (apcarotation.go); zero means 10 s.
	CAReconcileEvery time.Duration
	// MemberDeadAfter is how long a member stays down before a master
	// removes it (deadmembers.go); zero never removes one.
	MemberDeadAfter time.Duration
	// deadEvery, in tests, is how often the members down are looked at;
	// zero means a minute.
	deadEvery time.Duration
	// tuneGossip, in tests, speeds the membership up.
	tuneGossip func(*MembershipConfig)
}

// APNode is a hub's place in an AP cluster.
type APNode struct {
	cfg APConfig
	log *slog.Logger
	// cert is the hub node certificate this member presents; a hub CA
	// rotation replaces it (apcarotation.go).
	cert atomic.Pointer[tls.Certificate]
	// epoch is the cluster epoch of this member's certificate (epoch.go):
	// a peer of another epoch is refused.
	epoch      string
	hints      *Hints
	rep        *Replicator
	membership *Membership
	st         *store.Store
	// schema computes the write schema and keeps the written one
	// (apschema.go).
	schema *schemaGate
	// masters is the ring over the live masters, link the HTTP between
	// them (masters.go, masterlink.go); both exist once Bind ran.
	masters  *MasterRing
	link     *MasterLink
	masterH  atomic.Pointer[http.Handler]
	isolated Isolation

	// rolesMu guards local, this member's roles and the change under way
	// (promote.go).
	rolesMu sync.Mutex
	local   LocalRoles
	// roles is local.Roles, read without rolesMu.
	roles atomic.Pointer[RoleSet]
	// roleSubs are told when this member gains or loses the master role.
	subsMu   sync.Mutex
	roleSubs []chan struct{}
	// rolesKick starts a drain or catch-up round at once.
	rolesKick chan struct{}
	// grants are the members this master is promoting to master, which may
	// fetch the CA key until then (apcakey.go).
	grantsMu sync.Mutex
	grants   map[string]time.Time
	// changeFn runs the CLI's role changes while this member is a master
	// (apcontrol.go).
	changeFn atomic.Pointer[RoleChangeFunc]

	// The hub CA rotation (apcarotation.go): this member's node
	// certificate of the next CA, the rotation as last read, the policy
	// engine and the re-sealer the master layer sets.
	nextCert atomic.Pointer[tls.Certificate]
	rot      atomic.Pointer[store.CARotation]
	caPolicy atomic.Pointer[policy.Engine]
	resealer atomic.Pointer[Resealer]
	// rotMu runs one rotation step (rotate, finish, abort, a drop) at a
	// time; recMu one reconcile.
	rotMu, recMu sync.Mutex
	caKick       chan struct{}
	// unpinnedClosed is the rotation whose unpinned connections were
	// closed; halted is set once a rotation finished without this member.
	unpinnedClosed atomic.Pointer[string]
	halted         atomic.Bool
	// down records the members down, to remove those down for
	// MemberDeadAfter (deadmembers.go); nil when none is removed.
	down *downTracker
}

// NewAPNode prepares this hub's AP membership: its node certificate
// (issued by the local CA when it has none), its hints and its replicator.
// Open the store with StoreOptions, then Bind it and Run.
func NewAPNode(ctx context.Context, cfg APConfig) (*APNode, error) {
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.DiscardHandler)
	}
	if err := ValidNodeID(cfg.NodeID); err != nil {
		return nil, err
	}
	dir := filepath.Join(cfg.DataDir, StateDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("ap node: %w", err)
	}
	// A finished rotation's node certificate move a crash interrupted.
	if err := recoverNodeCertFinish(dir, cfg.CA); err != nil {
		return nil, fmt.Errorf("ap node: node certificate: %w", err)
	}
	// A restored hub's first certificate is in the epoch its restore
	// started; a joined one's is in the epoch of the master it joined.
	epoch, err := readEpoch(cfg.DataDir)
	if err != nil {
		return nil, fmt.Errorf("ap node: %w", err)
	}
	cert, err := loadAPNodeCert(dir, cfg.CA, cfg.NodeID, epoch, time.Now())
	if err != nil {
		return nil, fmt.Errorf("ap node: node certificate: %w", err)
	}
	nextCert, err := readNextNodeCert(dir)
	if err != nil {
		return nil, fmt.Errorf("ap node: %w", err)
	}
	hints, err := OpenHints(ctx, filepath.Join(cfg.DataDir, HintsFile), 0)
	if err != nil {
		return nil, err
	}
	local, err := LoadLocalRoles(cfg.DataDir, cfg.Allowed, cfg.Log)
	if err != nil {
		_ = hints.Close()
		return nil, err
	}
	if cfg.RolesEvery <= 0 {
		cfg.RolesEvery = 2 * time.Second
	}
	if cfg.CAReconcileEvery <= 0 {
		cfg.CAReconcileEvery = 10 * time.Second
	}
	n := &APNode{
		cfg: cfg, log: cfg.Log.With("component", "ap-cluster"), epoch: pki.HubEpoch(cert.Leaf), hints: hints,
		local: local, rolesKick: make(chan struct{}, 1), caKick: make(chan struct{}, 1),
	}
	if cfg.MemberDeadAfter > 0 {
		if n.down, err = loadDownTracker(dir, cfg.NodeID, time.Now()); err != nil && n.down == nil {
			_ = hints.Close()
			return nil, fmt.Errorf("ap node: %w", err)
		} else if err != nil {
			n.log.WarnContext(ctx, "the record of the members down is unreadable", "err", err)
		}
	}
	n.cert.Store(&cert)
	if nextCert != nil {
		n.nextCert.Store(nextCert)
	}
	n.resumeCutover()
	n.schema = newSchemaGate(cfg.NodeID, filepath.Join(dir, schemaWrittenFile), apNodePeers{n}.Members,
		func() bool { return n.rep != nil && n.rep.seeking.Load() }, n.log)
	rc := cfg.Gossip
	rc.OnSynced = n.onSynced
	rc.NodeID, rc.Peers, rc.Replicas, rc.Hints, rc.Log = cfg.NodeID, apNodePeers{n}, cfg.Replicas, hints, cfg.Log
	rc.LastContact = filepath.Join(dir, lastContactFile)
	rc.Broadcast = func(b []byte) {
		if m := n.membership; m != nil {
			m.Broadcast(b)
		}
	}
	if n.rep, err = NewReplicator(rc); err != nil {
		_ = hints.Close()
		return nil, err
	}
	n.rep.SetLocal(local.Roles.Has(RoleStorage), local.Syncing)
	// A member with seeds has a cluster to find: no critical write until it
	// has (or starts alone, StartAlone).
	n.rep.SetSeeking(len(n.seeds()) > 0)
	n.setRoles(local.Roles)
	return n, nil
}

// apNodePeers reaches the members through the node's membership, once it
// exists.
type apNodePeers struct{ n *APNode }

func (p apNodePeers) Members() []MemberInfo {
	if p.n.membership == nil {
		return nil
	}
	return p.n.membership.Members()
}

func (p apNodePeers) DialReplica(ctx context.Context, id string) (net.Conn, error) {
	if p.n.membership == nil {
		return nil, errors.New("replica: membership not started")
	}
	return p.n.membership.DialReplica(ctx, id)
}

// StoreOptions are the options to open this hub's store with: sharded
// reads and replicated writes, stamped with this member's id.
func (n *APNode) StoreOptions() []store.Option {
	return []store.Option{
		store.WithShards(n.rep), store.WithApplier(n.rep.Bind), store.WithOrigin(n.cfg.NodeID),
		store.WithWriteSchema(n.schema.WriteSchema),
	}
}

// Bind checks the opened store (a member away longer than the tombstone
// window must rejoin empty, ErrRejoinEmpty) and starts the membership on
// it.
func (n *APNode) Bind(ctx context.Context, st *store.Store) error {
	has, err := hasRows(ctx, st)
	if err != nil {
		return err
	}
	if err := CheckRejoin(filepath.Join(n.cfg.DataDir, StateDir, lastContactFile), has, time.Now()); err != nil {
		return err
	}
	supported, err := st.SchemaVersion(ctx)
	if err != nil {
		return err
	}
	if h := n.schema.Written(); supported < h {
		return fmt.Errorf("this hub's store is at schema %d but the cluster has written %d: run the cluster's "+
			"hearth version or a newer one", supported, h)
	}
	n.schema.bind(supported)
	n.st = st
	// Before any peer is checked: during a rotation only pinned
	// certificates of the old CA pass.
	n.loadRotation(ctx)
	mc := MembershipConfig{
		NodeID: n.cfg.NodeID, Roles: n.local.Roles, Allowed: n.cfg.Allowed,
		Listen: n.cfg.Listen, Listener: n.cfg.Listener, Advertise: n.cfg.Advertise,
		Seeds: n.seeds,
		// The store's schema is fixed once it is open: gossip the one read
		// above rather than asking the database at every refresh, where a
		// failed read would leave the member saying none.
		Schema: func(context.Context) (int64, error) { return supported, nil },
		Log:    n.cfg.Log, CA: n.cfg.CA,
		Cert:        n.cert.Load,
		Check:       n.checkPeer,
		Replica:     n.rep.ServeConn,
		Master:      func(c net.Conn, peer string) { n.link.Accept(c, peer) },
		Message:     n.handleMessage,
		Removed:     n.removed,
		Written:     n.schema.Written,
		CheckSchema: n.schema.checkSchema,
	}
	if src := n.cfg.ConfigSource; src != nil {
		mc.ConfigDigest = func() string { return digestOf(src()) }
	}
	if n.cfg.tuneGossip != nil {
		n.cfg.tuneGossip(&mc)
	}
	m, err := NewMembership(mc)
	if err != nil {
		return err
	}
	if err := m.SetLocal(LocalState{Roles: n.local.Roles, Syncing: n.local.Syncing, Draining: n.local.Draining}); err != nil {
		return err
	}
	n.membership = m
	n.masters = NewMasterRing(n.cfg.NodeID, m.Members, time.Now)
	n.masters.SelfMaster(n.IsMaster)
	n.link = NewMasterLink(n.cfg.NodeID, m.DialMaster, m.Members, http.HandlerFunc(n.serveMaster), n.log)
	n.isolated = Isolation{
		LastContact: m.LastContact, Now: time.Now, Bound: IsolationBound,
		Others: func() bool {
			if len(n.seeds()) > 0 {
				return true
			}
			for _, mi := range m.Members() {
				if mi.ID != n.cfg.NodeID {
					return true
				}
			}
			return false
		},
	}
	return nil
}

// serveMaster serves another master's call: a role change (promote.go), or
// one for the handler SetMasterHandler set; none answers 503.
func (n *APNode) serveMaster(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == rolesPath {
		n.serveRoles(w, r)
		return
	}
	h := n.masterH.Load()
	if h == nil {
		http.Error(w, "this master serves no calls yet", http.StatusServiceUnavailable)
		return
	}
	(*h).ServeHTTP(w, r)
}

// SetMasterHandler sets the handler of the calls other masters make to this
// one (cluster.MasterPeer names the caller in its context).
func (n *APNode) SetMasterHandler(h http.Handler) {
	if h == nil {
		n.masterH.Store(nil)
		return
	}
	n.masterH.Store(&h)
}

// Masters returns the ring over the live masters (nil before Bind).
func (n *APNode) Masters() *MasterRing { return n.masters }

// MasterLink returns the HTTP link to the other masters (nil before Bind).
func (n *APNode) MasterLink() *MasterLink { return n.link }

// Isolated reports whether this master has reached no other member for
// IsolationBound though it knows of some: it then fails closed for
// dangerous actions and enrollments (docs/design/ap-cluster.md §5.4).
func (n *APNode) Isolated() bool {
	if n.membership == nil {
		return false
	}
	return n.isolated.Isolated()
}

// IsLeader reports whether this member is a master: in an AP cluster every
// master serves agents and enrollments (hub.Leadership).
func (n *APNode) IsLeader() bool { return n.IsMaster() }

// LeaderAgentURL is empty on a master: an AP cluster has no leader. A
// member that is no master names a live master, where its agents go
// (hub.Leadership).
func (n *APNode) LeaderAgentURL() string {
	if n.IsMaster() {
		return ""
	}
	if urls := n.AgentURLs(); len(urls) > 0 {
		return urls[0]
	}
	return ""
}

// AgentURLs are the agent-facing URLs of the live masters, this one first
// if it is one, as each recorded its own (Announce) (hub.Leadership).
func (n *APNode) AgentURLs() []string {
	if n.st == nil || n.masters == nil {
		return nil
	}
	urls, err := n.st.Hubs().AgentURLs(context.Background())
	if err != nil {
		n.log.Warn("read hub URLs", "err", err)
	}
	var out []string
	if n.cfg.AgentURL != "" && n.IsMaster() {
		out = append(out, n.cfg.AgentURL)
	}
	for _, id := range n.masters.Masters() {
		if u := urls[id]; id != n.cfg.NodeID && u != "" {
			out = append(out, u)
		}
	}
	return out
}

// AgentURLOf is the agent-facing URL master id recorded, or "".
func (n *APNode) AgentURLOf(ctx context.Context, id string) string {
	if id == n.cfg.NodeID {
		return n.cfg.AgentURL
	}
	urls, err := n.st.Hubs().AgentURLs(ctx)
	if err != nil {
		return ""
	}
	return urls[id]
}

// Announce records this hub's agent URL in the cluster, retrying until it
// is recorded or ctx ends.
func (n *APNode) Announce(ctx context.Context) {
	if n.cfg.AgentURL == "" {
		return
	}
	for {
		urls, err := n.st.Hubs().AgentURLs(ctx)
		if err == nil && urls[n.cfg.NodeID] == n.cfg.AgentURL {
			return
		}
		if err == nil {
			if err = n.st.Hubs().SetAgentURL(ctx, n.cfg.NodeID, n.cfg.AgentURL); err == nil {
				n.log.InfoContext(ctx, "recorded this hub's agent URL in the cluster", "agent_url", n.cfg.AgentURL)
				return
			}
		}
		n.log.WarnContext(ctx, "cannot record this hub's agent URL yet; retrying", "err", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(announceRetry):
		}
	}
}

// hasRows reports whether st holds any replicated row.
func hasRows(ctx context.Context, st *store.Store) (bool, error) {
	here, err := st.TablesHere(ctx)
	if err != nil {
		return false, err
	}
	for _, t := range here {
		// t is a table name of the store's own list.
		rows, err := st.ReadLocal(ctx, `SELECT 1 FROM `+t+` LIMIT 1`, nil)
		if err != nil {
			return false, err
		}
		if len(rows.Vals) > 0 {
			return true, nil
		}
	}
	return false, nil
}

// Epoch is this member's cluster epoch; empty for a cluster never restored
// from a backup.
func (n *APNode) Epoch() string { return n.epoch }

// checkPeer refuses a hub certificate of another cluster epoch, a revoked
// one and, during a hub CA rotation, an old-CA one other than the one
// pinned for its hub.
func (n *APNode) checkPeer(cert *x509.Certificate) error {
	if pki.HubEpoch(cert) != n.epoch {
		return errOtherEpoch
	}
	if err := n.checkRotationPin(cert); err != nil {
		return err
	}
	if n.st == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := n.st.Hubs().CheckCert(ctx, pki.SerialString(cert))
	if err != nil && !errors.Is(err, store.ErrCertRevoked) {
		n.log.Warn("cannot check a peer's hub certificate for revocation; accepting it", "err", err)
		return nil
	}
	return err
}

// seeds are the configured seeds and the members learnt before.
func (n *APNode) seeds() []string {
	out := slices.Clone(n.cfg.Seeds)
	if b, err := os.ReadFile(filepath.Join(n.cfg.DataDir, StateDir, seedsFile)); err == nil {
		out = append(out, strings.Fields(string(b))...)
	}
	if m := n.membership; m != nil {
		var learnt []string
		for _, mi := range m.Members() {
			if mi.ID != n.cfg.NodeID && mi.State != MemberLeft && mi.Address != "" {
				learnt = append(learnt, mi.Address)
			}
		}
		if len(learnt) > 0 {
			slices.Sort(learnt)
			_ = os.WriteFile(filepath.Join(n.cfg.DataDir, StateDir, seedsFile), []byte(strings.Join(learnt, "\n")+"\n"), 0o600)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// WaitPeers waits, up to limit, until the gossip has found another member,
// when this member has seeds to find them by: a hub that wrote before then
// would see a ring of one and keep its writes alone.
func (n *APNode) WaitPeers(ctx context.Context, limit time.Duration) error {
	if len(n.seeds()) == 0 {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	for {
		for _, m := range n.membership.Members() {
			if m.ID != n.cfg.NodeID && m.State == MemberAlive {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("no other member found: %w", ctx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// StartAlone lets a member that found none of the cluster its seeds name
// (WaitPeers gave up) take critical writes alone, on a ring of itself:
// until another member turns up, each has one copy.
func (n *APNode) StartAlone() { n.rep.SetSeeking(false) }

// Replicator returns the node's replicator.
func (n *APNode) Replicator() *Replicator { return n.rep }

// Membership returns the node's membership (nil before Bind).
func (n *APNode) Membership() *Membership { return n.membership }

// ID is this member's id.
func (n *APNode) ID() string { return n.cfg.NodeID }

// Run runs the membership and the replicator until ctx ends.
func (n *APNode) Run(ctx context.Context) error {
	if n.membership == nil {
		return errors.New("ap node: not bound to a store")
	}
	defer func() { _ = n.hints.Close() }()
	g, gctx := errgroup.WithContext(ctx)
	g.Go(func() error { return n.membership.Run(gctx) })
	g.Go(func() error { return n.rep.Run(gctx) })
	g.Go(func() error { return n.link.Run(gctx) })
	g.Go(func() error {
		changes, stop := n.membership.Changes()
		defer stop()
		n.masters.Run(gctx, changes)
		return nil
	})
	g.Go(func() error { n.runRoles(gctx); return nil })
	g.Go(func() error { n.runCA(gctx); return nil })
	if n.down != nil {
		g.Go(func() error {
			changes, stop := n.membership.Changes()
			defer stop()
			n.runDownTracker(gctx, changes)
			return nil
		})
	}
	g.Go(func() error {
		changes, stop := n.membership.Changes()
		defer stop()
		n.runSchemaGate(gctx, changes)
		return nil
	})
	return g.Wait()
}

// RecordNodeCert records this hub's node certificate in the hub
// certificates, so removing the hub can revoke it.
func (n *APNode) RecordNodeCert(ctx context.Context) error {
	cert := n.cert.Load()
	leaf := cert.Leaf
	if leaf == nil {
		var err error
		if leaf, err = x509.ParseCertificate(cert.Certificate[0]); err != nil {
			return err
		}
	}
	return n.st.Hubs().Record(ctx, store.HubCert{
		Serial: pki.SerialString(leaf), NodeID: n.cfg.NodeID,
		Fingerprint: pki.FingerprintHex(leaf), CAFP: pki.FingerprintHex(n.cfg.CA.Cert()),
	})
}

// Status is this member's view of the AP cluster.
func (n *APNode) Status() Status {
	st := Status{NodeID: n.cfg.NodeID}
	if n.membership != nil {
		st.Members = n.membership.Members()
	}
	for id, at := range n.autoRemoveAt(st.Members) {
		for i := range st.Members {
			if st.Members[i].ID == id {
				st.Members[i].AutoRemoveAt = &at
			}
		}
	}
	storage := 0
	for _, m := range st.Members {
		if m.Roles.Has(RoleStorage) && m.State != MemberLeft {
			storage++
		}
	}
	st.StorageMembers = max(storage, 1)
	st.Replicas = n.rep.N()
	st.HighlyAvailable = st.StorageMembers >= 2 && st.Replicas >= 2
	return st
}

// ServeAPControl serves the control socket of an AP member (the CLI's
// writes and `hearth cluster status`) until ctx ends.
func ServeAPControl(ctx context.Context, dataDir string, n *APNode, log *slog.Logger) error {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/status", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, n.StatusWithSafeStop(r.Context()))
	})
	mux.HandleFunc("POST /v1/change", n.serveRoleChange)
	mux.HandleFunc("POST /v1/ca/change", n.serveCAChange)
	mux.HandleFunc("GET /v1/ca/status", n.serveCAStatus)
	mux.HandleFunc("POST /v1/snapshot", n.serveSnapshot)
	mux.HandleFunc("POST /v1/apply", func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(io.LimitReader(r.Body, maxCommandSize))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		cmd, err := store.DecodeCommand(b)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if isRotationCommand(cmd) || cmd.Op() == (store.RevokeCACerts{}).Op() {
			// Only the rotation, on a master, writes these.
			writeJSON(w, applyReply{Error: toWireError(errRotationViaLog)})
			return
		}
		res, err := n.rep.Apply(r.Context(), cmd)
		out := applyReply{Result: res}
		if err != nil {
			out.Error = toWireError(err)
			if out.Error.Kind == "" {
				log.WarnContext(r.Context(), "control apply failed", "op", cmd.Op(), "err", err)
			}
		}
		writeJSON(w, out)
	})
	return serveControlHandler(ctx, dataDir, mux)
}

// serveControlHandler serves h on the control socket of dataDir until ctx
// ends, as ServeControl does.
func serveControlHandler(ctx context.Context, dataDir string, h http.Handler) error {
	path, ownDir := controlSocketPath(dataDir)
	if ownDir {
		if err := privateSocketDir(filepath.Dir(path)); err != nil {
			return fmt.Errorf("control socket: %w", err)
		}
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("control socket: %w", err)
	}
	ln, err := listenPrivate(ctx, path)
	if err != nil {
		return fmt.Errorf("control socket: %w", err)
	}
	defer func() { _ = os.Remove(path) }()
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second}
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	select {
	case err := <-errc:
		return fmt.Errorf("control socket: %w", err)
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)
	if err := <-errc; err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("control socket: %w", err)
	}
	return nil
}

// APJoinServer serves ClusterService on a master: Join admits a new hub with
// a join token (the hub gets its node certificate and the CA, and joins the
// gossip on its own), and FetchCAKey hands members the CA key and node
// certificates (apcakey.go).
type APJoinServer struct {
	clusterv1connect.UnimplementedClusterServiceHandler
	node   *APNode
	store  *store.Store
	ca     *pki.CA
	policy *policy.Engine
	log    *slog.Logger
	now    func() time.Time
	// fetchRefused rate-limits the audit entries of refused FetchCAKey calls.
	fetchRefused fetchRefusals
}

// NewAPJoinServer returns the join service of node.
func NewAPJoinServer(node *APNode, st *store.Store, ca *pki.CA, pol *policy.Engine, log *slog.Logger) *APJoinServer {
	return &APJoinServer{node: node, store: st, ca: ca, policy: pol, log: log, now: time.Now}
}

// Handler returns the service's path prefix and HTTP handler, for the hub's
// TLS listener only: FetchCAKey authenticates callers by their client
// certificate.
func (s *APJoinServer) Handler() (string, http.Handler) {
	path, h := clusterv1connect.NewClusterServiceHandler(s)
	return path, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), tlsStateKey{}, r.TLS)))
	})
}

// Join admits a new hub into the AP cluster.
func (s *APJoinServer) Join(ctx context.Context, req *connect.Request[clusterv1.JoinRequest]) (*connect.Response[clusterv1.JoinResponse], error) {
	msg := req.Msg
	if msg.GetTokenSecret() == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("join token is required"))
	}
	if err := ValidNodeID(msg.GetNodeId()); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	allowed, err := ParseRoles(strings.Join(msg.GetAllowedRoles(), ","))
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("allowed_roles: %w", err))
	}
	var (
		cert    *x509.Certificate
		granted RoleSet
		refused string
	)
	// The outcome entry shows the token's roles and the roles granted: fn
	// adds them.
	detail := map[string]any{
		"address": msg.GetAddress(), "schema_version": msg.GetSchemaVersion(), "allowed_roles": allowed.String(),
	}
	err = s.policy.Do(ctx, policy.Request{
		ActorKind: policy.ActorJoinToken,
		ActorID:   tokenActorID(msg.GetTokenSecret()),
		Action:    policy.ClusterJoin,
		Target:    msg.GetNodeId(),
		Detail:    detail,
	}, func(ctx context.Context) error {
		// A joiner needs the schema the cluster has written, not this
		// master's: during a rolling upgrade an older binary still joins.
		if have := s.node.WrittenSchema(); msg.GetSchemaVersion() < have {
			refused = fmt.Sprintf("this hub's binary supports store schema up to %d but the cluster has written %d; "+
				"run the cluster's hearth version or a newer one", msg.GetSchemaVersion(), have)
			return fmt.Errorf("%w: joining binary supports %d, cluster wrote %d", errSchema, msg.GetSchemaVersion(), have)
		}
		for _, m := range s.node.Status().Members {
			if m.ID == msg.GetNodeId() && m.State != MemberLeft {
				return errNodeTaken
			}
		}
		// Every member takes part in a rotation from its start: a hub that
		// joined during one would hold only the old CA.
		if s.node.rotationActive() {
			return store.ErrCARotationActive
		}
		now := s.now()
		// In this member's epoch: the joiner records it (Join).
		c, err := s.ca.SignHubCSRInEpoch(msg.GetCsr(), msg.GetNodeId(), s.node.epoch, now)
		if err != nil {
			return fmt.Errorf("%w: %w", errBadCSR, err)
		}
		tokenRoles, err := s.store.JoinTokens().Consume(ctx, msg.GetTokenSecret(), now)
		if err != nil {
			return err
		}
		granted = joinGrant(tokenRoles, allowed)
		detail["token_roles"], detail["granted_roles"] = cmp.Or(tokenRoles, "none"), granted.String()
		if !granted.Gossips() {
			refused = fmt.Sprintf("the join token grants %s and this host allows %s (--allow-roles): "+
				"no role left to join with", cmp.Or(tokenRoles, "none"), allowed)
			return fmt.Errorf("%w: token grants %s, host allows %s", errNoRole, cmp.Or(tokenRoles, "none"), allowed)
		}
		if err := s.store.Hubs().Record(ctx, store.HubCert{
			Serial: pki.SerialString(c), NodeID: msg.GetNodeId(),
			Fingerprint: pki.FingerprintHex(c), CAFP: pki.FingerprintHex(s.ca.Cert()),
		}); err != nil {
			return err
		}
		cert = c
		return nil
	})
	if err != nil {
		if refused != "" {
			return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New(refused))
		}
		return nil, s.toConnectError(ctx, err)
	}
	// The CA key goes to masters only (docs/design/ap-cluster.md §9): a hub
	// is granted the master role only when both the join token and its host
	// allow it.
	var keyDER []byte
	if granted.Has(RoleMaster) {
		if keyDER, err = s.ca.KeyDER(); err != nil {
			return nil, connect.NewError(connect.CodeInternal, errors.New("join failed"))
		}
	}
	s.log.InfoContext(ctx, "hub joined the AP cluster", "joined_id", msg.GetNodeId(), "roles", granted.String(),
		"ca_key_sent", keyDER != nil)
	return connect.NewResponse(&clusterv1.JoinResponse{
		Certificate: cert.Raw, CaCertificate: s.ca.Cert().Raw, CaKey: keyDER, Roles: granted.Strings(),
	}), nil
}

// joinGrant is the roles a joining hub is granted: those of tokenRoles, the
// join token's (comma-separated), that its host allows, storage and master
// only. A token whose roles do not parse grants none.
func joinGrant(tokenRoles string, allowed RoleSet) RoleSet {
	tok, err := ParseRoles(tokenRoles)
	if err != nil {
		return 0
	}
	return tok & allowed & HubRoles
}

func (s *APJoinServer) toConnectError(ctx context.Context, err error) error {
	switch {
	case errors.Is(err, errBadCSR):
		return connect.NewError(connect.CodeInvalidArgument, err)
	case errors.Is(err, errNodeTaken):
		return connect.NewError(connect.CodeAlreadyExists, err)
	case errors.Is(err, store.ErrCARotationActive):
		return connect.NewError(connect.CodeFailedPrecondition, errors.New("a hub CA rotation is under way: "+
			"no hub joins until it is finished or aborted (`hearth cluster ca finish|abort`)"))
	case errors.Is(err, store.ErrNotFound):
		return connect.NewError(connect.CodeUnauthenticated, errors.New("unknown join token"))
	case errors.Is(err, store.ErrTokenUsed):
		return connect.NewError(connect.CodeUnauthenticated, errors.New("join token already used"))
	case errors.Is(err, store.ErrTokenExpired):
		return connect.NewError(connect.CodeUnauthenticated, errors.New("join token expired"))
	case errors.Is(err, store.ErrNotOwner):
		owner := store.OwnerOf(err)
		msg := "this join token belongs to hub " + owner + ": join through it"
		if u := s.node.AgentURLOf(ctx, owner); u != "" {
			msg += " (--join " + u + ")"
		}
		return connect.NewError(connect.CodeFailedPrecondition, errors.New(msg))
	case errors.Is(err, policy.ErrDenied) && strings.Contains(err.Error(), policy.ErrIsolated):
		return connect.NewError(connect.CodeUnavailable, errors.New(policy.ErrIsolated))
	case errors.Is(err, store.ErrUnavailable):
		return connect.NewError(connect.CodeUnavailable, errors.New("join: the cluster is unavailable; try again"))
	case errors.Is(err, policy.ErrDenied):
		return connect.NewError(connect.CodePermissionDenied, errors.New("join denied by policy"))
	default:
		s.log.ErrorContext(ctx, "cluster join failed", "err", err)
		return connect.NewError(connect.CodeInternal, errors.New("join failed"))
	}
}

// Self is this member's id (hub.Masters).
func (n *APNode) Self() string { return n.cfg.NodeID }

// Live reports whether master id is alive (hub.Masters).
func (n *APNode) Live(id string) bool { return n.masters != nil && n.masters.Live(id) }

// Client sends HTTP requests to http://<master id>/ over the masters' link
// (hub.Masters).
func (n *APNode) Client() *http.Client { return n.link.Client() }

// OwnerOf is the master owning key on the ring of live masters
// (hub.Masters).
func (n *APNode) OwnerOf(key string) string { return n.masters.Owner(key) }
