// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/raft"
	raftboltdb "github.com/hashicorp/raft-boltdb/v2"

	"github.com/gvart/hearth/internal/pki"
	"github.com/gvart/hearth/internal/store"
)

// Files and directories inside a hub data dir.
const (
	// RaftDir holds every piece of cluster state. Its presence makes a data
	// dir a cluster member.
	RaftDir      = "raft"
	boltFile     = "raft.db"
	nodeIDFile   = "node-id"
	joinURLFile  = "join-url"
	nodeCertFile = "node.crt"
	nodeKeyFile  = "node.key"
)

// Defaults.
const (
	// DefaultRaftPort is the default port of the Raft transport.
	DefaultRaftPort = "7444"
	applyTimeout    = 10 * time.Second
	snapshotsRetain = 2
	maxPool         = 3
	dialTimeout     = 10 * time.Second
)

// IsMember reports whether dataDir belongs to a cluster member, that is,
// whether it holds Raft state. A hub that never joined or formed a cluster
// has none and runs exactly as a standalone hub.
func IsMember(dataDir string) bool {
	info, err := os.Stat(filepath.Join(dataDir, RaftDir))
	return err == nil && info.IsDir()
}

// Config configures a Node.
type Config struct {
	// DataDir is the hub data dir; Raft state lives in DataDir/raft.
	DataDir string
	// NodeID is this hub's Raft server ID (see NodeID).
	NodeID string
	// Listen is the address the Raft transport listens on, e.g. ":7444".
	Listen string
	// Listener, if set, is the transport's listener, already bound to
	// Listen; the node closes it on shutdown. Tests bind port 0 and pass
	// it, so no other process can take the port before the node starts.
	Listener net.Listener
	// Advertise is the host:port other hubs dial to reach this one; empty
	// means the listener's own address (only useful on loopback, in tests).
	Advertise string
	// CA is the hub CA. Peers must present certificates it issued.
	CA *pki.CA
	// Bootstrap forms a new one-voter cluster from the current store when
	// DataDir holds no Raft state yet. A joining hub leaves it false and
	// waits for the leader to add it.
	Bootstrap bool
	// Log receives the node's logs, raft's included.
	Log *slog.Logger
	// OnFatal is called once, without blocking, when this node fails to
	// apply a committed entry for a reason other than the command's own
	// outcome (I/O, a full disk), or to restore a snapshot. The node stops
	// applying entries; the caller must shut the hub down. After a restart
	// the node restores its latest snapshot and replays the log, so nothing
	// is lost or skipped.
	OnFatal func(error)
	// AgentURL is this hub's agent-facing URL (https://host:port), which
	// Announce records in the replicated store. Agents are sent it to fail
	// over to, and followers forward writes to the leader's.
	AgentURL string
	// AgentPort is the fallback for a hub whose agent URL is not recorded
	// yet: https://<its raft host>:AgentPort. Empty means no fallback.
	AgentPort string
	// ForwardWait bounds how long ApplyOrForward waits for a reachable
	// leader; zero means 5 s.
	ForwardWait time.Duration

	// Tuning; zero values use raft's defaults. Tests shorten them.
	HeartbeatTimeout   time.Duration
	ElectionTimeout    time.Duration
	LeaderLeaseTimeout time.Duration
	SnapshotInterval   time.Duration
	SnapshotThreshold  uint64
	TrailingLogs       uint64
}

// Node is one hub's Raft replica. It is the store's Applier (see Bind).
type Node struct {
	cfg   Config
	dir   string
	log   *slog.Logger
	store *store.Store

	raft  *raft.Raft
	trans *raft.NetworkTransport
	bolt  *raftboltdb.BoltStore
	fsm   *fsm
	// fwdHTTP forwards writes to the leader with this hub's node certificate.
	fwdHTTP *http.Client

	obsCh   chan raft.Observation
	obs     *raft.Observer
	stopObs chan struct{}
	obsDone chan struct{}

	mu        sync.Mutex
	listeners []func(LeaderInfo)

	// applyObs is the ApplyObserver; see ObserveApplies.
	applyObs atomic.Pointer[ApplyObserver]

	// stream is the Raft transport's connection layer, cert this node's
	// hub node certificate and members the removal bookkeeping (members.go).
	stream  *tlsStream
	cert    *x509.Certificate
	members memberWatch
	// epoch is the cluster epoch of this node's certificate; see epoch.go.
	epoch string

	// configSource digests this hub's configuration; see SetConfigSource.
	configSource atomic.Pointer[ConfigSource]
}

var _ store.Applier = (*Node)(nil)

// New returns a Node for cfg. Bind it to the store, then Start it.
func New(cfg Config) (*Node, error) {
	switch {
	case cfg.DataDir == "":
		return nil, errors.New("cluster: no data dir")
	case cfg.CA == nil:
		return nil, errors.New("cluster: no CA")
	case cfg.Listen == "":
		return nil, errors.New("cluster: no listen address")
	}
	if err := ValidNodeID(cfg.NodeID); err != nil {
		return nil, err
	}
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.DiscardHandler)
	}
	if cfg.OnFatal == nil {
		cfg.OnFatal = func(error) {}
	}
	if cfg.ForwardWait <= 0 {
		cfg.ForwardWait = defaultForwardWait
	}
	return &Node{cfg: cfg, dir: filepath.Join(cfg.DataDir, RaftDir), log: cfg.Log.With("node_id", cfg.NodeID)}, nil
}

// Bind records the store this node replicates and returns the node as its
// Applier. Pass it to store.Open with store.WithApplier(node.Bind).
func (n *Node) Bind(s *store.Store) store.Applier {
	n.store = s
	return n
}

// Addr returns the advertised Raft address. It is empty before Start.
func (n *Node) Addr() string {
	if n.trans == nil {
		return ""
	}
	return string(n.trans.LocalAddr())
}

// ID returns this node's ID.
func (n *Node) ID() string { return n.cfg.NodeID }

// Start opens the Raft state in DataDir/raft, starts the transport and joins
// the replication: as the only voter of a new cluster when Bootstrap is set
// and there is no state yet, otherwise as whatever the stored configuration
// says. On start raft restores the latest snapshot into the store and replays
// the log after it.
func (n *Node) Start(ctx context.Context) error {
	if n.store == nil {
		return errors.New("cluster: start: node not bound to a store")
	}
	if err := os.MkdirAll(n.dir, 0o700); err != nil {
		return fmt.Errorf("cluster: create raft dir: %w", err)
	}
	epoch, err := readEpoch(n.cfg.DataDir)
	if err != nil {
		return fmt.Errorf("cluster: %w", err)
	}
	cert, err := loadOrIssueNodeCert(n.dir, n.cfg.CA, n.cfg.NodeID, epoch, time.Now())
	if err != nil {
		return fmt.Errorf("cluster: node certificate: %w", err)
	}
	n.epoch = pki.HubEpoch(cert.Leaf)
	logger := hclog.FromStandardLogger(slog.NewLogLogger(n.log.Handler(), slog.LevelInfo),
		&hclog.LoggerOptions{Name: "raft", Level: hclog.Info})

	n.cert = cert.Leaf
	stream, err := listenTLS(ctx, n.cfg.Listener, n.cfg.Listen, n.cfg.Advertise, cert, n.cfg.CA, n.refuseRevoked)
	if err != nil {
		return fmt.Errorf("cluster: %w", err)
	}
	n.stream = stream
	n.fwdHTTP = newForwardClient(n.cfg.CA, cert, n.epoch)
	n.trans = raft.NewNetworkTransportWithLogger(stream, maxPool, dialTimeout, logger)
	n.bolt, err = raftboltdb.NewBoltStore(filepath.Join(n.dir, boltFile))
	if err != nil {
		_ = n.trans.Close()
		return fmt.Errorf("cluster: open raft log: %w", err)
	}
	snaps, err := raft.NewFileSnapshotStoreWithLogger(n.dir, snapshotsRetain, logger)
	if err != nil {
		n.closeStores()
		return fmt.Errorf("cluster: open snapshots: %w", err)
	}
	n.fsm = newFSM(n.store, n.dir, n.log, n.cfg.OnFatal, &n.applyObs)
	n.fsm.snaps = snaps

	conf := raft.DefaultConfig()
	conf.LocalID = raft.ServerID(n.cfg.NodeID)
	conf.Logger = logger
	setIfNonZero(&conf.HeartbeatTimeout, n.cfg.HeartbeatTimeout)
	setIfNonZero(&conf.ElectionTimeout, n.cfg.ElectionTimeout)
	setIfNonZero(&conf.LeaderLeaseTimeout, n.cfg.LeaderLeaseTimeout)
	setIfNonZero(&conf.SnapshotInterval, n.cfg.SnapshotInterval)
	setIfNonZero(&conf.SnapshotThreshold, n.cfg.SnapshotThreshold)
	setIfNonZero(&conf.TrailingLogs, n.cfg.TrailingLogs)

	hasState, err := raft.HasExistingState(n.bolt, n.bolt, snaps)
	if err != nil {
		n.closeStores()
		return fmt.Errorf("cluster: %w", err)
	}
	if !hasState && n.cfg.Bootstrap {
		if err := n.bootstrap(ctx, snaps); err != nil {
			n.closeStores()
			return fmt.Errorf("cluster: bootstrap: %w", err)
		}
		n.log.InfoContext(ctx, "formed a new one-node cluster from the current database")
	}

	r, err := raft.NewRaft(conf, n.fsm, n.bolt, n.bolt, snaps, n.trans)
	if err != nil {
		n.closeStores()
		return fmt.Errorf("cluster: start raft: %w", err)
	}
	n.raft = r
	n.fsm.raft.Store(r)
	n.watchLeader()
	n.watchMembers()
	return nil
}

// bootstrap writes a snapshot of the current database as raft index 1, with
// a configuration of this node alone, so the cluster's state starts with
// everything the hub had before it was clustered. Raft logs then begin at
// index 2, which means every node that joins later is sent a snapshot first
// and never misses that pre-cluster state.
func (n *Node) bootstrap(ctx context.Context, snaps raft.SnapshotStore) error {
	conf := raft.Configuration{Servers: []raft.Server{{
		Suffrage: raft.Voter, ID: raft.ServerID(n.cfg.NodeID), Address: n.trans.LocalAddr(),
	}}}
	sink, err := snaps.Create(raft.SnapshotVersionMax, 1, 1, conf, 1, n.trans)
	if err != nil {
		return err
	}
	if err := n.store.Snapshot(ctx, sink); err != nil {
		_ = sink.Cancel()
		return err
	}
	return sink.Close()
}

func setIfNonZero[T comparable](dst *T, v T) {
	var zero T
	if v != zero {
		*dst = v
	}
}

func (n *Node) closeStores() {
	if n.bolt != nil {
		_ = n.bolt.Close()
	}
	if n.trans != nil {
		_ = n.trans.Close()
	}
}

// Shutdown stops Raft, the transport and the leader watcher. The store stays
// open; close it afterwards.
func (n *Node) Shutdown() error {
	if n.raft == nil {
		return nil
	}
	err := n.raft.Shutdown().Error()
	n.raft.DeregisterObserver(n.obs)
	close(n.stopObs)
	<-n.obsDone
	n.stopMembers()
	n.closeStores()
	n.fwdHTTP.CloseIdleConnections()
	if err != nil {
		return fmt.Errorf("cluster: shutdown: %w", err)
	}
	return nil
}

// ErrNotLeader is returned by Apply on a node that is not the leader. Leader
// fields are empty while no leader is known.
type ErrNotLeader struct {
	LeaderID   string
	LeaderAddr string
}

func (e *ErrNotLeader) Error() string {
	if e.LeaderID == "" {
		return "not the cluster leader; no leader is known"
	}
	return fmt.Sprintf("not the cluster leader; the leader is %s at %s", e.LeaderID, e.LeaderAddr)
}

// Apply implements store.Applier. On the leader it proposes the encoded
// command to the Raft log and waits for it to be committed and applied, then
// returns the leader's own state machine result for exactly those bytes. On
// any other node it returns *ErrNotLeader without proposing anything.
func (n *Node) Apply(ctx context.Context, cmd store.Command) (store.Result, error) {
	res, _, err := n.apply(ctx, cmd)
	return res, err
}

// apply is Apply that also returns the entry's log index once it was
// committed and applied here (zero when it was not proposed or not applied).
// It refuses store.MigrateSchema, which only MigrateSchema proposes.
func (n *Node) apply(ctx context.Context, cmd store.Command) (store.Result, uint64, error) {
	if _, ok := cmd.(store.MigrateSchema); ok {
		return store.Result{}, 0, errMigrateViaLog
	}
	return n.propose(ctx, cmd)
}

// propose is apply for any command.
func (n *Node) propose(ctx context.Context, cmd store.Command) (store.Result, uint64, error) {
	if n.raft == nil {
		return store.Result{}, 0, errors.New("cluster: node not started")
	}
	if n.raft.State() != raft.Leader {
		return store.Result{}, 0, n.notLeader()
	}
	b, err := store.EncodeCommand(cmd)
	if err != nil {
		return store.Result{}, 0, err
	}
	if err := ctx.Err(); err != nil {
		return store.Result{}, 0, err
	}
	timeout := applyTimeout
	if dl, ok := ctx.Deadline(); ok {
		timeout = time.Until(dl)
	}
	n.fsm.writes.begin(b)
	f := n.raft.Apply(b, timeout)
	err = f.Error()
	claimed, wasClaimed := n.fsm.writes.end(b)
	if err != nil {
		if wasClaimed {
			// The entry committed after all, and observers were told it is
			// this caller's: it has to see the write as done.
			return claimed, 0, nil
		}
		if errors.Is(err, raft.ErrNotLeader) {
			return store.Result{}, 0, n.notLeader()
		}
		return store.Result{}, 0, applyFailed(cmd.Op(), err)
	}
	resp, ok := f.Response().(applyResponse)
	if !ok {
		return store.Result{}, 0, fmt.Errorf("cluster: apply %s: unexpected response %T", cmd.Op(), f.Response())
	}
	return resp.res, f.Index(), resp.err
}

// applyFailed wraps an error from proposing a command to the Raft log.
// ErrLeadershipLost and timeouts are not ErrNotLeader: the entry may still
// commit, so the caller must not assume it did not happen. A leader change
// (lost, or being transferred) is transient, so it also matches
// store.ErrUnavailable and the API answers a retryable 503.
func applyFailed(op string, err error) error {
	if errors.Is(err, raft.ErrLeadershipLost) || errors.Is(err, raft.ErrLeadershipTransferInProgress) {
		return fmt.Errorf("cluster: apply %s: %w: %w", op, err, store.ErrUnavailable)
	}
	return fmt.Errorf("cluster: apply %s: %w", op, err)
}

func (n *Node) notLeader() *ErrNotLeader {
	l := n.Leader()
	return &ErrNotLeader{LeaderID: l.ID, LeaderAddr: l.Addr}
}

// LeaderInfo identifies the current leader. ID is empty while none is known.
type LeaderInfo struct {
	ID   string
	Addr string
	// Self is true when this node is the leader.
	Self bool
}

// Leader returns the leader as this node currently knows it.
func (n *Node) Leader() LeaderInfo {
	if n.raft == nil {
		return LeaderInfo{}
	}
	addr, id := n.raft.LeaderWithID()
	return LeaderInfo{ID: string(id), Addr: string(addr), Self: id != "" && string(id) == n.cfg.NodeID}
}

// IsLeader reports whether this node is the leader right now.
func (n *Node) IsLeader() bool { return n.raft != nil && n.raft.State() == raft.Leader }

// OnLeaderChange registers fn to be called with the new leader every time
// this node learns of a leader change, including losing the leader (empty
// ID) and becoming the leader itself (Self). Calls are serialized on one
// goroutine owned by the node and stop at Shutdown; fn must not block for long.
func (n *Node) OnLeaderChange(fn func(LeaderInfo)) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.listeners = append(n.listeners, fn)
}

// ObserveApplies makes o the observer of every command this node applies
// from now on, replacing any earlier one; nil removes it. It may be called
// before or after Start. The hub's registry uses it to publish device events
// on followers.
func (n *Node) ObserveApplies(o ApplyObserver) {
	if o == nil {
		n.applyObs.Store(nil)
		return
	}
	n.applyObs.Store(&o)
}

func (n *Node) watchLeader() {
	n.obsCh = make(chan raft.Observation, 16)
	n.stopObs = make(chan struct{})
	n.obsDone = make(chan struct{})
	n.obs = raft.NewObserver(n.obsCh, false, func(o *raft.Observation) bool {
		_, ok := o.Data.(raft.LeaderObservation)
		return ok
	})
	n.raft.RegisterObserver(n.obs)
	go func() {
		defer close(n.obsDone)
		for {
			select {
			case <-n.stopObs:
				return
			case o := <-n.obsCh:
				lo, _ := o.Data.(raft.LeaderObservation)
				info := LeaderInfo{
					ID: string(lo.LeaderID), Addr: string(lo.LeaderAddr),
					Self: lo.LeaderID != "" && string(lo.LeaderID) == n.cfg.NodeID,
				}
				n.log.Info("cluster leader changed", "leader_id", info.ID, "leader_addr", info.Addr, "self", info.Self)
				n.mu.Lock()
				fns := append([]func(LeaderInfo){}, n.listeners...)
				n.mu.Unlock()
				for _, fn := range fns {
					fn(info)
				}
			}
		}
	}()
}

// futureErr waits for f, or for ctx. Raft drops a future that was committed
// but not yet applied when the node shuts down (runFSM returns without
// answering what is queued for it), so f.Error() alone can block forever.
// The goroutine waiting on f ends when raft answers; only such a dropped
// future leaves it parked, once, after Shutdown.
func futureErr(ctx context.Context, f raft.Future) error {
	done := make(chan error, 1)
	go func() { done <- f.Error() }()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// WaitReady blocks until a leader is known and this node has applied
// everything the cluster has committed, or ctx is done. After a restart the
// store is first rolled back to the latest snapshot and the log after it is
// replayed; reads before WaitReady returns may see that older state.
func (n *Node) WaitReady(ctx context.Context) error {
	t := time.NewTicker(50 * time.Millisecond)
	defer t.Stop()
	for {
		if n.IsLeader() {
			// A new leader learns the final commit index of its predecessor's
			// term only by committing an entry of its own: the barrier.
			timeout := applyTimeout
			if dl, ok := ctx.Deadline(); ok {
				timeout = min(timeout, time.Until(dl))
			}
			if err := futureErr(ctx, n.raft.Barrier(timeout)); err == nil {
				return nil
			}
		} else if n.raft != nil && n.Leader().ID != "" {
			commit := n.raft.CommitIndex()
			if commit > 0 && n.appliedThrough(commit) {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("wait for the cluster: %w", ctx.Err())
		case <-t.C:
		}
	}
}

// Peer is one server in the Raft configuration.
type Peer struct {
	ID       string `json:"id"`
	Address  string `json:"address"`
	Suffrage string `json:"suffrage"`
	// Schema is the hub's store schema, filled by StatusWithSchemas;
	// SchemaError says why it could not be read.
	Schema      *SchemaInfo `json:"schema,omitempty"`
	SchemaError string      `json:"schema_error,omitempty"`
}

// Status is this node's view of the cluster.
type Status struct {
	NodeID       string `json:"node_id"`
	State        string `json:"state"`
	LeaderID     string `json:"leader_id"`
	LeaderAddr   string `json:"leader_addr"`
	Term         uint64 `json:"term"`
	LastIndex    uint64 `json:"last_index"`
	CommitIndex  uint64 `json:"commit_index"`
	AppliedIndex uint64 `json:"applied_index"`
	Peers        []Peer `json:"peers"`
	// ConfigDrift compares the hubs' configuration, filled by
	// StatusWithSchemas; nil when it could not be read.
	ConfigDrift *DriftReport `json:"config_drift,omitempty"`
}

// Status returns this node's view of the cluster.
func (n *Node) Status() (Status, error) {
	if n.raft == nil {
		return Status{}, errors.New("cluster: node not started")
	}
	l := n.Leader()
	st := Status{
		NodeID:       n.cfg.NodeID,
		State:        n.raft.State().String(),
		LeaderID:     l.ID,
		LeaderAddr:   l.Addr,
		Term:         n.raft.CurrentTerm(),
		LastIndex:    n.raft.LastIndex(),
		CommitIndex:  n.raft.CommitIndex(),
		AppliedIndex: n.raft.AppliedIndex(),
	}
	cf := n.raft.GetConfiguration()
	if err := cf.Error(); err != nil {
		return Status{}, fmt.Errorf("cluster: configuration: %w", err)
	}
	for _, s := range cf.Configuration().Servers {
		st.Peers = append(st.Peers, Peer{ID: string(s.ID), Address: string(s.Address), Suffrage: s.Suffrage.String()})
	}
	return st, nil
}

// StatusWithSchemas is Status with every peer's store schema (see
// HubSchemas) and the comparison of the hubs' configuration (see ConfigDrift).
func (n *Node) StatusWithSchemas(ctx context.Context) (Status, error) {
	st, err := n.Status()
	if err != nil {
		return st, err
	}
	// A status is read in a polling loop; a hub that does not answer soon
	// shows its error rather than slowing every poll down.
	ctx, cancel := context.WithTimeout(ctx, statusSchemaTimeout)
	defer cancel()
	var wg sync.WaitGroup
	wg.Go(func() {
		if d, err := n.ConfigDrift(ctx); err == nil {
			st.ConfigDrift = &d
		}
	})
	hubs, err := n.HubSchemas(ctx)
	wg.Wait()
	if err != nil {
		return st, err
	}
	for i := range st.Peers {
		for _, h := range hubs {
			switch {
			case h.ID != st.Peers[i].ID:
			case h.Err != nil:
				st.Peers[i].SchemaError = h.Err.Error()
			default:
				si := h.Schema
				st.Peers[i].Schema = &si
			}
		}
	}
	return st, nil
}

// server returns the configuration entry for id, if any.
func (n *Node) server(id string) (raft.Server, bool, error) {
	cf := n.raft.GetConfiguration()
	if err := cf.Error(); err != nil {
		return raft.Server{}, false, err
	}
	for _, s := range cf.Configuration().Servers {
		if string(s.ID) == id {
			return s, true, nil
		}
	}
	return raft.Server{}, false, nil
}

// addressInUse reports whether another server already uses addr.
func (n *Node) addressInUse(addr string) (bool, error) {
	cf := n.raft.GetConfiguration()
	if err := cf.Error(); err != nil {
		return false, err
	}
	for _, s := range cf.Configuration().Servers {
		if string(s.Address) == addr {
			return true, nil
		}
	}
	return false, nil
}

// IsVoter reports whether this node is a voter in the latest configuration.
func (n *Node) IsVoter() (bool, error) {
	s, ok, err := n.server(n.cfg.NodeID)
	return ok && s.Suffrage == raft.Voter, err
}
