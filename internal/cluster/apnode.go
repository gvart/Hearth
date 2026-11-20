// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import (
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
	"time"

	"connectrpc.com/connect"
	"golang.org/x/sync/errgroup"

	"github.com/gvart/hearth/internal/pki"
	"github.com/gvart/hearth/internal/policy"
	clusterv1 "github.com/gvart/hearth/internal/proto/hearth/cluster/v1"
	"github.com/gvart/hearth/internal/proto/hearth/cluster/v1/clusterv1connect"
	"github.com/gvart/hearth/internal/store"
)

// A hub in an AP cluster (`--cluster-mode ap`, docs/design/ap-cluster.md):
// no Raft. Its identity is the same as a Raft member's (a hub node
// certificate from the cluster CA, in DataDir/raft), its membership is the
// gossip, and its store is sharded by the Replicator. A hub alone is a
// cluster of one, N = 1, not highly available.

// Files of an AP member, in DataDir/raft.
const (
	// apModeFile marks a data dir as an AP member's, so it is never
	// started as a Raft member, nor a Raft member's as an AP one.
	apModeFile = "mode"
	// lastContactFile records when the member last reached the cluster.
	lastContactFile = "last-contact"
	// seedsFile keeps the gossip addresses this member learnt, so it finds
	// the cluster again after a restart.
	seedsFile = "gossip-seeds"
)

// ErrModeMismatch refuses to start a data dir in the other cluster mode.
var ErrModeMismatch = errors.New("cluster mode mismatch")

// CheckMode checks that dataDir may run in mode ("ap" or "raft"): an AP
// member's data dir runs only as AP, a Raft member's only as Raft.
func CheckMode(dataDir, mode string) error {
	dir := filepath.Join(dataDir, RaftDir)
	b, err := os.ReadFile(filepath.Join(dir, apModeFile))
	isAP := err == nil && strings.TrimSpace(string(b)) == "ap"
	_, boltErr := os.Stat(filepath.Join(dir, boltFile))
	isRaft := boltErr == nil
	switch {
	case mode == "ap" && isRaft:
		return fmt.Errorf("%w: %s belongs to a Raft cluster member; an AP cluster starts from a fresh data dir "+
			"(or a backup restored into one)", ErrModeMismatch, dataDir)
	case mode != "ap" && isAP:
		return fmt.Errorf("%w: %s belongs to an AP cluster member: start it with --cluster-mode ap", ErrModeMismatch, dataDir)
	}
	return nil
}

// IsAPMember reports whether dataDir belongs to an AP cluster member.
func IsAPMember(dataDir string) bool {
	b, err := os.ReadFile(filepath.Join(dataDir, RaftDir, apModeFile))
	return err == nil && strings.TrimSpace(string(b)) == "ap"
}

// APConfig configures an APNode.
type APConfig struct {
	DataDir string
	NodeID  string
	CA      *pki.CA
	// Allowed is the host's --allow-roles; the hub takes HubRoles.
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
	Log      *slog.Logger
	// Tuning for tests; zero uses the defaults.
	Gossip ReplicatorConfig
}

// APNode is a hub's place in an AP cluster.
type APNode struct {
	cfg        APConfig
	log        *slog.Logger
	cert       tls.Certificate
	hints      *Hints
	rep        *Replicator
	membership *Membership
	st         *store.Store
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
	if err := CheckMode(cfg.DataDir, "ap"); err != nil {
		return nil, err
	}
	dir := filepath.Join(cfg.DataDir, RaftDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("ap node: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, apModeFile), []byte("ap\n"), 0o600); err != nil {
		return nil, fmt.Errorf("ap node: %w", err)
	}
	cert, err := loadOrIssueNodeCert(dir, cfg.CA, cfg.NodeID, "", time.Now())
	if err != nil {
		return nil, fmt.Errorf("ap node: node certificate: %w", err)
	}
	hints, err := OpenHints(ctx, filepath.Join(cfg.DataDir, HintsFile), 0)
	if err != nil {
		return nil, err
	}
	n := &APNode{cfg: cfg, log: cfg.Log.With("component", "ap-cluster"), cert: cert, hints: hints}
	rc := cfg.Gossip
	rc.NodeID, rc.Peers, rc.Replicas, rc.Hints, rc.Log = cfg.NodeID, apNodePeers{n}, cfg.Replicas, hints, cfg.Log
	rc.LastContact = filepath.Join(dir, lastContactFile)
	if n.rep, err = NewReplicator(rc); err != nil {
		_ = hints.Close()
		return nil, err
	}
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
	return []store.Option{store.WithShards(n.rep), store.WithApplier(n.rep.Bind), store.WithOrigin(n.cfg.NodeID)}
}

// Bind checks the opened store (a member away longer than the tombstone
// window must rejoin empty, ErrRejoinEmpty) and starts the membership on
// it.
func (n *APNode) Bind(ctx context.Context, st *store.Store) error {
	has, err := hasRows(ctx, st)
	if err != nil {
		return err
	}
	if err := CheckRejoin(filepath.Join(n.cfg.DataDir, RaftDir, lastContactFile), has, time.Now()); err != nil {
		return err
	}
	n.st = st
	cert := n.cert
	m, err := NewMembership(MembershipConfig{
		NodeID: n.cfg.NodeID, Roles: HubRoles, Allowed: n.cfg.Allowed,
		Listen: n.cfg.Listen, Listener: n.cfg.Listener, Advertise: n.cfg.Advertise,
		Seeds:  n.seeds,
		Schema: func(ctx context.Context) (int64, error) { return st.SchemaVersion(ctx) },
		Log:    n.cfg.Log, CA: n.cfg.CA,
		Cert:    func() *tls.Certificate { return &cert },
		Check:   n.checkPeer,
		Replica: n.rep.ServeConn,
	})
	if err != nil {
		return err
	}
	n.membership = m
	return nil
}

// hasRows reports whether st holds any replicated row.
func hasRows(ctx context.Context, st *store.Store) (bool, error) {
	for _, t := range store.ReplicatedTables() {
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

// checkPeer refuses a revoked hub certificate.
func (n *APNode) checkPeer(cert *x509.Certificate) error {
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
	if b, err := os.ReadFile(filepath.Join(n.cfg.DataDir, RaftDir, seedsFile)); err == nil {
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
			_ = os.WriteFile(filepath.Join(n.cfg.DataDir, RaftDir, seedsFile), []byte(strings.Join(learnt, "\n")+"\n"), 0o600)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

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
	return g.Wait()
}

// RecordNodeCert records this hub's node certificate in the hub
// certificates, so removing the hub can revoke it.
func (n *APNode) RecordNodeCert(ctx context.Context) error {
	leaf := n.cert.Leaf
	if leaf == nil {
		var err error
		if leaf, err = x509.ParseCertificate(n.cert.Certificate[0]); err != nil {
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
	st := Status{NodeID: n.cfg.NodeID, State: "ap", Mode: "ap"}
	if n.membership != nil {
		st.Members = n.membership.Members()
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
	mux.HandleFunc("GET /v1/status", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, n.Status())
	})
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

// APJoinServer serves the Join call of ClusterService on an AP member: it
// admits a new hub with a join token, as JoinServer does on a Raft leader,
// without Raft: the hub gets its node certificate and the CA, and joins the
// gossip on its own.
type APJoinServer struct {
	clusterv1connect.UnimplementedClusterServiceHandler
	node   *APNode
	store  *store.Store
	ca     *pki.CA
	policy *policy.Engine
	log    *slog.Logger
	now    func() time.Time
}

// NewAPJoinServer returns the join service of node.
func NewAPJoinServer(node *APNode, st *store.Store, ca *pki.CA, pol *policy.Engine, log *slog.Logger) *APJoinServer {
	return &APJoinServer{node: node, store: st, ca: ca, policy: pol, log: log, now: time.Now}
}

// Handler returns the service's path prefix and HTTP handler, for the hub's
// TLS listener.
func (s *APJoinServer) Handler() (string, http.Handler) {
	return clusterv1connect.NewClusterServiceHandler(s)
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
	var (
		cert    *x509.Certificate
		refused string
	)
	err := s.policy.Do(ctx, policy.Request{
		ActorKind: policy.ActorJoinToken,
		ActorID:   tokenActorID(msg.GetTokenSecret()),
		Action:    policy.ClusterJoin,
		Target:    msg.GetNodeId(),
		Detail:    map[string]any{"gossip_address": msg.GetRaftAddress(), "schema_version": msg.GetSchemaVersion(), "mode": "ap"},
	}, func(ctx context.Context) error {
		have, err := s.store.SchemaVersion(ctx)
		if err != nil {
			return err
		}
		if msg.GetSchemaVersion() < have {
			refused = fmt.Sprintf("this hub's binary supports store schema up to %d but the cluster is at %d; "+
				"run the cluster's hearth version or a newer one", msg.GetSchemaVersion(), have)
			return fmt.Errorf("%w: joining binary supports %d, cluster at %d", errSchema, msg.GetSchemaVersion(), have)
		}
		for _, m := range s.node.Status().Members {
			if m.ID == msg.GetNodeId() && m.State != MemberLeft {
				return errNodeTaken
			}
		}
		now := s.now()
		c, err := s.ca.SignHubCSRInEpoch(msg.GetCsr(), msg.GetNodeId(), "", now)
		if err != nil {
			return fmt.Errorf("%w: %w", errBadCSR, err)
		}
		if err := s.store.JoinTokens().Consume(ctx, msg.GetTokenSecret(), now); err != nil {
			return err
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
	keyDER, err := s.ca.KeyDER()
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("join failed"))
	}
	s.log.InfoContext(ctx, "hub joined the AP cluster", "joined_id", msg.GetNodeId())
	return connect.NewResponse(&clusterv1.JoinResponse{
		Certificate: cert.Raw, CaCertificate: s.ca.Cert().Raw, CaKey: keyDER, LeaderId: s.node.ID(),
	}), nil
}

func (s *APJoinServer) toConnectError(ctx context.Context, err error) error {
	switch {
	case errors.Is(err, errBadCSR):
		return connect.NewError(connect.CodeInvalidArgument, err)
	case errors.Is(err, errNodeTaken):
		return connect.NewError(connect.CodeAlreadyExists, err)
	case errors.Is(err, store.ErrNotFound):
		return connect.NewError(connect.CodeUnauthenticated, errors.New("unknown join token"))
	case errors.Is(err, store.ErrTokenUsed):
		return connect.NewError(connect.CodeUnauthenticated, errors.New("join token already used"))
	case errors.Is(err, store.ErrTokenExpired):
		return connect.NewError(connect.CodeUnauthenticated, errors.New("join token expired"))
	case errors.Is(err, store.ErrUnavailable):
		return connect.NewError(connect.CodeUnavailable, errors.New("join: the cluster is unavailable; try again"))
	case errors.Is(err, policy.ErrDenied):
		return connect.NewError(connect.CodePermissionDenied, errors.New("join denied by policy"))
	default:
		s.log.ErrorContext(ctx, "cluster join failed", "err", err)
		return connect.NewError(connect.CodeInternal, errors.New("join failed"))
	}
}
