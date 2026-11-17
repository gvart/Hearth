// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/hashicorp/raft"

	"github.com/gvart/hearth/internal/pki"
	"github.com/gvart/hearth/internal/policy"
	clusterv1 "github.com/gvart/hearth/internal/proto/hearth/cluster/v1"
	"github.com/gvart/hearth/internal/proto/hearth/cluster/v1/clusterv1connect"
	"github.com/gvart/hearth/internal/store"
)

// Error metadata a follower sets when it refuses a ClusterService call.
const (
	metaLeaderID   = "hearth-leader-id"
	metaLeaderAddr = "hearth-leader-addr"
	// metaNotLeader marks the refusal as "not the leader", which a caller
	// may retry on the leader, apart from any other failed precondition.
	metaNotLeader = "hearth-not-leader"
)

const membershipTimeout = 30 * time.Second

// JoinServer implements ClusterService on the leader.
type JoinServer struct {
	node   *Node
	store  *store.Store
	ca     *pki.CA
	policy *policy.Engine
	log    *slog.Logger
	now    func() time.Time
}

var _ clusterv1connect.ClusterServiceHandler = (*JoinServer)(nil)

// NewJoinServer returns the ClusterService implementation for node.
func NewJoinServer(node *Node, st *store.Store, ca *pki.CA, pol *policy.Engine, log *slog.Logger) *JoinServer {
	return &JoinServer{node: node, store: st, ca: ca, policy: pol, log: log, now: time.Now}
}

// Handler returns the service's path prefix and HTTP handler. Mount it on the
// hub's TLS listener only: Promote authenticates callers by their client
// certificate.
func (s *JoinServer) Handler() (string, http.Handler) {
	path, h := clusterv1connect.NewClusterServiceHandler(s)
	return path, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), tlsStateKey{}, r.TLS)))
	})
}

type tlsStateKey struct{}

// Errors that map to specific codes.
var (
	errSchema    = errors.New("schema mismatch")
	errNodeTaken = errors.New("node ID or raft address already in the cluster")
	errBadCSR    = errors.New("invalid CSR")
)

// Join admits a new hub as a non-voter and hands it its identity and the CA.
func (s *JoinServer) Join(ctx context.Context, req *connect.Request[clusterv1.JoinRequest]) (*connect.Response[clusterv1.JoinResponse], error) {
	msg := req.Msg
	if !s.node.IsLeader() {
		return nil, s.notLeaderError()
	}
	if msg.GetTokenSecret() == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("join token is required"))
	}
	if err := ValidNodeID(msg.GetNodeId()); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	if _, port, err := net.SplitHostPort(msg.GetRaftAddress()); err != nil || port == "" || port == "0" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("raft_address must be host:port"))
	}

	var (
		cert      *x509.Certificate
		schemaErr string
	)
	err := s.policy.Do(ctx, policy.Request{
		ActorKind: policy.ActorJoinToken,
		ActorID:   tokenActorID(msg.GetTokenSecret()),
		Action:    policy.ClusterJoin,
		Target:    msg.GetNodeId(),
		Detail:    map[string]any{"raft_address": msg.GetRaftAddress(), "schema_version": msg.GetSchemaVersion()},
	}, func(ctx context.Context) error {
		// Every check that does not need the token runs first, so a
		// rejected attempt does not burn it.
		have, err := s.store.SchemaVersion(ctx)
		if err != nil {
			return err
		}
		if msg.GetSchemaVersion() != have {
			schemaErr = fmt.Sprintf("this hub's binary has store schema %d but the cluster is at %d; "+
				"run the same hearth version as the cluster", msg.GetSchemaVersion(), have)
			return fmt.Errorf("%w: joining %d, cluster %d", errSchema, msg.GetSchemaVersion(), have)
		}
		if _, taken, err := s.node.server(msg.GetNodeId()); err != nil {
			return err
		} else if taken {
			return errNodeTaken
		}
		if taken, err := s.node.addressInUse(msg.GetRaftAddress()); err != nil {
			return err
		} else if taken {
			return errNodeTaken
		}
		now := s.now()
		c, err := s.ca.SignHubCSR(msg.GetCsr(), msg.GetNodeId(), now)
		if err != nil {
			return fmt.Errorf("%w: %w", errBadCSR, err)
		}
		if err := s.store.JoinTokens().Consume(ctx, msg.GetTokenSecret(), now); err != nil {
			return err
		}
		// Recorded before the hub can use it, so removing the hub later
		// revokes it.
		if err := s.store.Hubs().RecordCert(ctx, pki.SerialString(c), msg.GetNodeId()); err != nil {
			return err
		}
		// A non-voter does not count towards quorum, so a hub that never
		// comes up after joining cannot stall the cluster.
		f := s.node.raft.AddNonvoter(raft.ServerID(msg.GetNodeId()), raft.ServerAddress(msg.GetRaftAddress()), 0, membershipTimeout)
		if err := f.Error(); err != nil {
			return fmt.Errorf("add non-voter: %w", err)
		}
		cert = c
		return nil
	})
	if err != nil {
		if schemaErr != "" {
			return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New(schemaErr))
		}
		return nil, s.toConnectError(ctx, "join", err)
	}
	keyDER, err := s.ca.KeyDER()
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("join failed"))
	}
	s.log.InfoContext(ctx, "hub joined the cluster as a non-voter", "joined_id", msg.GetNodeId(), "raft_address", msg.GetRaftAddress())
	return connect.NewResponse(&clusterv1.JoinResponse{
		Certificate:   cert.Raw,
		CaCertificate: s.ca.Cert().Raw,
		CaKey:         keyDER,
		LeaderId:      s.node.ID(),
		LastIndex:     s.node.raft.LastIndex(),
	}), nil
}

// Promote makes a joined non-voter a voter. The caller must present the hub
// node certificate issued to the node it names.
func (s *JoinServer) Promote(ctx context.Context, req *connect.Request[clusterv1.PromoteRequest]) (*connect.Response[clusterv1.PromoteResponse], error) {
	if !s.node.IsLeader() {
		return nil, s.notLeaderError()
	}
	id := req.Msg.GetNodeId()
	certID, err := s.peerHubID(ctx)
	if err != nil {
		return nil, err
	}
	if certID != id {
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("certificate does not belong to this node"))
	}
	err = s.policy.Do(ctx, policy.Request{
		ActorKind: policy.ActorHub,
		ActorID:   id,
		Action:    policy.ClusterPromote,
		Target:    id,
	}, func(context.Context) error {
		srv, ok, err := s.node.server(id)
		switch {
		case err != nil:
			return err
		case !ok:
			return store.ErrNotFound
		case srv.Suffrage == raft.Voter:
			return nil
		}
		if err := s.node.raft.AddVoter(srv.ID, srv.Address, 0, membershipTimeout).Error(); err != nil {
			return fmt.Errorf("add voter: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, s.toConnectError(ctx, "promote", err)
	}
	s.log.InfoContext(ctx, "hub promoted to voter", "promoted_id", id)
	return connect.NewResponse(&clusterv1.PromoteResponse{}), nil
}

func (s *JoinServer) notLeaderError() error {
	l := s.node.Leader()
	e := connect.NewError(connect.CodeFailedPrecondition, (&ErrNotLeader{LeaderID: l.ID, LeaderAddr: l.Addr}))
	e.Meta().Set(metaLeaderID, l.ID)
	e.Meta().Set(metaLeaderAddr, l.Addr)
	e.Meta().Set(metaNotLeader, "1")
	return e
}

func (s *JoinServer) toConnectError(ctx context.Context, op string, err error) error {
	var nl *ErrNotLeader
	switch {
	case errors.As(err, &nl) || errors.Is(err, raft.ErrNotLeader) || errors.Is(err, raft.ErrLeadershipLost):
		return s.notLeaderError()
	case errors.Is(err, errBadCSR):
		return connect.NewError(connect.CodeInvalidArgument, err)
	case errors.Is(err, errNodeTaken):
		return connect.NewError(connect.CodeAlreadyExists, err)
	case errors.Is(err, store.ErrNotFound) && op == "promote":
		return connect.NewError(connect.CodeNotFound, errors.New("node is not in the cluster; join it first"))
	case errors.Is(err, store.ErrNotFound):
		return connect.NewError(connect.CodeUnauthenticated, errors.New("unknown join token"))
	case errors.Is(err, store.ErrTokenUsed):
		return connect.NewError(connect.CodeUnauthenticated, errors.New("join token already used"))
	case errors.Is(err, store.ErrTokenExpired):
		return connect.NewError(connect.CodeUnauthenticated, errors.New("join token expired"))
	case errors.Is(err, policy.ErrDenied):
		return connect.NewError(connect.CodePermissionDenied, errors.New(op+" denied by policy"))
	default:
		s.log.ErrorContext(ctx, "cluster "+op+" failed", "err", err)
		return connect.NewError(connect.CodeInternal, errors.New(op+" failed"))
	}
}

// tokenActorID is a short, non-reversible handle for a token in the audit log.
func tokenActorID(secret string) string {
	h := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(h[:6])
}

// JoinParams describes a hub joining a cluster.
type JoinParams struct {
	// URL is any member's TLS listener, e.g. https://hub-a:7443. A follower
	// redirects to the leader on the same port.
	URL string
	// Token is the encoded join token (hearthj1.<secret>.<fingerprint>).
	Token string
	// DataDir is the joining hub's data dir. It must not hold a CA yet.
	DataDir string
	// NodeID and RaftAddress identify the joining hub to its peers.
	NodeID      string
	RaftAddress string
}

// maxRedirects bounds how often Join and Promote follow a follower to the leader.
const maxRedirects = 3

// Join admits this hub into a cluster: it pins the cluster's CA by the
// token's fingerprint, sends a CSR and receives a node certificate and the
// CA, key included, which it writes into DataDir (ca.key at 0600). Start the
// node afterwards (without Bootstrap) and call Promote once it runs.
func Join(ctx context.Context, p JoinParams) error {
	tok, err := pki.ParseJoinToken(p.Token)
	if err != nil {
		return err
	}
	if _, err := os.Stat(filepath.Join(p.DataDir, pki.CAKeyFile)); err == nil {
		return fmt.Errorf("%s already holds a hub CA; --join needs a fresh data dir", p.DataDir)
	}
	dir := filepath.Join(p.DataDir, RaftDir)
	if _, err := os.Stat(filepath.Join(dir, nodeCertFile)); err == nil {
		return fmt.Errorf("%s already holds a node certificate; --join needs a fresh data dir", p.DataDir)
	}
	key, err := pki.NewKey()
	if err != nil {
		return err
	}
	csr, err := pki.NewCSR(key, p.NodeID)
	if err != nil {
		return err
	}
	req := &clusterv1.JoinRequest{
		TokenSecret:   tok.Secret,
		NodeId:        p.NodeID,
		RaftAddress:   p.RaftAddress,
		Csr:           csr,
		SchemaVersion: store.SchemaVersion(),
	}
	var resp *connect.Response[clusterv1.JoinResponse]
	target := p.URL
	err = followLeader(ctx, &target, func(ctx context.Context, u *url.URL) error {
		transport := &http.Transport{TLSClientConfig: pki.PinnedTLSConfig(tok.CAFingerprint, u.Hostname())}
		defer transport.CloseIdleConnections()
		client := clusterv1connect.NewClusterServiceClient(&http.Client{Transport: transport}, u.String())
		resp, err = client.Join(ctx, connect.NewRequest(req))
		return err
	})
	if err != nil {
		return fmt.Errorf("join cluster at %s: %w", target, err)
	}
	cert, err := x509.ParseCertificate(resp.Msg.GetCertificate())
	if err != nil {
		return fmt.Errorf("join: parse node certificate: %w", err)
	}
	if id, err := pki.HubNodeID(cert); err != nil || id != p.NodeID {
		return errors.New("join: node certificate does not carry this node's ID")
	}
	if err := writeNodeCert(dir, cert, key); err != nil {
		return fmt.Errorf("join: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, joinURLFile), []byte(target+"\n"), 0o600); err != nil {
		return fmt.Errorf("join: %w", err)
	}
	if err := pki.InstallCA(p.DataDir, resp.Msg.GetCaCertificate(), resp.Msg.GetCaKey(), tok.CAFingerprint); err != nil {
		return fmt.Errorf("join: %w", err)
	}
	return nil
}

// Promote asks the leader, reached through the URL this hub joined with, to
// make it a voter. It authenticates with the node certificate in DataDir.
// Promoting a voter is a no-op.
func Promote(ctx context.Context, dataDir, nodeID string) error {
	dir := filepath.Join(dataDir, RaftDir)
	b, err := os.ReadFile(filepath.Join(dir, joinURLFile))
	if err != nil {
		return fmt.Errorf("promote: no join URL recorded: %w", err)
	}
	cert, err := tls.LoadX509KeyPair(filepath.Join(dir, nodeCertFile), filepath.Join(dir, nodeKeyFile))
	if err != nil {
		return fmt.Errorf("promote: %w", err)
	}
	caCert, err := pki.LoadCACert(dataDir)
	if err != nil {
		return fmt.Errorf("promote: %w", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	target := strings.TrimSpace(string(b))
	err = followLeader(ctx, &target, func(ctx context.Context, u *url.URL) error {
		transport := &http.Transport{TLSClientConfig: &tls.Config{
			MinVersion:   tls.VersionTLS13,
			ServerName:   u.Hostname(),
			RootCAs:      roots,
			Certificates: []tls.Certificate{cert},
		}}
		defer transport.CloseIdleConnections()
		client := clusterv1connect.NewClusterServiceClient(&http.Client{Transport: transport}, u.String())
		_, err := client.Promote(ctx, connect.NewRequest(&clusterv1.PromoteRequest{NodeId: nodeID}))
		return err
	})
	if err != nil {
		return fmt.Errorf("promote at %s: %w", target, err)
	}
	return nil
}

// followLeader calls call on *target and, when a follower answers with the
// leader's raft address, retries on the leader's host with the same scheme
// and port, updating *target. Hubs therefore must use the same TLS port.
func followLeader(ctx context.Context, target *string, call func(context.Context, *url.URL) error) error {
	for range maxRedirects {
		u, err := url.Parse(*target)
		if err != nil || u.Host == "" {
			return fmt.Errorf("invalid hub URL %q", *target)
		}
		err = call(ctx, u)
		var ce *connect.Error
		if !errors.As(err, &ce) || ce.Code() != connect.CodeFailedPrecondition || ce.Meta().Get(metaLeaderAddr) == "" {
			return err
		}
		host, _, splitErr := net.SplitHostPort(ce.Meta().Get(metaLeaderAddr))
		if splitErr != nil {
			return err
		}
		next := *u
		next.Host = host
		if u.Port() != "" {
			next.Host = net.JoinHostPort(host, u.Port())
		}
		if next.String() == u.String() {
			return err
		}
		*target = next.String()
	}
	return errors.New("too many redirects to the leader")
}
