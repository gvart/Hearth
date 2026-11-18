// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"slices"
	"sync"
	"time"

	"connectrpc.com/connect"
	"github.com/hashicorp/raft"

	"github.com/gvart/hearth/internal/pki"
	clusterv1 "github.com/gvart/hearth/internal/proto/hearth/cluster/v1"
	"github.com/gvart/hearth/internal/proto/hearth/cluster/v1/clusterv1connect"
	"github.com/gvart/hearth/internal/store"
)

// Member removal and hub certificate revocation.
//
// Every hub node certificate's serial is recorded in the replicated store
// (store.Hubs): by the leader when it signs one at Join, and by each hub for
// its own certificate once it has caught up (RecordNodeCert), which covers a
// certificate the hub renewed itself at start and certificates issued before
// serials were recorded. Removing a hub revokes every serial recorded for its
// node ID. The Raft transport refuses a revoked certificate at the handshake
// and closes already open connections of one within revokeSweep;
// ClusterService refuses it on every call.

// revokeSweep is how often each node closes open Raft connections whose peer
// certificate has been revoked since the handshake.
const revokeSweep = 2 * time.Second

// Refusals of RemoveMember.
var (
	// ErrRemoveLeader refuses removing the leader: transfer leadership first.
	ErrRemoveLeader = errors.New("cannot remove the leader")
	// ErrLastVoter refuses removing the only voter.
	ErrLastVoter = errors.New("cannot remove the last voter")
	// ErrQuorumAtRisk refuses a removal after which the voters that answer
	// the leader would not be a majority of the remaining voters.
	ErrQuorumAtRisk = errors.New("removal would leave the cluster without a working majority")
)

// memberWatch tracks, on the leader, which peers fail heartbeats, and runs the
// revocation sweep. Its goroutine is owned by the Node: started in Start,
// stopped in Shutdown.
type memberWatch struct {
	ch   chan raft.Observation
	obs  *raft.Observer
	stop chan struct{}
	done chan struct{}

	mu      sync.Mutex
	failing map[raft.ServerID]bool
}

func (n *Node) watchMembers() {
	w := &n.members
	w.failing = map[raft.ServerID]bool{}
	w.ch = make(chan raft.Observation, 64)
	w.stop = make(chan struct{})
	w.done = make(chan struct{})
	w.obs = raft.NewObserver(w.ch, false, func(o *raft.Observation) bool {
		switch o.Data.(type) {
		case raft.FailedHeartbeatObservation, raft.ResumedHeartbeatObservation,
			raft.LeaderObservation, raft.PeerObservation:
			return true
		}
		return false
	})
	n.raft.RegisterObserver(w.obs)
	go func() {
		defer close(w.done)
		t := time.NewTicker(revokeSweep)
		defer t.Stop()
		for {
			select {
			case <-w.stop:
				return
			case o := <-w.ch:
				w.observe(o)
			case <-t.C:
				n.closeRevokedConns()
			}
		}
	}()
}

func (n *Node) stopMembers() {
	n.raft.DeregisterObserver(n.members.obs)
	close(n.members.stop)
	<-n.members.done
}

func (w *memberWatch) observe(o raft.Observation) {
	w.mu.Lock()
	defer w.mu.Unlock()
	switch d := o.Data.(type) {
	case raft.FailedHeartbeatObservation:
		w.failing[d.PeerID] = true
	case raft.ResumedHeartbeatObservation:
		delete(w.failing, d.PeerID)
	case raft.PeerObservation:
		if d.Removed {
			delete(w.failing, d.Peer.ID)
		}
	case raft.LeaderObservation:
		// Heartbeat failures are a leader's view; a new term starts afresh.
		clear(w.failing)
	}
}

func (w *memberWatch) isFailing(id raft.ServerID) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.failing[id]
}

// checkPeerCert refuses a revoked hub node certificate. It reads the local
// replica of the revocation table and returns any read error.
func (n *Node) checkPeerCert(cert *x509.Certificate) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return n.store.Hubs().CheckCert(ctx, pki.SerialString(cert))
}

// refuseRevoked is the Raft transport's peer check. It refuses a revoked
// certificate only: when the revocation table cannot be read, it accepts the
// CA-issued hub certificate and logs the failure, so a store problem on this
// node halts it through the FSM, as before, rather than cutting it off from
// its peers.
func (n *Node) refuseRevoked(cert *x509.Certificate) error {
	err := n.checkPeerCert(cert)
	if err != nil && !errors.Is(err, store.ErrCertRevoked) {
		n.log.Warn("cannot check a peer's hub certificate for revocation; accepting it", "err", err)
		return nil
	}
	return err
}

// closeRevokedConns closes the open Raft connections of revoked peers.
func (n *Node) closeRevokedConns() {
	k := n.stream.closeRevoked(func(c *x509.Certificate) bool {
		return errors.Is(n.checkPeerCert(c), store.ErrCertRevoked)
	})
	if k > 0 {
		n.log.Info("closed raft connections of revoked hub certificates", "count", k)
	}
}

// RecordNodeCert records this node's hub node certificate in the replicated
// store, through the leader, unless it is recorded already. It retries until
// it is recorded or ctx ends, like Announce. A hub whose certificate has been
// revoked, because it was removed from the cluster, logs that and gives up.
func (n *Node) RecordNodeCert(ctx context.Context) {
	if n.cert == nil {
		return
	}
	serial := pki.SerialString(n.cert)
	waiting := false
	for {
		err := n.store.Hubs().RequireCerts(ctx)
		if errors.Is(err, store.ErrSchemaTooOld) {
			// A newer binary on an older schema: record it once the
			// cluster migrates.
			if !waiting {
				n.log.InfoContext(ctx, "this hub's node certificate is recorded once the cluster migrates its schema",
					"reason", err)
				waiting = true
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(announceRetry):
			}
			continue
		}
		var certs []store.HubCert
		if err == nil {
			certs, err = n.store.Hubs().Certs(ctx, n.cfg.NodeID)
		}
		if err == nil {
			i := slices.IndexFunc(certs, func(c store.HubCert) bool { return c.Serial == serial })
			switch {
			case i >= 0 && certs[i].Revoked:
				n.log.ErrorContext(ctx, "this hub's node certificate is revoked: it was removed from the cluster. "+
					"To bring it back, join it again with a fresh data dir and a new join token", "serial", serial)
				return
			case i >= 0:
				return
			}
			if err = n.store.Hubs().RecordCert(ctx, serial, n.cfg.NodeID); err == nil {
				n.log.InfoContext(ctx, "recorded this hub's node certificate in the cluster", "serial", serial)
				return
			}
		}
		if ctx.Err() != nil {
			return
		}
		n.log.WarnContext(ctx, "cannot record this hub's node certificate yet; retrying", "err", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(announceRetry):
		}
	}
}

// RemoveMember removes hub id from the cluster: on the leader, or forwarded
// to it like ApplyOrForward, authenticated with this hub's node certificate.
// The leader removes id from the Raft configuration, then revokes every hub
// certificate recorded for it, and returns how many it revoked. Removing a
// hub that already left the configuration finishes an interrupted removal by
// revoking what is left. The caller makes the policy decision.
//
// It refuses (see the Err variables) to remove the leader, the last voter,
// or a voter whose removal leaves fewer voters answering the leader than the
// remaining voters' majority. An ID that is neither in the configuration nor
// has unrevoked certificates fails with store.ErrNotFound.
func (n *Node) RemoveMember(ctx context.Context, id string) (int, error) {
	if err := ValidNodeID(id); err != nil {
		return 0, err
	}
	var revoked int
	err := n.onLeader(ctx, "remove "+id, func() error {
		var err error
		revoked, err = n.removeLocal(ctx, id)
		return err
	}, func(ctx context.Context, c clusterv1connect.ClusterServiceClient) error {
		resp, err := c.RemoveMember(ctx, connect.NewRequest(&clusterv1.RemoveMemberRequest{NodeId: id}))
		if err == nil {
			revoked = int(resp.Msg.GetRevoked())
		}
		return err
	})
	return revoked, err
}

func (n *Node) removeLocal(ctx context.Context, id string) (int, error) {
	if id == n.cfg.NodeID {
		return 0, fmt.Errorf("%w: %s leads the cluster; run `hearth cluster transfer-leadership` first, "+
			"then remove it through another hub", ErrRemoveLeader, id)
	}
	cf := n.raft.GetConfiguration()
	if err := cf.Error(); err != nil {
		return 0, fmt.Errorf("read the cluster configuration: %w", err)
	}
	// Checked before the configuration change, so a removal on an older
	// schema does not leave a hub out of the cluster with live certificates.
	if err := n.store.Hubs().RequireCerts(ctx); err != nil {
		return 0, fmt.Errorf("remove %s: %w", id, err)
	}
	servers := cf.Configuration().Servers
	i := slices.IndexFunc(servers, func(s raft.Server) bool { return string(s.ID) == id })
	if i < 0 {
		k, err := n.store.Hubs().RevokeCerts(ctx, id, time.Now())
		if err != nil {
			return 0, err
		}
		if k == 0 {
			return 0, fmt.Errorf("hub %s is not a cluster member: %w", id, store.ErrNotFound)
		}
		n.closeRevokedConns()
		n.log.InfoContext(ctx, "revoked the certificates of a hub that already left the cluster", "removed_id", id, "revoked", k)
		return k, nil
	}
	if servers[i].Suffrage == raft.Voter {
		if err := n.voterRemovable(servers, servers[i].ID); err != nil {
			return 0, err
		}
	}
	if err := futureErr(ctx, n.raft.RemoveServer(servers[i].ID, 0, membershipTimeout)); err != nil {
		return 0, fmt.Errorf("remove %s from the raft configuration: %w", id, err)
	}
	k, err := n.store.Hubs().RevokeCerts(ctx, id, time.Now())
	if err != nil {
		return 0, fmt.Errorf("%s left the cluster, but revoking its certificates failed; "+
			"run the removal again to finish it: %w", id, err)
	}
	n.closeRevokedConns()
	n.log.InfoContext(ctx, "removed a hub from the cluster", "removed_id", id, "revoked", k)
	return k, nil
}

// voterRemovable refuses removing voter id when that leaves no voter, or
// fewer voters answering heartbeats than a majority of those that remain:
// the configuration change could then never commit and the cluster would
// stall. The leader itself always counts as answering.
func (n *Node) voterRemovable(servers []raft.Server, id raft.ServerID) error {
	voters, healthy := 0, 0
	for _, s := range servers {
		if s.Suffrage != raft.Voter || s.ID == id {
			continue
		}
		voters++
		if string(s.ID) == n.cfg.NodeID || !n.members.isFailing(s.ID) {
			healthy++
		}
	}
	if voters == 0 {
		return fmt.Errorf("%w: %s is the only voter", ErrLastVoter, id)
	}
	if need := voters/2 + 1; healthy < need {
		return fmt.Errorf("%w: without %s, %d of the %d remaining voters answer the leader and %d are needed; "+
			"bring the unreachable voters back or remove them first", ErrQuorumAtRisk, id, healthy, voters, need)
	}
	return nil
}

// TransferLeadership asks the leader, here or forwarded, to hand leadership
// to voter to, or to the most up-to-date voter when to is empty, and waits
// until it has. The caller makes the policy decision.
func (n *Node) TransferLeadership(ctx context.Context, to string) error {
	if to != "" {
		if err := ValidNodeID(to); err != nil {
			return err
		}
	}
	return n.onLeader(ctx, "transfer leadership", func() error {
		return n.transferLocal(ctx, to)
	}, func(ctx context.Context, c clusterv1connect.ClusterServiceClient) error {
		_, err := c.TransferLeadership(ctx, connect.NewRequest(&clusterv1.TransferLeadershipRequest{NodeId: to}))
		return err
	})
}

func (n *Node) transferLocal(ctx context.Context, to string) error {
	if to == "" {
		if err := futureErr(ctx, n.raft.LeadershipTransfer()); err != nil {
			return fmt.Errorf("transfer leadership: %w", err)
		}
		return nil
	}
	if to == n.cfg.NodeID {
		return fmt.Errorf("%s already leads the cluster", to)
	}
	srv, ok, err := n.server(to)
	switch {
	case err != nil:
		return fmt.Errorf("read the cluster configuration: %w", err)
	case !ok:
		return fmt.Errorf("hub %s is not a cluster member: %w", to, store.ErrNotFound)
	case srv.Suffrage != raft.Voter:
		return fmt.Errorf("hub %s is not a voter and cannot lead", to)
	}
	if err := futureErr(ctx, n.raft.LeadershipTransferToServer(srv.ID, srv.Address)); err != nil {
		return fmt.Errorf("transfer leadership to %s: %w", to, err)
	}
	return nil
}

// onLeader runs local on the leader, or remote against the leader's
// ClusterService from a follower. Until the leader is known and reachable it
// retries for up to Config.ForwardWait, then fails with store.ErrUnavailable.
func (n *Node) onLeader(ctx context.Context, what string, local func() error,
	remote func(context.Context, clusterv1connect.ClusterServiceClient) error,
) error {
	if n.raft == nil {
		return errors.New("cluster: node not started")
	}
	deadline := time.Now().Add(n.cfg.ForwardWait)
	for {
		if n.IsLeader() {
			err := local()
			if !errors.Is(err, raft.ErrNotLeader) {
				return err
			}
		} else if l := n.Leader(); l.ID != "" && l.ID != n.cfg.NodeID {
			if base := n.agentURL(n.hubURLs(ctx), l.ID, l.Addr); base != "" {
				err := remote(ctx, clusterv1connect.NewClusterServiceClient(n.fwdHTTP, base))
				if !retryOnLeader(err) {
					return fromConnect(err)
				}
			}
		}
		if !time.Now().Before(deadline) {
			return fmt.Errorf("cluster: %s: no leader reachable within %s: %w", what, n.cfg.ForwardWait, store.ErrUnavailable)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(forwardRetry):
		}
	}
}

// retryOnLeader reports whether a ClusterService call failed before the
// leader acted on it: the hub was not the leader, or could not be dialed.
func retryOnLeader(err error) bool {
	var (
		ce *connect.Error
		oe *net.OpError
	)
	return (errors.As(err, &ce) && ce.Code() == connect.CodeFailedPrecondition && ce.Meta().Get(metaNotLeader) != "") ||
		(errors.As(err, &oe) && oe.Op == "dial")
}

// fromConnect turns a leader's refusal back into an error with its message.
func fromConnect(err error) error {
	var ce *connect.Error
	if !errors.As(err, &ce) {
		return err
	}
	if ce.Code() == connect.CodeNotFound {
		return fmt.Errorf("%s: %w", ce.Message(), store.ErrNotFound)
	}
	return errors.New(ce.Message())
}

// RemoveMember removes a hub on behalf of a member hub (see Node.RemoveMember).
func (s *JoinServer) RemoveMember(ctx context.Context, req *connect.Request[clusterv1.RemoveMemberRequest]) (*connect.Response[clusterv1.RemoveMemberResponse], error) {
	if !s.node.IsLeader() {
		return nil, s.notLeaderError()
	}
	from, err := s.memberPeer(ctx)
	if err != nil {
		return nil, err
	}
	id := req.Msg.GetNodeId()
	if err := ValidNodeID(id); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	k, err := s.node.removeLocal(ctx, id)
	if err != nil {
		return nil, s.memberError(err)
	}
	s.log.InfoContext(ctx, "hub removal requested by a member", "removed_id", id, "from", from)
	return connect.NewResponse(&clusterv1.RemoveMemberResponse{Revoked: int32(min(k, 1<<30))}), nil //nolint:gosec // bounded
}

// TransferLeadership hands leadership over on behalf of a member hub (see
// Node.TransferLeadership).
func (s *JoinServer) TransferLeadership(ctx context.Context, req *connect.Request[clusterv1.TransferLeadershipRequest]) (*connect.Response[clusterv1.TransferLeadershipResponse], error) {
	if !s.node.IsLeader() {
		return nil, s.notLeaderError()
	}
	if _, err := s.memberPeer(ctx); err != nil {
		return nil, err
	}
	to := req.Msg.GetNodeId()
	if to != "" {
		if err := ValidNodeID(to); err != nil {
			return nil, connect.NewError(connect.CodeInvalidArgument, err)
		}
	}
	if err := s.node.transferLocal(ctx, to); err != nil {
		return nil, s.memberError(err)
	}
	return connect.NewResponse(&clusterv1.TransferLeadershipResponse{}), nil
}

// memberError maps a RemoveMember, TransferLeadership or MigrateSchema
// failure on the leader. Callers are authenticated members, so the message goes back as is.
func (s *JoinServer) memberError(err error) error {
	switch {
	case errors.Is(err, raft.ErrNotLeader):
		return s.notLeaderError()
	case errors.Is(err, store.ErrNotFound):
		return connect.NewError(connect.CodeNotFound, err)
	case errors.Is(err, ErrRemoveLeader), errors.Is(err, ErrLastVoter), errors.Is(err, ErrQuorumAtRisk),
		errors.Is(err, ErrSchemaUnsupported), errors.Is(err, store.ErrSchemaNotNewer), errors.Is(err, store.ErrSchemaTooOld):
		return connect.NewError(connect.CodeFailedPrecondition, err)
	default:
		return connect.NewError(connect.CodeInternal, err)
	}
}
