// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"connectrpc.com/connect"
	"github.com/hashicorp/raft"

	"github.com/gvart/hearth/internal/pki"
	clusterv1 "github.com/gvart/hearth/internal/proto/hearth/cluster/v1"
	"github.com/gvart/hearth/internal/proto/hearth/cluster/v1/clusterv1connect"
	"github.com/gvart/hearth/internal/store"
)

const (
	// defaultForwardWait bounds how long ApplyOrForward waits for a leader
	// it can reach before it gives up with store.ErrUnavailable.
	defaultForwardWait = 5 * time.Second
	forwardRetry       = 100 * time.Millisecond
	// appliedWait bounds how long a follower waits, after the leader applied
	// a forwarded write, to apply it itself (see ApplyOrForward).
	appliedWait = 2 * time.Second
	appliedPoll = 5 * time.Millisecond
)

// BindForwarding is Bind for a hub that serves users: the store's writes go
// through ApplyOrForward, so they work on a follower too. Pass it to
// store.Open with store.WithApplier(node.BindForwarding).
func (n *Node) BindForwarding(s *store.Store) store.Applier {
	n.store = s
	return store.ApplierFunc(n.ApplyOrForward)
}

// ApplyOrForward applies cmd like Apply on the leader. On a follower it sends
// cmd to the leader's ClusterService.Forward, authenticated with this hub's
// node certificate, and returns the leader's result. While no leader is known
// or reachable it retries for a few seconds, then fails with
// store.ErrUnavailable; the command was then not applied.
//
// A forwarded write is read-your-writes: once the leader answered, the
// follower waits, for at most two seconds or until ctx is done, until it has
// applied the entry to its own store, so the caller's next local read sees
// it (a session the user just logged in with, a token just created). If that
// wait runs out, the leader's result is returned anyway: the write is
// committed and the follower applies it shortly.
//
// Forwarding is replication, not a new decision: the caller made the policy
// decision and wrote (or will write) its audit entry through this same path,
// on the hub that received the user's request.
func (n *Node) ApplyOrForward(ctx context.Context, cmd store.Command) (store.Result, error) {
	deadline := time.Now().Add(n.cfg.ForwardWait)
	for {
		res, err := n.Apply(ctx, cmd)
		var nl *ErrNotLeader
		if !errors.As(err, &nl) {
			return res, err
		}
		if nl.LeaderID != "" && nl.LeaderID != n.cfg.NodeID {
			res, retry, err := n.forwardWrite(ctx, nl.LeaderID, nl.LeaderAddr, cmd)
			if !retry {
				return res, err
			}
		}
		if !time.Now().Before(deadline) {
			return store.Result{}, fmt.Errorf("cluster: %s: no leader reachable within %s: %w",
				cmd.Op(), n.cfg.ForwardWait, store.ErrUnavailable)
		}
		select {
		case <-ctx.Done():
			return store.Result{}, ctx.Err()
		case <-time.After(forwardRetry):
		}
	}
}

// forwardWrite forwards cmd and waits to apply it here. While it waits the
// entry counts as this node's own write, so observers do not react to it a
// second time when the caller reacts to the returned result.
func (n *Node) forwardWrite(ctx context.Context, leaderID, leaderAddr string, cmd store.Command) (store.Result, bool, error) {
	b, err := store.EncodeCommand(cmd)
	if err != nil {
		return store.Result{}, false, err
	}
	n.fsm.writes.begin(b)
	res, index, retry, err := n.forward(ctx, leaderID, leaderAddr, cmd)
	if !retry {
		n.waitApplied(ctx, cmd, index)
	}
	claimed, wasClaimed := n.fsm.writes.end(b)
	if err != nil && wasClaimed {
		// The answer was lost, but the entry was applied here and observers
		// were told it is this caller's.
		return claimed, false, nil
	}
	return res, retry, err
}

// waitApplied waits, bounded by appliedWait and ctx, until this node's
// store has applied the log entry at index. Zero means there is nothing to
// wait for: the leader did not apply the command, or predates the field.
func (n *Node) waitApplied(ctx context.Context, cmd store.Command, index uint64) {
	if index == 0 || n.appliedThrough(index) {
		return
	}
	timer := time.NewTimer(appliedWait)
	defer timer.Stop()
	tick := time.NewTicker(appliedPoll)
	defer tick.Stop()
	for !n.appliedThrough(index) {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			n.log.WarnContext(ctx, "forwarded write not applied locally in time; a read right after it may not see it yet",
				"op", cmd.Op(), "index", index, "applied", n.fsm.applied.Load(), "waited", appliedWait)
			return
		case <-tick.C:
		}
	}
}

// appliedThrough reports whether this node's store reflects every log entry
// up to index. Raft's AppliedIndex alone does not say so: it moves when
// entries are handed to the state machine, before they are applied. Entries
// that are not commands (no-ops, barriers, configuration changes) never
// reach the store, so the state machine's own index may stay below index
// for good; only command entries after it are waited for.
func (n *Node) appliedThrough(index uint64) bool {
	if n.raft.AppliedIndex() < index {
		return false
	}
	for i := index; i > n.fsm.applied.Load(); i-- {
		var l raft.Log
		err := n.bolt.GetLog(i, &l)
		switch {
		case errors.Is(err, raft.ErrLogNotFound):
			// Compacted into a snapshot this node took or installed, so
			// at or before what its state machine applied.
			return true
		case err != nil:
			return false
		case l.Type == raft.LogCommand:
			return false
		}
	}
	return true
}

// forward sends cmd to the leader and returns its result and the log index
// it applied the command at. retry is true only when the leader did not
// apply the command: it was not the leader (anymore) or could not be
// dialed. Any other failure may have happened after the command was
// committed, so it is returned and never retried.
func (n *Node) forward(ctx context.Context, leaderID, leaderAddr string, cmd store.Command) (store.Result, uint64, bool, error) {
	base := n.agentURL(n.hubURLs(ctx), leaderID, leaderAddr)
	if base == "" {
		return store.Result{}, 0, true, nil
	}
	b, err := store.EncodeCommand(cmd)
	if err != nil {
		return store.Result{}, 0, false, err
	}
	client := clusterv1connect.NewClusterServiceClient(n.fwdHTTP, base)
	resp, err := client.Forward(ctx, connect.NewRequest(&clusterv1.ForwardRequest{Command: b}))
	if err != nil {
		var (
			ce *connect.Error
			oe *net.OpError
		)
		if (errors.As(err, &ce) && ce.Code() == connect.CodeFailedPrecondition) ||
			(errors.As(err, &oe) && oe.Op == "dial") {
			n.log.DebugContext(ctx, "forward to the leader failed; retrying", "op", cmd.Op(), "leader_id", leaderID, "err", err)
			return store.Result{}, 0, true, nil
		}
		return store.Result{}, 0, false, fmt.Errorf("cluster: forward %s to the leader %s: %w", cmd.Op(), leaderID, err)
	}
	index := resp.Msg.GetIndex()
	if msg := resp.Msg.GetErrorMessage(); msg != "" {
		return store.Result{}, index, false, (&wireError{Kind: resp.Msg.GetErrorKind(), Message: msg}).toError()
	}
	var res store.Result
	if err := json.Unmarshal(resp.Msg.GetResult(), &res); err != nil {
		return store.Result{}, index, false, fmt.Errorf("cluster: forward %s: decode result: %w", cmd.Op(), err)
	}
	return res, index, false, nil
}

// newForwardClient is the HTTP client a follower forwards writes with: TLS
// 1.3 to a hub certificate from the CA and of this hub's cluster epoch,
// presenting this hub's node certificate.
func newForwardClient(ca *pki.CA, cert tls.Certificate, epoch string) *http.Client {
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert())
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS13, RootCAs: pool, Certificates: []tls.Certificate{cert},
				VerifyConnection: requireEpoch(epoch),
			},
			ForceAttemptHTTP2: true,
		},
		Timeout: applyTimeout + 5*time.Second,
	}
}

// Forward applies a command a follower could not propose itself. Only the
// leader serves it, and only to a cluster member presenting its hub node
// certificate. It makes no policy decision and writes no audit entry: the
// follower's hub already did both for the user's request, through this same
// forwarding path.
func (s *JoinServer) Forward(ctx context.Context, req *connect.Request[clusterv1.ForwardRequest]) (*connect.Response[clusterv1.ForwardResponse], error) {
	if !s.node.IsLeader() {
		return nil, s.notLeaderError()
	}
	id, err := s.memberPeer(ctx)
	if err != nil {
		return nil, err
	}
	cmd, err := store.DecodeCommand(req.Msg.GetCommand())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	res, index, err := s.node.apply(ctx, cmd)
	var nl *ErrNotLeader
	if errors.As(err, &nl) {
		return nil, s.notLeaderError()
	}
	out := &clusterv1.ForwardResponse{Index: index}
	if err != nil {
		we := toWireError(err)
		if we.Kind == "" {
			s.log.WarnContext(ctx, "forwarded apply failed", "op", cmd.Op(), "from", id, "err", err)
		}
		out.ErrorKind, out.ErrorMessage = we.Kind, we.Message
		return connect.NewResponse(out), nil
	}
	if out.Result, err = json.Marshal(res); err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("encode result: %w", err))
	}
	return connect.NewResponse(out), nil
}

// memberPeer is peerHubID for a caller that must also be in the Raft
// configuration.
func (s *JoinServer) memberPeer(ctx context.Context) (string, error) {
	id, err := s.peerHubID(ctx)
	if err != nil {
		return "", err
	}
	if _, member, err := s.node.server(id); err != nil {
		return "", connect.NewError(connect.CodeUnavailable, errors.New("cannot read the cluster configuration"))
	} else if !member {
		return "", connect.NewError(connect.CodePermissionDenied, errors.New("not a member of this cluster"))
	}
	return id, nil
}

// peerHubID returns the node ID in the caller's verified hub node
// certificate. Device certificates, revoked hub certificates and callers
// without a certificate are refused.
func (s *JoinServer) peerHubID(ctx context.Context) (string, error) {
	cs, _ := ctx.Value(tlsStateKey{}).(*tls.ConnectionState)
	if cs == nil || len(cs.VerifiedChains) == 0 {
		return "", connect.NewError(connect.CodeUnauthenticated, errors.New("hub node certificate required"))
	}
	cert := cs.VerifiedChains[0][0]
	id, err := pki.HubNodeID(cert)
	if err != nil {
		return "", connect.NewError(connect.CodePermissionDenied, errors.New("not a hub node certificate"))
	}
	if err := s.node.checkPeerCert(cert); errors.Is(err, store.ErrCertRevoked) {
		return "", connect.NewError(connect.CodePermissionDenied, errors.New("hub node certificate revoked"))
	} else if err != nil {
		s.log.WarnContext(ctx, "check hub node certificate", "from", id, "err", err)
		return "", connect.NewError(connect.CodeUnavailable, errors.New("cannot check the hub node certificate"))
	}
	return id, nil
}
