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
			res, retry, err := n.forward(ctx, nl.LeaderID, nl.LeaderAddr, cmd)
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

// forward sends cmd to the leader. retry is true only when the leader did
// not apply the command: it was not the leader (anymore) or could not be
// dialed. Any other failure may have happened after the command was
// committed, so it is returned and never retried.
func (n *Node) forward(ctx context.Context, leaderID, leaderAddr string, cmd store.Command) (store.Result, bool, error) {
	base := n.agentURL(n.hubURLs(ctx), leaderID, leaderAddr)
	if base == "" {
		return store.Result{}, true, nil
	}
	b, err := store.EncodeCommand(cmd)
	if err != nil {
		return store.Result{}, false, err
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
			return store.Result{}, true, nil
		}
		return store.Result{}, false, fmt.Errorf("cluster: forward %s to the leader %s: %w", cmd.Op(), leaderID, err)
	}
	if msg := resp.Msg.GetErrorMessage(); msg != "" {
		return store.Result{}, false, (&wireError{Kind: resp.Msg.GetErrorKind(), Message: msg}).toError()
	}
	var res store.Result
	if err := json.Unmarshal(resp.Msg.GetResult(), &res); err != nil {
		return store.Result{}, false, fmt.Errorf("cluster: forward %s: decode result: %w", cmd.Op(), err)
	}
	return res, false, nil
}

// newForwardClient is the HTTP client a follower forwards writes with: TLS
// 1.3 to a hub certificate from the CA, presenting this hub's node
// certificate.
func newForwardClient(ca *pki.CA, cert tls.Certificate) *http.Client {
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert())
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, Certificates: []tls.Certificate{cert}},
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
	id, err := peerHubID(ctx)
	if err != nil {
		return nil, err
	}
	if _, member, err := s.node.server(id); err != nil {
		return nil, connect.NewError(connect.CodeUnavailable, errors.New("cannot read the cluster configuration"))
	} else if !member {
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("not a member of this cluster"))
	}
	cmd, err := store.DecodeCommand(req.Msg.GetCommand())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	res, err := s.node.Apply(ctx, cmd)
	var nl *ErrNotLeader
	if errors.As(err, &nl) {
		return nil, s.notLeaderError()
	}
	out := &clusterv1.ForwardResponse{}
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

// peerHubID returns the node ID in the caller's verified hub node
// certificate. Device certificates and callers without one are refused.
func peerHubID(ctx context.Context) (string, error) {
	cs, _ := ctx.Value(tlsStateKey{}).(*tls.ConnectionState)
	if cs == nil || len(cs.VerifiedChains) == 0 {
		return "", connect.NewError(connect.CodeUnauthenticated, errors.New("hub node certificate required"))
	}
	id, err := pki.HubNodeID(cs.VerifiedChains[0][0])
	if err != nil {
		return "", connect.NewError(connect.CodePermissionDenied, errors.New("not a hub node certificate"))
	}
	return id, nil
}
