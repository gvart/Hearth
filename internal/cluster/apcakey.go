// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"connectrpc.com/connect"

	"github.com/gvart/hearth/internal/pki"
	"github.com/gvart/hearth/internal/policy"
	clusterv1 "github.com/gvart/hearth/internal/proto/hearth/cluster/v1"
	"github.com/gvart/hearth/internal/proto/hearth/cluster/v1/clusterv1connect"
	"github.com/gvart/hearth/internal/store"
)

// The CA key of an AP cluster reaches a member promoted to master the way it
// reaches a hub during a CA rotation: the member fetches it from the master
// that promotes it, over that master's ClusterService, with mutual TLS
// pinned to the cluster CA (the member presents its hub node certificate).
// The master hands it out only while it promotes that member (a grant that
// lasts the promotion's call and is used once), as the fixed
// cluster.ca.fetch_key action, audited; a refusal before the decision is
// audited too. The key never travels on the gossip port.

// grantKey lets member id fetch the CA key once, for keyGrantTTL.
func (n *APNode) grantKey(id string) {
	n.grantsMu.Lock()
	defer n.grantsMu.Unlock()
	if n.grants == nil {
		n.grants = map[string]time.Time{}
	}
	n.grants[id] = time.Now().Add(keyGrantTTL)
}

// revokeGrant ends member id's grant, used or not.
func (n *APNode) revokeGrant(id string) {
	n.grantsMu.Lock()
	defer n.grantsMu.Unlock()
	delete(n.grants, id)
}

// takeGrant uses member id's grant: false if it has none.
func (n *APNode) takeGrant(id string) bool {
	n.grantsMu.Lock()
	defer n.grantsMu.Unlock()
	until, ok := n.grants[id]
	delete(n.grants, id)
	return ok && time.Now().Before(until)
}

// errNoGrant refuses the CA key to a member no promotion is under way for.
var errNoGrant = errors.New("no promotion of this member to master is under way here")

// fetchCAKey fetches the CA key from the master at fromURL, pinned to this
// member's CA and authenticated by its hub node certificate.
func (n *APNode) fetchCAKey(ctx context.Context, fromURL string) ([]byte, error) {
	u, err := url.Parse(fromURL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, fmt.Errorf("the promoting master sent no URL to fetch the CA key from (%q)", fromURL)
	}
	caCert := n.cfg.CA.Cert()
	tlsCfg := pki.PinnedTLSConfig(pki.Fingerprint(caCert), u.Hostname())
	cert := n.cert
	tlsCfg.Certificates = []tls.Certificate{cert}
	transport := &http.Transport{TLSClientConfig: tlsCfg}
	defer transport.CloseIdleConnections()
	client := clusterv1connect.NewClusterServiceClient(&http.Client{Transport: transport, Timeout: 30 * time.Second}, u.String())
	resp, err := client.FetchCAKey(ctx, connect.NewRequest(&clusterv1.FetchCAKeyRequest{NewCaFingerprint: pki.FingerprintHex(caCert)}))
	if err != nil {
		return nil, err
	}
	if len(resp.Msg.GetCaKey()) == 0 {
		return nil, errors.New("the master sent no CA key")
	}
	return resp.Msg.GetCaKey(), nil
}

// FetchCAKey hands the CA key to a member this master is promoting to
// master. The caller must present a hub node certificate of the cluster CA,
// not revoked, of a live member, and ask for this CA's key. Every request is
// decided by policy and audited, refusals before the decision included.
func (s *APJoinServer) FetchCAKey(ctx context.Context, req *connect.Request[clusterv1.FetchCAKeyRequest]) (*connect.Response[clusterv1.FetchCAKeyResponse], error) {
	id, err := s.memberPeer(ctx)
	if err != nil {
		s.auditFetchRefused(ctx, err)
		return nil, err
	}
	var keyDER []byte
	err = s.policy.Do(ctx, policy.Request{
		ActorKind: policy.ActorHub,
		ActorID:   id,
		Action:    policy.ClusterCAFetchKey,
		Target:    id,
		Detail:    map[string]any{"ca": req.Msg.GetNewCaFingerprint(), "promotion": true},
	}, func(context.Context) error {
		if req.Msg.GetNewCaFingerprint() != pki.FingerprintHex(s.ca.Cert()) {
			return store.ErrNotFound
		}
		if !s.node.takeGrant(id) {
			return errNoGrant
		}
		var err error
		keyDER, err = s.ca.KeyDER()
		return err
	})
	switch {
	case err == nil:
	case errors.Is(err, store.ErrNotFound):
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("this master serves another CA"))
	case errors.Is(err, errNoGrant):
		return nil, connect.NewError(connect.CodePermissionDenied, err)
	case errors.Is(err, pki.ErrNoCAKey):
		return nil, connect.NewError(connect.CodeFailedPrecondition, err)
	case errors.Is(err, policy.ErrDenied):
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("fetching the CA key denied by policy"))
	default:
		s.log.ErrorContext(ctx, "hand out the CA key to a promoted member", "to", id, "err", err)
		return nil, connect.NewError(connect.CodeInternal, errors.New("fetching the CA key failed"))
	}
	s.log.InfoContext(ctx, "handed the CA key to a member promoted to master", "to", id)
	return connect.NewResponse(&clusterv1.FetchCAKeyResponse{CaKey: keyDER}), nil
}

// memberPeer returns the node ID in the caller's verified hub node
// certificate, when it is a live member's and not revoked.
func (s *APJoinServer) memberPeer(ctx context.Context) (string, error) {
	cs, _ := ctx.Value(tlsStateKey{}).(*tls.ConnectionState)
	if cs == nil || len(cs.VerifiedChains) == 0 {
		return "", connect.NewError(connect.CodeUnauthenticated, errors.New("hub node certificate required"))
	}
	cert := cs.VerifiedChains[0][0]
	id, err := pki.HubNodeID(cert)
	if err != nil {
		return "", connect.NewError(connect.CodePermissionDenied, errors.New("not a hub node certificate"))
	}
	if s.ca.IssuerOf(cert) == nil {
		return "", connect.NewError(connect.CodeUnauthenticated, errors.New("hub node certificate of a CA no longer trusted"))
	}
	if err := s.store.Hubs().CheckCert(ctx, pki.SerialString(cert)); errors.Is(err, store.ErrCertRevoked) {
		return "", connect.NewError(connect.CodePermissionDenied, errors.New("hub node certificate revoked"))
	} else if err != nil {
		return "", connect.NewError(connect.CodeUnavailable, errors.New("cannot check the hub node certificate"))
	}
	if m, err := s.node.member(ctx, id); err != nil || !alive(m) {
		return "", connect.NewError(connect.CodePermissionDenied, errors.New("not a live member of this cluster"))
	}
	return id, nil
}

// auditFetchRefused records a FetchCAKey refused before its policy
// decision, at most one entry per caller a minute (see fetchRefusals).
func (s *APJoinServer) auditFetchRefused(ctx context.Context, refusal error) {
	actor := "unknown"
	detail := map[string]any{"reason": refusal.Error(), "promotion": true}
	if cs, _ := ctx.Value(tlsStateKey{}).(*tls.ConnectionState); cs != nil && len(cs.PeerCertificates) > 0 {
		c := cs.PeerCertificates[0]
		if id, err := pki.HubNodeID(c); err == nil {
			actor = id
		}
		detail["serial"], detail["fingerprint"] = pki.SerialString(c), pki.FingerprintHex(c)
	}
	ok, suppressed := s.fetchRefused.admit(actor, s.now())
	if !ok {
		return
	}
	if suppressed > 0 {
		detail["refusals_not_audited_before"] = suppressed
	}
	b, err := json.Marshal(detail)
	if err != nil {
		return
	}
	if _, err := s.store.Audit().Append(ctx, store.AuditEntry{
		TS: s.now(), ActorKind: policy.ActorHub, ActorID: actor, Action: string(policy.ClusterCAFetchKey),
		Target: actor, Decision: policy.Deny, Result: "refused: " + refusal.Error(), Detail: b,
	}); err != nil {
		s.log.ErrorContext(ctx, "audit a refused CA key fetch", "err", err)
	}
}
