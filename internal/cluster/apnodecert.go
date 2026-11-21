// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"connectrpc.com/connect"

	"github.com/gvart/hearth/internal/pki"
	"github.com/gvart/hearth/internal/policy"
	clusterv1 "github.com/gvart/hearth/internal/proto/hearth/cluster/v1"
	"github.com/gvart/hearth/internal/store"
)

// Node certificate renewal in an AP cluster. A master renews its own hub
// node certificate with the CA key it holds; a member that holds no CA key
// asks a master, over the master's ClusterService with mutual TLS, as it
// fetches the new CA during a rotation (FetchCAKey with a CSR for the
// current CA). The master issues it only to a live, unrevoked member whose
// certificate expires within renewBefore, for the same member and cluster
// epoch, as the fixed cluster.node_cert.renew action, audited.

// loadAPNodeCert is loadOrIssueNodeCert for a member that may hold no CA
// key: such a member keeps its certificate until it expires, and renews it
// through a master while it runs (renewNodeCertIfDue).
func loadAPNodeCert(dir string, ca *pki.CA, nodeID, epoch string, now time.Time) (tls.Certificate, error) {
	if ca.HasKey() {
		return loadOrIssueNodeCert(dir, ca, nodeID, epoch, now)
	}
	cert, err := tls.LoadX509KeyPair(filepath.Join(dir, nodeCertFile), filepath.Join(dir, nodeKeyFile))
	if errors.Is(err, os.ErrNotExist) {
		return tls.Certificate{}, errors.New("no node certificate, and no CA key to issue one: join the cluster again")
	} else if err != nil {
		return tls.Certificate{}, err
	}
	if id, err := pki.HubNodeID(cert.Leaf); err != nil || id != nodeID {
		return tls.Certificate{}, fmt.Errorf("the node certificate is not %s's", nodeID)
	}
	if !now.Before(cert.Leaf.NotAfter) {
		return tls.Certificate{}, errors.New("the node certificate expired, and this member holds no CA key to " +
			"renew it: remove it (`hearth cluster remove`), wipe its data dir and join it again")
	}
	return cert, nil
}

// renewNodeCertIfDue renews this member's node certificate once it expires
// within renewBefore, outside a hub CA rotation (which renews it anyway).
func (n *APNode) renewNodeCertIfDue(ctx context.Context) {
	cur := n.cert.Load()
	if n.st == nil || n.halted.Load() || n.rotationActive() || time.Until(cur.Leaf.NotAfter) > renewBefore {
		return
	}
	if err := n.renewNodeCert(ctx); err != nil && ctx.Err() == nil {
		n.log.WarnContext(ctx, "renew the node certificate; retrying", "expires", cur.Leaf.NotAfter, "err", err)
	}
}

func (n *APNode) renewNodeCert(ctx context.Context) error {
	ca := n.cfg.CA
	key, err := pki.NewKey()
	if err != nil {
		return err
	}
	csr, err := pki.NewCSR(key, n.cfg.NodeID)
	if err != nil {
		return err
	}
	var leaf *x509.Certificate
	if ca.HasKey() {
		if leaf, err = n.issueNodeCert(ctx, csr, n.cfg.NodeID); err != nil {
			return err
		}
	} else {
		var errs []error
		for _, id := range n.masters.Masters() {
			if id == n.cfg.NodeID {
				continue
			}
			base := n.AgentURLOf(ctx, id)
			if base == "" {
				errs = append(errs, fmt.Errorf("%s: its URL is unknown", id))
				continue
			}
			resp, err := n.callFetchCAKey(ctx, base, pki.FingerprintHex(ca.Cert()), csr, nil)
			if err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", id, err))
				continue
			}
			if leaf, err = checkNodeCert(ca.Cert(), resp.GetCertificate(), key, n.cfg.NodeID, n.epoch); err != nil {
				return fmt.Errorf("node certificate from %s: %w", id, err)
			}
			break
		}
		if leaf == nil {
			if len(errs) == 0 {
				return errors.New("no master to renew it")
			}
			return errors.Join(errs...)
		}
	}
	// Written next to the old one, then moved over it: a crash part way is
	// completed when the member starts again (recoverNodeCertFinish), as a
	// rotation's finish is.
	dir := filepath.Join(n.cfg.DataDir, RaftDir)
	if _, err := writeNextNodeCert(dir, leaf, key); err != nil {
		return err
	}
	if err := recoverNodeCertFinish(dir, ca); err != nil {
		return err
	}
	tc, err := tls.LoadX509KeyPair(filepath.Join(dir, nodeCertFile), filepath.Join(dir, nodeKeyFile))
	if err != nil {
		return err
	}
	n.cert.Store(&tc)
	n.log.InfoContext(ctx, "renewed the node certificate", "serial", pki.SerialString(leaf), "expires", leaf.NotAfter)
	return nil
}

// checkNodeCert checks der, a node certificate of ca received for key: hub
// id's, in cluster epoch epoch.
func checkNodeCert(ca *x509.Certificate, der []byte, key crypto.Signer, id, epoch string) (*x509.Certificate, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	if cert.CheckSignatureFrom(ca) != nil {
		return nil, errors.New("not signed by the cluster CA")
	}
	if got, err := pki.HubNodeID(cert); err != nil || got != id {
		return nil, errors.New("issued to another hub")
	}
	if pki.HubEpoch(cert) != epoch {
		return nil, errOtherEpoch
	}
	pub, ok := key.Public().(interface{ Equal(crypto.PublicKey) bool })
	if !ok || !pub.Equal(cert.PublicKey) {
		return nil, errors.New("issued for another key")
	}
	return cert, nil
}

// issueNodeCert signs csr as member id's node certificate of the current
// CA, in this member's epoch, and records it.
func (n *APNode) issueNodeCert(ctx context.Context, csr []byte, id string) (*x509.Certificate, error) {
	ca := n.cfg.CA
	cert, err := ca.SignHubCSRInEpoch(csr, id, n.epoch, time.Now())
	if err != nil {
		return nil, err
	}
	if cert.CheckSignatureFrom(ca.Cert()) != nil {
		return nil, errors.New("the node certificate is not signed by the cluster CA")
	}
	if err := n.st.Hubs().Record(ctx, store.HubCert{
		Serial: pki.SerialString(cert), NodeID: id, Fingerprint: pki.FingerprintHex(cert), CAFP: pki.FingerprintHex(ca.Cert()),
	}); err != nil {
		return nil, fmt.Errorf("record the node certificate of %s: %w", id, err)
	}
	return cert, nil
}

// errNotDue refuses a renewal of a certificate that does not expire soon.
var errNotDue = errors.New("the node certificate does not expire soon")

// renewNodeCert serves FetchCAKey with a CSR outside a rotation: a new node
// certificate of the current CA for a live, unrevoked member whose
// certificate expires within renewBefore.
func (s *APJoinServer) renewNodeCert(ctx context.Context, req *connect.Request[clusterv1.FetchCAKeyRequest],
) (*connect.Response[clusterv1.FetchCAKeyResponse], error) {
	id, cert, err := s.memberPeerCert(ctx)
	switch {
	case err != nil:
	case req.Msg.GetNewCaFingerprint() != pki.FingerprintHex(s.ca.Cert()):
		err = connect.NewError(connect.CodeFailedPrecondition, errors.New("this master serves another CA"))
	case s.node.rotationActive():
		err = connect.NewError(connect.CodeFailedPrecondition, errors.New("a hub CA rotation renews node certificates"))
	case time.Until(cert.NotAfter) > renewBefore:
		err = connect.NewError(connect.CodePermissionDenied, errNotDue)
	}
	if err != nil {
		s.auditFetchRefused(ctx, err, false)
		return nil, err
	}
	var der []byte
	err = s.policy.Do(ctx, policy.Request{
		ActorKind: policy.ActorHub,
		ActorID:   id,
		Action:    policy.ClusterNodeCertRenew,
		Target:    id,
		Detail:    map[string]any{"serial": pki.SerialString(cert), "expires": cert.NotAfter},
	}, func(ctx context.Context) error {
		if !s.ca.HasKey() {
			return pki.ErrNoCAKey
		}
		c, err := s.node.issueNodeCert(ctx, req.Msg.GetCsr(), id)
		if err != nil {
			return err
		}
		der = c.Raw
		return nil
	})
	switch {
	case err == nil:
	case errors.Is(err, pki.ErrNoCAKey):
		return nil, connect.NewError(connect.CodeFailedPrecondition, err)
	case errors.Is(err, policy.ErrDenied):
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("renewing the node certificate denied by policy"))
	default:
		s.log.ErrorContext(ctx, "renew a member's node certificate", "to", id, "err", err)
		return nil, connect.NewError(connect.CodeInternal, errors.New("renewing the node certificate failed"))
	}
	s.log.InfoContext(ctx, "renewed a member's node certificate", "member", id)
	return connect.NewResponse(&clusterv1.FetchCAKeyResponse{Certificate: der}), nil
}
