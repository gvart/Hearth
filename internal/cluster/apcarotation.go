// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import (
	"cmp"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"connectrpc.com/connect"

	"github.com/gvart/hearth/internal/pki"
	"github.com/gvart/hearth/internal/policy"
	clusterv1 "github.com/gvart/hearth/internal/proto/hearth/cluster/v1"
	"github.com/gvart/hearth/internal/proto/hearth/cluster/v1/clusterv1connect"
	"github.com/gvart/hearth/internal/store"
)

// Hub CA rotation in an AP cluster (docs/cluster.md, "Rotating the hub CA").
//
// The rotation is owned by the master that starts it, the origin of the
// replicated ca_rotations row; a master that moves it on while its owner is
// not alive takes it over. RotateCA generates the new CA on the owner and
// records it, without its key, with the fingerprint of the node certificate
// every member presented on the owner's gossip connections (the pins).
// Every member's reconcile loop then trusts both CAs and gets a node
// certificate of the new CA; a master also the new CA's key. Both come from
// a master holding the key, over its ClusterService with mutual TLS
// (FetchCAKey): until the rotation ends, an old-CA hub certificate is
// accepted only if it is the one pinned for its hub, and a member that is no
// master never gets the key. FinishCA cuts over (every member presents, and
// every master serves and seals with, the new CA), re-seals the sealed
// secrets with the new key and finishes: every member drops the old CA and
// every master deletes its key. A member's progress travels on the gossip
// (CAMeta). Each stage is kept in the replicated row and on each member's
// disk, so a restart, of the owner or of any member, resumes it.

// caCutoverFile, in the raft dir, holds the fingerprint of the next CA a
// member cut over to: a master that restarts during the cutover serves and
// seals with it again before anything else runs.
const caCutoverFile = "ca-cutover"

// Errors of the rotation in an AP cluster.
var (
	// ErrRotationOwner refuses to move a rotation on from a master other
	// than its owner while the owner is alive.
	ErrRotationOwner = errors.New("another master drives the hub CA rotation")
)

// keyProofMessage is what a master signs with the current CA key to be
// handed the new one during the rotation to newCAFP: bound to the node
// certificate it presents (certFP), so a proof is no use to another caller.
func keyProofMessage(newCAFP, certFP string) []byte {
	return []byte("hearth ap ca rotation: hand me the new key\x00" + newCAFP + "\x00" + certFP)
}

// shortFP is the gossip form of a CA fingerprint.
func shortFP(fp string) string {
	if len(fp) > 16 {
		return fp[:16]
	}
	return fp
}

// SetCAPolicy sets the policy engine the control socket's hub CA rotation
// commands are decided with; nil while this member is no master.
func (n *APNode) SetCAPolicy(pol *policy.Engine) { n.caPolicy.Store(pol) }

// SetResealer sets the function FinishCA re-seals secrets with. Without one,
// FinishCA refuses to finish while there are sealed secrets.
func (n *APNode) SetResealer(r Resealer) { n.resealer.Store(&r) }

// rotationActive reports whether a hub CA rotation is under way, as this
// member last read it.
func (n *APNode) rotationActive() bool {
	rot := n.rot.Load()
	return rot != nil && rot.Active()
}

// loadRotation reads the latest rotation from the store into n.rot.
func (n *APNode) loadRotation(ctx context.Context) (store.CARotation, bool) {
	rot, err := n.st.CARotations().Latest(ctx)
	if err != nil {
		if !errors.Is(err, store.ErrNotFound) && ctx.Err() == nil {
			n.log.WarnContext(ctx, "read the hub CA rotation", "err", err)
		}
		n.rot.Store(nil)
		return store.CARotation{}, false
	}
	n.rot.Store(&rot)
	return rot, true
}

// checkRotationPin refuses, during a rotation, a hub certificate of the old
// CA other than the one pinned for its hub. A certificate of the new CA was
// issued by a master holding its key, which only pinned members reach.
func (n *APNode) checkRotationPin(cert *x509.Certificate) error {
	rot := n.rot.Load()
	if rot == nil || !rot.Active() {
		return nil
	}
	if issuer := n.cfg.CA.IssuerOf(cert); issuer != nil && pki.FingerprintHex(issuer) == rot.NewCAFP {
		return nil
	}
	if id, err := pki.HubNodeID(cert); err == nil && rot.Pins[id] == pki.FingerprintHex(cert) {
		return nil
	}
	return errNotPinned
}

// resumeCutover, at start, serves the next CA again if this member cut
// over to it before it stopped (caCutoverFile): the cutover is past the
// point an abort can undo, and a master must not seal a secret, nor present
// a certificate, of the old CA until the reconcile loop runs.
func (n *APNode) resumeCutover() {
	ca, next := n.cfg.CA, n.cfg.CA.Next()
	b, err := os.ReadFile(filepath.Join(n.cfg.DataDir, RaftDir, caCutoverFile))
	nextCert := n.nextCert.Load()
	if err != nil || next == nil || nextCert == nil || strings.TrimSpace(string(b)) != pki.FingerprintHex(next) {
		return
	}
	if err := ca.TrustNext(next); err != nil {
		n.log.Error("trust the new hub CA", "err", err)
		return
	}
	if err := ca.Cutover(); err != nil {
		n.log.Error("serve the new hub CA", "err", err)
		return
	}
	n.cert.Store(nextCert)
	n.log.Info("serving the new hub CA: the rotation is at its cutover")
}

// kickCA makes the reconcile loop run soon.
func (n *APNode) kickCA() {
	select {
	case n.caKick <- struct{}{}:
	default:
	}
}

// runCA reconciles this member's CA with the rotation until ctx ends.
func (n *APNode) runCA(ctx context.Context) {
	t := time.NewTicker(n.cfg.CAReconcileEvery)
	defer t.Stop()
	n.reconcileCA(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-n.caKick:
		}
		n.reconcileCA(ctx)
		n.renewNodeCertIfDue(ctx)
	}
}

// localCAMeta is this member's side of a rotation.
func (n *APNode) localCAMeta() CAMeta {
	ca := n.cfg.CA
	m := CAMeta{
		Serving: shortFP(pki.FingerprintHex(ca.Cert())), NextKey: ca.HasNextKey(),
		NextCert: n.nextCert.Load() != nil, CutOver: ca.CutOver(),
	}
	if next := ca.Next(); next != nil {
		m.Next = shortFP(pki.FingerprintHex(next))
	}
	return m
}

// publishCA puts this member's side of a rotation on the gossip.
func (n *APNode) publishCA() {
	if m := n.membership; m != nil {
		m.SetCA(n.localCAMeta())
	}
}

// reconcileCA brings this member's CA, and the node certificate it
// presents, to the stage of the replicated rotation. It is idempotent; a
// failed step is retried on the next run.
func (n *APNode) reconcileCA(ctx context.Context) {
	n.recMu.Lock()
	defer n.recMu.Unlock()
	defer n.publishCA()
	if n.halted.Load() || n.st == nil {
		return
	}
	ca := n.cfg.CA
	rot, ok := n.loadRotation(ctx)
	if !ok {
		n.dropLeftoverNext(ctx)
		return
	}
	next := ca.Next()
	switch {
	case rot.Stage == store.CAStageAborted && next != nil && pki.FingerprintHex(next) == rot.NewCAFP:
		if err := n.dropNextLocal(ctx); err != nil {
			n.log.ErrorContext(ctx, "drop the CA of the aborted rotation", "err", err)
		}
		return
	case rot.Stage == store.CAStageFinished && next == nil && pki.FingerprintHex(ca.Cert()) == rot.NewCAFP:
		return // finished here
	case rot.Stage == store.CAStageFinished:
		n.finishLocal(ctx, rot)
		return
	case !rot.Active():
		n.dropLeftoverNext(ctx)
		return
	}
	newCA, err := pki.ParseCertPEM([]byte(rot.NewCACert))
	if err != nil || pki.FingerprintHex(newCA) != rot.NewCAFP {
		n.log.ErrorContext(ctx, "the hub CA rotation's certificate does not match its fingerprint", "err", err)
		return
	}
	if next != nil && pki.FingerprintHex(next) != rot.NewCAFP {
		// A next CA of an attempt that did not start, or of a rotation that
		// lost to this one.
		n.dropLeftoverNext(ctx)
		if ca.Next() != nil {
			return
		}
	}
	// A connection opened before the rotation by a certificate other than
	// the pinned one (minted with a stolen old key) does not outlive it.
	if closed := n.unpinnedClosed.Load(); closed == nil || *closed != rot.NewCAFP {
		if k := n.membership.closeRevoked(func(c *x509.Certificate) bool {
			return errors.Is(n.checkRotationPin(c), errNotPinned)
		}); k > 0 {
			n.log.WarnContext(ctx, "closed gossip connections of hub certificates this rotation did not pin", "count", k)
		}
		fp := rot.NewCAFP
		n.unpinnedClosed.Store(&fp)
	}
	if err := ca.TrustNext(newCA); err != nil {
		n.log.ErrorContext(ctx, "trust the new hub CA", "err", err)
		return
	}
	master := n.IsMaster()
	if n.nextCert.Load() == nil || (master && !ca.HasNextKey()) {
		if err := n.obtainNext(ctx, rot); err != nil {
			if ctx.Err() == nil {
				n.log.WarnContext(ctx, "fetch the new hub CA; retrying", "err", err)
			}
			return
		}
	}
	nextCert := n.nextCert.Load()
	if rot.Stage != store.CAStageCutover || ca.CutOver() || nextCert == nil || (master && !ca.HasNextKey()) {
		return
	}
	if master {
		// Kept on disk first: once serving the new CA, a master that
		// restarts must not seal with the old key again.
		if err := writeFileSync(filepath.Join(n.cfg.DataDir, RaftDir, caCutoverFile), []byte(rot.NewCAFP+"\n"), 0o600); err != nil {
			n.log.ErrorContext(ctx, "record the cutover to the new hub CA", "err", err)
			return
		}
	}
	if err := ca.Cutover(); err != nil {
		n.log.ErrorContext(ctx, "cut over to the new hub CA", "err", err)
		return
	}
	n.cert.Store(nextCert)
	n.log.InfoContext(ctx, "presenting the new hub CA's node certificate", "master", master)
}

// dropLeftoverNext drops a next CA that no rotation under way uses: one
// whose start was never recorded, or whose rotation was aborted, or that
// lost to a rotation started at once on another master (the owner aborts
// that one). It skips a run while RotateCA, FinishCA or AbortCA runs.
func (n *APNode) dropLeftoverNext(ctx context.Context) {
	if n.cfg.CA.Next() == nil || !n.rotMu.TryLock() {
		return
	}
	defer n.rotMu.Unlock()
	n.dropLeftoverNextLocked(ctx)
}

// dropLeftoverNextLocked is dropLeftoverNext with rotMu held.
func (n *APNode) dropLeftoverNextLocked(ctx context.Context) {
	next := n.cfg.CA.Next()
	if next == nil {
		return
	}
	fp := pki.FingerprintHex(next)
	rot, err := n.st.CARotations().Get(ctx, fp)
	switch {
	case errors.Is(err, store.ErrNotFound):
		if n.cfg.CA.NextActive() || n.cfg.CA.CutOver() {
			return // trusted: its rotation started, the row is still on its way
		}
		err = n.dropNextLocal(ctx)
	case err != nil:
	case rot.Stage == store.CAStageAborted:
		err = n.dropNextLocal(ctx)
	case rot.Stage == store.CAStageFinished:
		n.finishLocal(ctx, rot)
	case rot.Owner == n.cfg.NodeID && rot.Stage == store.CAStageStarted:
		// Two masters started a rotation at once: the latest one stands,
		// and the owner of the other aborts it.
		n.log.WarnContext(ctx, "aborting a hub CA rotation another one started at once overtook", "new_ca", fp)
		if err = n.st.CARotations().Advance(ctx, fp, store.CAStageStarted, store.CAStageAborted, time.Now()); err == nil {
			_, _ = n.st.CARotations().RevokeCerts(ctx, fp, time.Now())
			err = n.dropNextLocal(ctx)
		}
	}
	if err != nil && ctx.Err() == nil {
		n.log.WarnContext(ctx, "drop a leftover next CA; retrying", "err", err)
	}
}

// dropNextLocal forgets this member's next CA and its node certificate of
// it.
func (n *APNode) dropNextLocal(ctx context.Context) error {
	if err := n.cfg.CA.DropNext(); err != nil {
		return fmt.Errorf("drop the next CA: %w", err)
	}
	dir := filepath.Join(n.cfg.DataDir, RaftDir)
	for _, f := range []string{nextNodeCertFile, nextNodeKeyFile, caCutoverFile} {
		if err := os.Remove(filepath.Join(dir, f)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("drop the node certificate of the next CA: %w", err)
		}
	}
	n.nextCert.Store(nil)
	n.log.InfoContext(ctx, "dropped a next hub CA of a rotation that did not happen")
	return nil
}

// obtainNext gets this member's node certificate of the new CA and, on a
// master, the new CA's key: a master holding the key issues its own; the
// others fetch them from a master holding it, the owner first.
func (n *APNode) obtainNext(ctx context.Context, rot store.CARotation) error {
	ca := n.cfg.CA
	key, err := pki.NewKey()
	if err != nil {
		return err
	}
	csr, err := pki.NewCSR(key, n.cfg.NodeID)
	if err != nil {
		return err
	}
	master := n.IsMaster()
	if master && ca.HasNextKey() {
		cert, err := n.issueNextNodeCert(ctx, csr, n.cfg.NodeID)
		if err != nil {
			return err
		}
		return n.saveNextCert(cert, key)
	}
	masters := n.masters.Masters()
	slices.SortStableFunc(masters, func(a, b string) int {
		switch {
		case a == rot.Owner:
			return -1
		case b == rot.Owner:
			return 1
		}
		return 0
	})
	var errs []error
	for _, id := range masters {
		if id == n.cfg.NodeID {
			continue
		}
		base := n.AgentURLOf(ctx, id)
		if base == "" {
			errs = append(errs, fmt.Errorf("%s: its URL is unknown", id))
			continue
		}
		var proof []byte
		if master && !ca.HasNextKey() {
			// What a member says of its roles is its own word: a master
			// proves it holds the current CA key.
			if proof, err = ca.ProveKey(rot.OldCAFP, keyProofMessage(rot.NewCAFP, pki.FingerprintHex(n.cert.Load().Leaf))); err != nil {
				return fmt.Errorf("prove the CA key: %w", err)
			}
		}
		resp, err := n.callFetchCAKey(ctx, base, rot.NewCAFP, csr, proof)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", id, err))
			continue
		}
		if master && !ca.HasNextKey() {
			if len(resp.GetCaKey()) == 0 {
				errs = append(errs, fmt.Errorf("%s sent no CA key", id))
				continue
			}
			if err := ca.InstallNextKey(resp.GetCaKey()); err != nil {
				return fmt.Errorf("install the new CA key from %s: %w", id, err)
			}
			n.log.InfoContext(ctx, "fetched the new hub CA key", "from", id)
		}
		if der := resp.GetCertificate(); len(der) > 0 {
			cert, err := checkNextNodeCert(ca, der, key, n.cfg.NodeID, n.epoch)
			if err != nil {
				return fmt.Errorf("node certificate from %s: %w", id, err)
			}
			return n.saveNextCert(cert, key)
		}
		errs = append(errs, fmt.Errorf("%s sent no node certificate", id))
	}
	if len(errs) == 0 {
		return errors.New("no master to fetch the new CA from")
	}
	return errors.Join(errs...)
}

// callFetchCAKey asks the master at base for a node certificate of the CA
// caFP for csr (and, with proof, a key proof of the current CA key, the CA's
// key), over mutual TLS: the master must present a certificate of a CA this
// member trusts.
func (n *APNode) callFetchCAKey(ctx context.Context, base, caFP string, csr, proof []byte) (*clusterv1.FetchCAKeyResponse, error) {
	u, err := url.Parse(base)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, fmt.Errorf("not a master URL: %q", base)
	}
	tlsCfg := pki.PinnedAnyTLSConfig(n.cfg.CA.TrustedCerts(), u.Hostname())
	tlsCfg.Certificates = []tls.Certificate{*n.cert.Load()}
	transport := &http.Transport{TLSClientConfig: tlsCfg}
	defer transport.CloseIdleConnections()
	client := clusterv1connect.NewClusterServiceClient(&http.Client{Transport: transport, Timeout: caInfoTimeout}, u.String())
	resp, err := client.FetchCAKey(ctx, connect.NewRequest(&clusterv1.FetchCAKeyRequest{
		NewCaFingerprint: caFP, Csr: csr, OldCaKeyProof: proof,
	}))
	if err != nil {
		return nil, err
	}
	return resp.Msg, nil
}

// issueNextNodeCert signs csr as member id's node certificate of the new
// CA and records it, so removing the member revokes it. Only a master
// holding the new CA's key issues one.
func (n *APNode) issueNextNodeCert(ctx context.Context, csr []byte, id string) (*x509.Certificate, error) {
	ca := n.cfg.CA
	next := ca.Next()
	if next == nil || !ca.HasNextKey() || !ca.NextActive() {
		return nil, pki.ErrNoNextCA
	}
	cert, err := ca.SignHubCSRInEpoch(csr, id, n.epoch, time.Now())
	if err != nil {
		return nil, err
	}
	if cert.CheckSignatureFrom(next) != nil {
		return nil, errors.New("the node certificate is not signed by the new CA")
	}
	if err := n.st.Hubs().Record(ctx, store.HubCert{
		Serial: pki.SerialString(cert), NodeID: id, Fingerprint: pki.FingerprintHex(cert), CAFP: pki.FingerprintHex(next),
	}); err != nil {
		return nil, fmt.Errorf("record the node certificate of %s: %w", id, err)
	}
	return cert, nil
}

// saveNextCert keeps this member's node certificate of the new CA, on disk
// and for the cutover.
func (n *APNode) saveNextCert(cert *x509.Certificate, key any) error {
	tc, err := writeNextNodeCert(filepath.Join(n.cfg.DataDir, RaftDir), cert, key)
	if err != nil {
		return err
	}
	n.nextCert.Store(tc)
	n.log.Info("holding a node certificate of the new hub CA", "serial", pki.SerialString(cert))
	return nil
}

// finishLocal ends the rotation rot on this member: the next CA becomes its
// only one (a master deletes the old key) and the node certificate of the
// new CA replaces the old one. Open connections of old-CA certificates are
// closed: a handshake checks a certificate only once. A member that missed
// the rotation stops taking part (missedRotation).
func (n *APNode) finishLocal(ctx context.Context, rot store.CARotation) {
	ca := n.cfg.CA
	nextCert := n.nextCert.Load()
	if ca.Next() == nil && nextCert != nil {
		// A member without the CA key keeps the next CA in memory only: it
		// restarted since, with its node certificate of it on disk.
		if newCA, err := pki.ParseCertPEM([]byte(rot.NewCACert)); err == nil &&
			nextCert.Leaf != nil && nextCert.Leaf.CheckSignatureFrom(newCA) == nil {
			_ = ca.TrustNext(newCA)
		}
	}
	next := ca.Next()
	if next == nil || pki.FingerprintHex(next) != rot.NewCAFP || nextCert == nil || (ca.HasKey() && !ca.HasNextKey()) {
		n.missedRotation(ctx, rot)
		return
	}
	if err := ca.Finish(); err != nil {
		n.log.ErrorContext(ctx, "finish the hub CA rotation", "err", err)
		return
	}
	dir := filepath.Join(n.cfg.DataDir, RaftDir)
	if err := recoverNodeCertFinish(dir, ca); err != nil {
		n.log.ErrorContext(ctx, "replace the node certificate with the new CA's", "err", err)
	}
	_ = os.Remove(filepath.Join(dir, caCutoverFile))
	n.cert.Store(nextCert)
	n.nextCert.Store(nil)
	k := n.membership.closeRevoked(func(c *x509.Certificate) bool { return ca.IssuerOf(c) == nil })
	n.log.InfoContext(ctx, "finished the hub CA rotation here: the old CA is no longer trusted", "closed_connections", k)
}

// missedRotation ends a member the rotation rot finished without: the new
// CA becomes its only CA, without a key, every CA key file of it is
// deleted, and it stops taking part. It never presents the old CA again.
func (n *APNode) missedRotation(ctx context.Context, rot store.CARotation) {
	if !n.halted.CompareAndSwap(false, true) {
		return
	}
	n.log.ErrorContext(ctx, errMissedRotation.Error())
	newCA, err := pki.ParseCertPEM([]byte(rot.NewCACert))
	if err == nil {
		err = n.cfg.CA.Abandon(newCA)
	}
	if err != nil {
		n.log.ErrorContext(ctx, "drop the old hub CA", "err", err)
	}
	dir := filepath.Join(n.cfg.DataDir, RaftDir)
	for _, f := range []string{nextNodeCertFile, nextNodeKeyFile, caCutoverFile} {
		_ = os.Remove(filepath.Join(dir, f))
	}
	n.nextCert.Store(nil)
	k := n.membership.closeRevoked(func(*x509.Certificate) bool { return true })
	n.log.ErrorContext(ctx, "stopped taking part in the cluster: closed every gossip connection", "closed_connections", k)
}

// rotationMembers are the members a rotation covers: every member not
// removed, this one included. A member stopped (left) or down takes part as
// well: it is not cut off without being removed first.
func (n *APNode) rotationMembers() []MemberInfo {
	return n.membership.Members()
}

// livePins returns, for every member, the fingerprint of the node
// certificate it presents: this member's own, and the one each other member
// presented on the gossip connections this member dialed to it. Every
// member must be alive. A presented certificate that is revoked, or not the
// one recorded for its serial, refuses the rotation; one not recorded at
// all is returned in unpinned.
func (n *APNode) livePins(ctx context.Context) (map[string]string, []store.UnpinnedCert, error) {
	pins := map[string]string{}
	var (
		unpinned []store.UnpinnedCert
		problems []string
	)
	for _, m := range n.rotationMembers() {
		var cert *x509.Certificate
		if m.ID == n.cfg.NodeID {
			cert = n.cert.Load().Leaf
		} else {
			if m.State != MemberAlive {
				problems = append(problems, fmt.Sprintf("%s (%s)", m.ID, m.State))
				continue
			}
			var fps []string
			for _, c := range n.membership.PeerCerts(m.ID) {
				if !slices.Contains(fps, pki.FingerprintHex(c)) {
					fps = append(fps, pki.FingerprintHex(c))
					cert = c
				}
			}
			switch {
			case len(fps) == 0:
				problems = append(problems, m.ID+" (no gossip connection to it yet: try again shortly)")
				continue
			case len(fps) > 1:
				problems = append(problems, m.ID+" (it presented different certificates)")
				continue
			}
		}
		fp, serial := pki.FingerprintHex(cert), pki.SerialString(cert)
		recorded, err := n.st.Hubs().Certs(ctx, m.ID)
		if err != nil {
			return nil, nil, err
		}
		i := slices.IndexFunc(recorded, func(c store.HubCert) bool { return c.Serial == serial })
		switch {
		case i < 0 || recorded[i].Fingerprint == "":
			unpinned = append(unpinned, store.UnpinnedCert{Kind: "hub", ID: m.ID, Serial: serial})
			continue
		case recorded[i].Revoked:
			problems = append(problems, m.ID+" (its certificate is revoked)")
			continue
		case recorded[i].Fingerprint != fp:
			problems = append(problems, m.ID+" (it presented a certificate other than the one recorded for its serial)")
			continue
		}
		pins[m.ID] = fp
	}
	if len(problems) > 0 {
		return nil, nil, fmt.Errorf("rotate the hub CA: every member must take part: %s; "+
			"bring them back, or remove a member that is gone for good", strings.Join(problems, ", "))
	}
	return pins, unpinned, nil
}

// RotateCA starts a hub CA rotation owned by this master. No rotation may be
// under way, and every member must be alive and present a pinned node
// certificate. The caller makes the policy decision.
func (n *APNode) RotateCA(ctx context.Context, opts RotateOptions) (RotatePlan, error) {
	if !n.IsMaster() {
		return RotatePlan{}, ErrNotMasterHere
	}
	n.rotMu.Lock()
	defer n.rotMu.Unlock()
	switch _, err := n.st.CARotations().Active(ctx); {
	case err == nil:
		return RotatePlan{}, fmt.Errorf("rotate the hub CA: %w; finish or abort it first (`hearth cluster ca finish|abort`)",
			store.ErrCARotationActive)
	case !errors.Is(err, store.ErrNotFound):
		return RotatePlan{}, err
	}
	unpinned, err := n.st.CARotations().Unpinned(ctx)
	if err != nil {
		return RotatePlan{}, err
	}
	pins, hubs, err := n.livePins(ctx)
	if err != nil {
		return RotatePlan{}, err
	}
	for _, h := range hubs {
		if !slices.Contains(unpinned, h) {
			unpinned = append(unpinned, h)
		}
	}
	plan := RotatePlan{Pins: pins, Unpinned: unpinned}
	if len(hubs) > 0 {
		return plan, fmt.Errorf("rotate the hub CA: %w: %s. A member presenting a certificate without a recorded "+
			"fingerprint is never given the new CA, --accept-unpinned or not: restart it so it records its "+
			"node certificate, or remove it", ErrUnpinnedCerts, describeUnpinned(hubs))
	}
	if len(unpinned) > 0 && !opts.AcceptUnpinned {
		return plan, fmt.Errorf("rotate the hub CA: %w: %s. Their holders would not be renewed; "+
			"reconnect those agents (a master records an agent's certificate when it connects), or revoke them, "+
			"or pass --accept-unpinned to rotate anyway and cut them off when the rotation finishes",
			ErrUnpinnedCerts, describeUnpinned(unpinned))
	}
	if opts.DryRun {
		return plan, nil
	}
	ca := n.cfg.CA
	if !ca.HasKey() {
		return plan, fmt.Errorf("rotate the hub CA: %w", pki.ErrNoCAKey)
	}
	if ca.Next() != nil {
		n.dropLeftoverNextLocked(ctx)
		if ca.Next() != nil {
			return plan, fmt.Errorf("rotate the hub CA: %w: this master still holds the CA of an earlier attempt",
				store.ErrCARotationActive)
		}
	}
	now := time.Now()
	next, err := ca.GenerateNext(now)
	if err != nil {
		return plan, fmt.Errorf("rotate the hub CA: %w", err)
	}
	plan.NewCAFP = pki.FingerprintHex(next)
	err = n.st.CARotations().Start(ctx, store.CARotation{
		NewCAFP: plan.NewCAFP, OldCAFP: pki.FingerprintHex(ca.Cert()), NewCACert: string(pki.EncodeCertPEM(next)), Pins: pins,
	}, now)
	if err != nil {
		if _, gerr := n.st.CARotations().Get(ctx, plan.NewCAFP); gerr != nil {
			// Not recorded here: the start did not happen.
			if dropErr := ca.DropNext(); dropErr != nil {
				n.log.ErrorContext(ctx, "drop the next CA of a rotation that did not start", "err", dropErr)
			}
			return plan, fmt.Errorf("rotate the hub CA: %w", err)
		}
		// Recorded here, not yet on enough replicas: they get it later.
		n.log.WarnContext(ctx, "the hub CA rotation started, but not every replica took it yet", "err", err)
	}
	if err := ca.TrustNext(next); err != nil {
		n.log.ErrorContext(ctx, "trust the new hub CA", "err", err)
	}
	n.loadRotation(ctx)
	n.log.InfoContext(ctx, "started a hub CA rotation", "new_ca", plan.NewCAFP)
	n.kickCA()
	return plan, nil
}

// activeOwned returns the rotation under way, refusing it while another
// master that is alive owns it.
func (n *APNode) activeOwned(ctx context.Context) (store.CARotation, error) {
	rot, err := n.st.CARotations().Active(ctx)
	if errors.Is(err, store.ErrNotFound) {
		return store.CARotation{}, ErrNoRotation
	} else if err != nil {
		return store.CARotation{}, err
	}
	if rot.Owner != "" && rot.Owner != n.cfg.NodeID && n.masters.Live(rot.Owner) {
		where := ""
		if u := n.AgentURLOf(ctx, rot.Owner); u != "" {
			where = " (" + u + ")"
		}
		return rot, fmt.Errorf("%w: master %s started it and is alive: run the command on its host%s",
			ErrRotationOwner, rot.Owner, where)
	}
	return rot, nil
}

// FinishCA finishes the rotation under way: once every member holds a node
// certificate of the new CA (and every master its key), it cuts over,
// re-seals the sealed secrets with the new key, and finishes, after which
// no member trusts the old CA and no master holds its key. It refuses with
// ErrOldCAHolders while agents or members still hold only old-CA
// certificates, unless forced. A finish that stopped part way is resumed by
// running it again, on the owner or, while the owner is not alive, on any
// master holding the new key. The caller makes the policy decision.
func (n *APNode) FinishCA(ctx context.Context, opts FinishOptions) (FinishPlan, error) {
	if !n.IsMaster() {
		return FinishPlan{}, ErrNotMasterHere
	}
	n.rotMu.Lock()
	defer n.rotMu.Unlock()
	rot, err := n.activeOwned(ctx)
	if err != nil {
		return FinishPlan{NewCAFP: rot.NewCAFP}, err
	}
	plan := FinishPlan{NewCAFP: rot.NewCAFP}
	if !n.cfg.CA.HasNextKey() {
		msg := "this master does not hold the new CA's key yet; try again shortly"
		if rot.Owner != "" && rot.Owner != n.cfg.NodeID {
			msg = fmt.Sprintf("this master does not hold the new CA's key, and %s, which started the rotation, is not "+
				"alive: bring it back, or give the rotation up (`hearth cluster ca abort`)", rot.Owner)
		}
		return plan, errors.New("finish the hub CA rotation: " + msg)
	}
	if plan.OldDevices, err = n.st.CARotations().OldCADevices(ctx, rot.NewCAFP); err != nil {
		return plan, err
	}
	var members []MemberInfo
	for _, m := range n.rotationMembers() {
		certs, err := n.st.Hubs().Certs(ctx, m.ID)
		if err != nil {
			return plan, err
		}
		if slices.ContainsFunc(certs, func(c store.HubCert) bool { return !c.Revoked && c.CAFP == rot.NewCAFP }) {
			members = append(members, m)
		} else {
			plan.OldHubs = append(plan.OldHubs, m.ID)
		}
	}
	if (len(plan.OldDevices) > 0 || len(plan.OldHubs) > 0) && !opts.Force {
		return plan, fmt.Errorf("finish the hub CA rotation: %w: %s. Agents renew when they connect; members as soon "+
			"as they are back. Check `hearth cluster ca status`, or pass --force to cut them off: an agent then has "+
			"to enroll again, a member to join again", ErrOldCAHolders, describeOld(plan.OldDevices, plan.OldHubs))
	}
	if opts.DryRun {
		return plan, nil
	}
	short := shortFP(rot.NewCAFP)
	if rot.Stage == store.CAStageStarted {
		if err := n.waitMembers(ctx, members, "hold a node certificate of the new CA (and, a master, its key)",
			func(m MemberInfo, c CAMeta) bool {
				return c.Next == short && c.NextCert && (c.NextKey || !m.Roles.Has(RoleMaster))
			}); err != nil {
			return plan, err
		}
		if err := n.st.CARotations().Advance(ctx, rot.NewCAFP, store.CAStageStarted, store.CAStageCutover, time.Now()); err != nil {
			return plan, fmt.Errorf("move the hub CA rotation to %s: %w", store.CAStageCutover, err)
		}
		n.log.InfoContext(ctx, "hub CA rotation moved on", "stage", store.CAStageCutover)
	}
	n.reconcileCA(ctx)
	// Every master seals with the new key once it cut over; until then one
	// could seal a secret with the old key after the re-seal.
	if err := n.waitMembers(ctx, members, "present the new CA", func(_ MemberInfo, c CAMeta) bool {
		return c.Next == short && c.CutOver
	}); err != nil {
		return plan, err
	}
	if plan.Resealed, err = n.resealSecrets(ctx, rot.NewCAFP); err != nil {
		return plan, err
	}
	if err := n.st.CARotations().Finish(ctx, rot.NewCAFP, "", time.Now()); err != nil {
		return plan, fmt.Errorf("move the hub CA rotation to %s: %w", store.CAStageFinished, err)
	}
	n.log.InfoContext(ctx, "hub CA rotation moved on", "stage", store.CAStageFinished)
	n.reconcileCA(ctx)
	n.log.InfoContext(ctx, "finished the hub CA rotation", "new_ca", rot.NewCAFP, "resealed", plan.Resealed,
		"cut_off_devices", len(plan.OldDevices), "cut_off_hubs", len(plan.OldHubs))
	return plan, nil
}

// waitMembers waits until every one of members says, on the gossip, what
// ready accepts; this member answers for itself.
func (n *APNode) waitMembers(ctx context.Context, members []MemberInfo, what string, ready func(MemberInfo, CAMeta) bool) error {
	deadline := time.Now().Add(caMemberWait)
	for {
		now := map[string]MemberInfo{}
		for _, m := range n.membership.Members() {
			now[m.ID] = m
		}
		var waiting, gone []string
		for _, m := range members {
			cur, ok := now[m.ID]
			var c CAMeta
			switch {
			case m.ID == n.cfg.NodeID:
				c = n.localCAMeta()
			case !ok || cur.CA == nil:
			default:
				c = *cur.CA
			}
			switch {
			case m.ID != n.cfg.NodeID && ok && (cur.State == MemberDead || cur.State == MemberLeft):
				gone = append(gone, m.ID)
				continue
			case !ok || (m.ID != n.cfg.NodeID && cur.State != MemberAlive):
				waiting = append(waiting, fmt.Sprintf("%s (%s)", m.ID, cmp.Or(cur.State, "unknown")))
				continue
			}
			if !ready(cur, c) {
				waiting = append(waiting, m.ID)
			}
		}
		if len(gone) > 0 {
			// No point waiting: a member down takes part again only once it
			// is back.
			return fmt.Errorf("finish the hub CA rotation: these members are down: %s; bring them back and run "+
				"the finish again, or remove a member that is gone for good (`hearth cluster remove`)",
				strings.Join(gone, ", "))
		}
		if len(waiting) == 0 {
			return nil
		}
		if !time.Now().Before(deadline) {
			return fmt.Errorf("finish the hub CA rotation: these members did not %s within %s: %s; "+
				"run the finish again once they are back, or remove a member that is gone for good",
				what, caMemberWait, strings.Join(waiting, ", "))
		}
		n.kickCA()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(min(n.cfg.CAReconcileEvery/2, time.Second)):
		}
	}
}

// resealSecrets re-seals every secret still sealed with the old key, one
// at a time, until a check finds none left. It returns how many it
// re-sealed.
func (n *APNode) resealSecrets(ctx context.Context, newCAFP string) (int, error) {
	rp := n.resealer.Load()
	total := 0
	for attempt := 0; ; attempt++ {
		secrets, err := n.st.CARotations().Sealed(ctx)
		if err != nil {
			return total, fmt.Errorf("finish the hub CA rotation: read sealed secrets: %w", err)
		}
		if len(secrets) == 0 {
			return total, nil
		}
		if rp == nil {
			return total, errors.New("finish the hub CA rotation: this master cannot re-seal secrets")
		}
		stale, err := (*rp)(ctx, secrets)
		if err != nil {
			return total, fmt.Errorf("finish the hub CA rotation: re-seal secrets: %w", err)
		}
		if len(stale) == 0 {
			return total, nil
		}
		if attempt == 5 {
			return total, errors.New("finish the hub CA rotation: secrets kept changing while they were re-sealed; try again")
		}
		for _, sec := range stale {
			err := n.st.CARotations().Reseal(ctx, newCAFP, []store.SealedSecret{sec})
			switch {
			case errors.Is(err, store.ErrCARotationConflict):
				continue // changed since it was read: checked again
			case err != nil:
				return total, fmt.Errorf("finish the hub CA rotation: re-seal secrets: %w", err)
			}
			total++
		}
	}
}

// AbortCA gives up the rotation under way before its cutover: every member
// drops the new CA, its key and its node certificate of it, and what the
// new CA issued is revoked. It is the way out when the new key was lost,
// say because the owner died before another master fetched it: any master
// may abort while the owner is not alive. After the cutover it refuses:
// finish the rotation instead. The caller makes the policy decision.
func (n *APNode) AbortCA(ctx context.Context, opts AbortOptions) (AbortPlan, error) {
	if !n.IsMaster() {
		return AbortPlan{}, ErrNotMasterHere
	}
	n.rotMu.Lock()
	defer n.rotMu.Unlock()
	rot, err := n.activeOwned(ctx)
	if err != nil {
		return AbortPlan{NewCAFP: rot.NewCAFP}, err
	}
	plan := AbortPlan{NewCAFP: rot.NewCAFP}
	if rot.Stage != store.CAStageStarted {
		return plan, fmt.Errorf("abort the hub CA rotation: %w: every member presents the new CA already; "+
			"finish it (`hearth cluster ca finish`)", store.ErrCARotationConflict)
	}
	if plan.RenewedDevices, err = n.st.CARotations().RenewedDevices(ctx, rot.NewCAFP); err != nil {
		return plan, err
	}
	if opts.DryRun {
		return plan, nil
	}
	now := time.Now()
	if err := n.st.CARotations().Advance(ctx, rot.NewCAFP, store.CAStageStarted, store.CAStageAborted, now); err != nil {
		return plan, fmt.Errorf("move the hub CA rotation to %s: %w", store.CAStageAborted, err)
	}
	// Nothing trusts the aborted CA any more; its certificates are revoked
	// too, on every shard. A shard down now keeps them unrevoked, but
	// untrusted.
	if _, err := n.st.CARotations().RevokeCerts(ctx, rot.NewCAFP, now); err != nil {
		n.log.WarnContext(ctx, "revoke the device certificates of the aborted hub CA", "err", err)
	}
	n.reconcileCA(ctx)
	n.log.InfoContext(ctx, "aborted the hub CA rotation", "new_ca", rot.NewCAFP, "cut_off_devices", len(plan.RenewedDevices))
	return plan, nil
}

// CAStatus reports the latest rotation, every member's side of it, and the
// devices it would still cut off.
func (n *APNode) CAStatus(ctx context.Context) (CAStatus, error) {
	var st CAStatus
	rot, err := n.st.CARotations().Latest(ctx)
	switch {
	case err == nil:
		st.Rotation = &rot
	case !errors.Is(err, store.ErrNotFound):
		return st, err
	}
	if st.Rotation != nil && st.Rotation.Active() {
		if st.OldDevices, err = n.st.CARotations().OldCADevices(ctx, rot.NewCAFP); err != nil {
			return st, err
		}
	}
	for _, m := range n.rotationMembers() {
		h := HubCAInfo{ID: m.ID}
		c := m.CA
		if m.ID == n.cfg.NodeID {
			local := n.localCAMeta()
			c = &local
		}
		switch {
		case m.State != MemberAlive && m.ID != n.cfg.NodeID:
			h.Error = m.State
		case c == nil:
			h.Error = "it says nothing of the hub CA yet"
		default:
			h.Info = CAInfo{ServingFP: c.Serving, NextFP: c.Next, HasNextKey: c.NextKey, HasNextCert: c.NextCert, CutOver: c.CutOver}
		}
		st.Hubs = append(st.Hubs, h)
	}
	return st, nil
}

// fetchNextCA serves FetchCAKey during a rotation: a node certificate of the
// new CA for the caller's CSR and, to a caller that proves it holds the
// current CA key (a master), the new CA's key. The caller must be a live
// member presenting its pinned node certificate, or one of the new CA. What
// a member says of its roles on the gossip is not taken for it: a storage
// member never holds the key, so it cannot prove it. Every request is
// decided by policy and audited, refusals before the decision included.
func (s *APJoinServer) fetchNextCA(ctx context.Context, req *connect.Request[clusterv1.FetchCAKeyRequest], rot store.CARotation,
) (*connect.Response[clusterv1.FetchCAKeyResponse], error) {
	id, cert, err := s.memberPeerCert(ctx)
	if err == nil && s.node.checkRotationPin(cert) != nil {
		err = connect.NewError(connect.CodePermissionDenied, errNotPinned)
	}
	wantKey := len(req.Msg.GetOldCaKeyProof()) > 0
	if err == nil && wantKey {
		if err = verifyKeyProof(s.ca, rot, cert, req.Msg.GetOldCaKeyProof()); err != nil {
			err = connect.NewError(connect.CodePermissionDenied, err)
		}
	}
	if err != nil {
		s.auditFetchRefused(ctx, err, false)
		return nil, err
	}
	var keyDER, certDER []byte
	err = s.policy.Do(ctx, policy.Request{
		ActorKind: policy.ActorHub,
		ActorID:   id,
		Action:    policy.ClusterCAFetchKey,
		Target:    id,
		Detail:    map[string]any{"new_ca": rot.NewCAFP, "certificate": len(req.Msg.GetCsr()) > 0, "key": wantKey},
	}, func(ctx context.Context) error {
		next := s.ca.Next()
		if next == nil || pki.FingerprintHex(next) != rot.NewCAFP || !s.ca.HasNextKey() {
			return errNoNextKey
		}
		if err := s.ca.TrustNext(next); err != nil {
			return err
		}
		if wantKey {
			var err error
			if keyDER, err = s.ca.NextKeyDER(); err != nil {
				return err
			}
		}
		if len(req.Msg.GetCsr()) > 0 {
			c, err := s.node.issueNextNodeCert(ctx, req.Msg.GetCsr(), id)
			if err != nil {
				return err
			}
			certDER = c.Raw
		}
		return nil
	})
	switch {
	case err == nil:
	case errors.Is(err, errNoNextKey):
		return nil, connect.NewError(connect.CodeFailedPrecondition, err)
	case errors.Is(err, policy.ErrDenied):
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("fetching the CA key denied by policy"))
	default:
		s.log.ErrorContext(ctx, "hand out the new hub CA", "to", id, "err", err)
		return nil, connect.NewError(connect.CodeInternal, errors.New("fetching the CA key failed"))
	}
	s.log.InfoContext(ctx, "handed out the new hub CA", "to", id, "key", keyDER != nil, "certificate", certDER != nil)
	return connect.NewResponse(&clusterv1.FetchCAKeyResponse{CaKey: keyDER, Certificate: certDER}), nil
}

// verifyKeyProof checks proof, by a caller presenting cert, of the key of the
// CA rot replaces.
func verifyKeyProof(ca *pki.CA, rot store.CARotation, cert *x509.Certificate, proof []byte) error {
	for _, c := range ca.TrustedCerts() {
		if pki.FingerprintHex(c) == rot.OldCAFP {
			return pki.VerifyKeyProof(c, keyProofMessage(rot.NewCAFP, pki.FingerprintHex(cert)), proof)
		}
	}
	return pki.ErrBadKeyProof
}
