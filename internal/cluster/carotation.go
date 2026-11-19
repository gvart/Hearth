// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"
	"github.com/hashicorp/raft"

	"github.com/gvart/hearth/internal/pki"
	clusterv1 "github.com/gvart/hearth/internal/proto/hearth/cluster/v1"
	"github.com/gvart/hearth/internal/proto/hearth/cluster/v1/clusterv1connect"
	"github.com/gvart/hearth/internal/store"
)

// Hub CA rotation (docs/cluster.md, "Rotating the hub CA").
//
// RotateCA, on the leader, generates a new CA and proposes it, without its
// key, with the fingerprint of the node certificate each member presented
// on the leader's own Raft connections to it (the pins). Each hub then
// trusts both CAs and fetches the new key, and a node certificate of the new
// CA, from the leader over the cluster's mTLS channel (FetchCAKey): until
// the rotation finishes, a hub presenting an old-CA certificate is accepted
// only with exactly its pinned one, so a certificate minted with a stolen
// old key gets nothing. FinishCA cuts over (every hub serves the new CA),
// re-seals the sealed secrets with the new key, and finishes: every hub
// drops the old CA and deletes its key.

// Files of this hub's node certificate of the new CA, in the raft dir.
const (
	nextNodeCertFile = "node.next.crt"
	nextNodeKeyFile  = "node.next.key"
)

// Timing of the rotation.
const (
	// caMemberWait bounds how long FinishCA waits for every hub to reach
	// a stage.
	caMemberWait = 2 * time.Minute
	// caInfoTimeout bounds one CAInfo or FetchCAKey call.
	caInfoTimeout = 5 * time.Second
	// caFinishTimeout bounds a finish over the control socket: two waits
	// for every hub, and the re-seal.
	caFinishTimeout = 3*caMemberWait + time.Minute
)

// Errors of the rotation.
var (
	// errRotationViaLog refuses the rotation's commands through Apply,
	// ApplyOrForward, Forward and the control socket.
	errRotationViaLog = errors.New("hub CA rotation commands are proposed only by `hearth cluster ca`")
	// ErrUnpinnedCerts refuses a rotation while a certificate it could not
	// renew safely is in use, unless the operator accepts that.
	ErrUnpinnedCerts = errors.New("certificates a rotation cannot renew safely")
	// ErrOldCAHolders refuses to finish a rotation while an agent or hub
	// still holds only old-CA certificates, unless forced.
	ErrOldCAHolders = errors.New("agents or hubs would be cut off")
	// ErrNoRotation is returned when finishing with no rotation under way.
	ErrNoRotation = errors.New("no hub CA rotation is under way")
	// errNotPinned refuses an old-CA hub certificate other than the one
	// pinned for its hub during a rotation.
	errNotPinned = errors.New("not the hub certificate pinned for this rotation")
)

// isRotationCommand reports whether cmd is a command only the rotation
// proposes.
func isRotationCommand(cmd store.Command) bool {
	switch cmd.(type) {
	case store.StartCARotation, store.AdvanceCARotation, store.ResealSecrets:
		return true
	}
	return false
}

// Resealer returns the secrets among secrets that are not sealed with the
// newest CA key yet, each with Resealed set to it sealed with that key. It
// fails if any secret cannot be opened.
type Resealer func(ctx context.Context, secrets []store.SealedSecret) ([]store.SealedSecret, error)

// SetResealer sets the function FinishCA re-seals secrets with. Without one,
// FinishCA refuses to finish while there are sealed secrets.
func (n *Node) SetResealer(r Resealer) { n.resealer.Store(&r) }

// RotateOptions are the options of RotateCA.
type RotateOptions struct {
	// AcceptUnpinned starts the rotation although some certificates have
	// no pinned fingerprint or a recorded mismatch: their holders are not
	// renewed and are cut off when the rotation finishes. It never covers a
	// hub presenting a certificate without a recorded fingerprint.
	AcceptUnpinned bool
	// DryRun checks and plans, and changes nothing.
	DryRun bool
}

// RotatePlan is what RotateCA did or would do.
type RotatePlan struct {
	// NewCAFP is the new CA's fingerprint; empty for a dry run.
	NewCAFP string
	// Pins are the node certificate fingerprints pinned per hub.
	Pins map[string]string
	// Unpinned are the certificates the rotation cannot renew.
	Unpinned []store.UnpinnedCert
}

// RotateCA starts a hub CA rotation. Only the leader rotates: elsewhere it
// fails with *ErrNotLeader. The cluster must be at store.CARotationSchema,
// with no rotation under way, and every hub in the configuration reachable.
// The caller makes the policy decision.
func (n *Node) RotateCA(ctx context.Context, opts RotateOptions) (RotatePlan, error) {
	if !n.IsLeader() {
		return RotatePlan{}, n.notLeader()
	}
	n.rotMu.Lock()
	defer n.rotMu.Unlock()
	if err := n.requireRotationSchema(ctx); err != nil {
		return RotatePlan{}, err
	}
	switch _, err := n.store.CARotations().Active(ctx); {
	case err == nil:
		return RotatePlan{}, fmt.Errorf("rotate the hub CA: %w; finish it first (`hearth cluster ca finish`)", store.ErrCARotationActive)
	case !errors.Is(err, store.ErrNotFound):
		return RotatePlan{}, err
	}
	unpinned, err := n.store.CARotations().Unpinned(ctx)
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
		// --accept-unpinned never covers a member presenting an unrecorded
		// certificate: it would get the new key.
		return plan, fmt.Errorf("rotate the hub CA: %w: %s. A hub presenting a certificate without a recorded "+
			"fingerprint is never given the new key, --accept-unpinned or not: restart it so it records its "+
			"node certificate, or remove it", ErrUnpinnedCerts, describeUnpinned(hubs))
	}
	if len(unpinned) > 0 && !opts.AcceptUnpinned {
		return plan, fmt.Errorf("rotate the hub CA: %w: %s. Their holders would not be renewed; "+
			"reconnect those agents (a hub records an agent's certificate when it connects), or revoke them, "+
			"or pass --accept-unpinned to rotate anyway and cut them off when the rotation finishes",
			ErrUnpinnedCerts, describeUnpinned(unpinned))
	}
	if opts.DryRun {
		return plan, nil
	}
	ca := n.cfg.CA
	if ca.Next() != nil {
		// A next CA of an attempt whose start may still commit: drop it
		// only once the log shows it did not.
		if err := n.dropUncommittedNext(ctx); err != nil {
			return plan, fmt.Errorf("rotate the hub CA: %w", err)
		}
		if ca.Next() != nil {
			return plan, fmt.Errorf("rotate the hub CA: %w", store.ErrCARotationActive)
		}
	}
	now := time.Now()
	next, err := ca.GenerateNext(now)
	if err != nil {
		return plan, fmt.Errorf("rotate the hub CA: %w", err)
	}
	plan.NewCAFP = pki.FingerprintHex(next)
	pinsJSON, err := json.Marshal(pins)
	if err == nil {
		_, _, err = n.propose(ctx, store.StartCARotation{
			NewCAFP: plan.NewCAFP, OldCAFP: pki.FingerprintHex(ca.Cert()),
			NewCACert: string(pki.EncodeCertPEM(next)), Pins: string(pinsJSON), Now: now.UnixMilli(),
		})
		if n.rotateProposed != nil {
			err = n.rotateProposed(err)
		}
		if err != nil && !notProposed(err) {
			// The start may still commit (a lost leadership, a timeout),
			// and the new key is its only copy. The reconcile loop drops
			// it once the log shows the rotation did not start.
			n.log.WarnContext(ctx, "the hub CA rotation may or may not have started; keeping its key", "err", err)
			n.kickCA()
			return plan, fmt.Errorf("rotate the hub CA: %w; check `hearth cluster ca status` before trying again", err)
		}
	}
	if err != nil {
		if dropErr := ca.DropNext(); dropErr != nil {
			n.log.ErrorContext(ctx, "drop the next CA of a rotation that did not start", "err", dropErr)
		}
		return plan, fmt.Errorf("rotate the hub CA: %w", err)
	}
	// The start committed: the new CA is trusted and signs from now on.
	if err := ca.TrustNext(next); err != nil {
		n.log.ErrorContext(ctx, "trust the new hub CA", "err", err)
	}
	n.log.InfoContext(ctx, "started a hub CA rotation", "new_ca", plan.NewCAFP)
	n.kickCA()
	return plan, nil
}

// notProposed reports whether err, from proposing a command, proves the
// command never reached the log: this hub was not the leader when it tried,
// or the context ended before it did. Any other failure (a lost leadership,
// a timeout) may still commit.
func notProposed(err error) bool {
	var nl *ErrNotLeader
	return errors.As(err, &nl) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

// dropUncommittedNext drops this hub's next CA, and its node certificate of
// it, once the log shows no rotation to it can still start: on the leader,
// after a barrier, which applies every earlier entry, the latest rotation is
// another one or was aborted. Elsewhere it does nothing. The caller holds
// rotMu, so no RotateCA is between generating a CA and proposing it.
func (n *Node) dropUncommittedNext(ctx context.Context) error {
	next := n.cfg.CA.Next()
	if next == nil || !n.IsLeader() {
		return nil
	}
	timeout := applyTimeout
	if dl, ok := ctx.Deadline(); ok {
		timeout = time.Until(dl)
	}
	if err := n.raft.Barrier(timeout).Error(); err != nil {
		return fmt.Errorf("wait for the log to settle: %w", err)
	}
	rot, err := n.store.CARotations().Latest(ctx)
	switch {
	case errors.Is(err, store.ErrNotFound):
	case err != nil:
		return err
	case rot.NewCAFP == pki.FingerprintHex(next) && rot.Stage != store.CAStageAborted:
		return nil // it started after all
	}
	return n.dropNextLocal(ctx)
}

// dropNextLocal forgets this hub's next CA and its node certificate of it.
func (n *Node) dropNextLocal(ctx context.Context) error {
	if err := n.cfg.CA.DropNext(); err != nil {
		return fmt.Errorf("drop the next CA: %w", err)
	}
	for _, f := range []string{nextNodeCertFile, nextNodeKeyFile} {
		if err := os.Remove(filepath.Join(n.dir, f)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("drop the node certificate of the next CA: %w", err)
		}
	}
	n.nextCert.Store(nil)
	n.log.InfoContext(ctx, "dropped a next hub CA of a rotation that did not happen")
	return nil
}

// AbortOptions are the options of AbortCA.
type AbortOptions struct {
	// DryRun checks and plans, and changes nothing.
	DryRun bool
}

// AbortPlan is what AbortCA did or would do.
type AbortPlan struct {
	NewCAFP string
	// RenewedDevices were handed a certificate of the new CA: the abort
	// cuts them off, and they enroll again.
	RenewedDevices []string
}

// AbortCA gives up the rotation under way before its cutover: every hub
// drops the new CA, its key and its node certificate of it, and hubs can
// join again. It is the way out when the new key was lost, say because the
// leader that made it died before another hub fetched it. After the cutover
// it refuses: finish the rotation instead. Only the leader aborts; elsewhere
// it fails with *ErrNotLeader. The caller makes the policy decision.
func (n *Node) AbortCA(ctx context.Context, opts AbortOptions) (AbortPlan, error) {
	if !n.IsLeader() {
		return AbortPlan{}, n.notLeader()
	}
	n.rotMu.Lock()
	defer n.rotMu.Unlock()
	if err := n.requireRotationSchema(ctx); err != nil {
		return AbortPlan{}, err
	}
	rot, err := n.store.CARotations().Active(ctx)
	if errors.Is(err, store.ErrNotFound) {
		return AbortPlan{}, ErrNoRotation
	} else if err != nil {
		return AbortPlan{}, err
	}
	plan := AbortPlan{NewCAFP: rot.NewCAFP}
	if rot.Stage != store.CAStageStarted {
		return plan, fmt.Errorf("abort the hub CA rotation: %w: every hub serves the new CA already; "+
			"finish it (`hearth cluster ca finish`)", store.ErrCARotationConflict)
	}
	if plan.RenewedDevices, err = n.store.CARotations().RenewedDevices(ctx, rot.NewCAFP); err != nil {
		return plan, err
	}
	if opts.DryRun {
		return plan, nil
	}
	if err := n.advanceCA(ctx, rot.NewCAFP, store.CAStageStarted, store.CAStageAborted); err != nil {
		return plan, err
	}
	n.reconcileCA(ctx)
	n.log.InfoContext(ctx, "aborted the hub CA rotation", "new_ca", rot.NewCAFP,
		"cut_off_devices", len(plan.RenewedDevices))
	return plan, nil
}

func (n *Node) requireRotationSchema(ctx context.Context) error {
	if !n.store.AtSchema(ctx, store.CARotationSchema) {
		return fmt.Errorf("a hub CA rotation needs store schema %d: %w; run `hearth cluster migrate` first",
			store.CARotationSchema, store.ErrSchemaTooOld)
	}
	return nil
}

func describeUnpinned(certs []store.UnpinnedCert) string {
	parts := make([]string, 0, len(certs))
	for _, c := range certs {
		why := "no recorded fingerprint"
		if c.Mismatch {
			why = "another certificate was presented with its serial"
		}
		parts = append(parts, fmt.Sprintf("%s %s (serial %s: %s)", c.Kind, c.ID, c.Serial, why))
	}
	return strings.Join(parts, ", ")
}

// livePins returns, for every hub in the configuration, the fingerprint of
// the node certificate it presents: this hub's own, and the one each other
// hub presented on the Raft connections this hub dialed to it. Every hub
// must also answer CAInfo, which shows it is live and runs a hearth that
// rotates. A presented certificate that is revoked, or not the one recorded
// for its serial, refuses the rotation; one not recorded at all is returned
// in unpinned.
func (n *Node) livePins(ctx context.Context) (map[string]string, []store.UnpinnedCert, error) {
	servers, err := n.servers()
	if err != nil {
		return nil, nil, err
	}
	pins := map[string]string{}
	var (
		unpinned []store.UnpinnedCert
		problems []string
	)
	for _, s := range servers {
		id := string(s.ID)
		var cert *x509.Certificate
		if id == n.cfg.NodeID {
			cert = n.stream.currentCert().Leaf
		} else {
			if _, err := n.hubCAInfo(ctx, id, string(s.Address)); err != nil {
				problems = append(problems, fmt.Sprintf("%s (cannot ask it: %v)", id, err))
				continue
			}
			var fps []string
			for _, c := range n.stream.dialedPeers(string(s.Address)) {
				if peer, err := pki.HubNodeID(c); err == nil && peer == id && !slices.Contains(fps, pki.FingerprintHex(c)) {
					fps = append(fps, pki.FingerprintHex(c))
					cert = c
				}
			}
			switch {
			case len(fps) == 0:
				problems = append(problems, id+" (no Raft connection to it: wait until it is in sync)")
				continue
			case len(fps) > 1:
				problems = append(problems, id+" (it presented different certificates)")
				continue
			}
		}
		fp, serial := pki.FingerprintHex(cert), pki.SerialString(cert)
		recorded, err := n.store.Hubs().Certs(ctx, id)
		if err != nil {
			return nil, nil, err
		}
		i := slices.IndexFunc(recorded, func(c store.HubCert) bool { return c.Serial == serial })
		switch {
		case i < 0 || recorded[i].Fingerprint == "":
			// Never pinned: a pin is a recorded fingerprint, so the hub
			// could not prove which certificate is its own.
			unpinned = append(unpinned, store.UnpinnedCert{Kind: "hub", ID: id, Serial: serial})
			continue
		case recorded[i].Revoked:
			problems = append(problems, id+" (its certificate is revoked)")
			continue
		case recorded[i].Fingerprint != "" && recorded[i].Fingerprint != fp:
			problems = append(problems, id+" (it presented a certificate other than the one recorded for its serial)")
			continue
		}
		pins[id] = fp
	}
	if len(problems) > 0 {
		return nil, nil, fmt.Errorf("rotate the hub CA: every hub must take part: %s; "+
			"bring them back, or remove a hub that is gone for good", strings.Join(problems, ", "))
	}
	return pins, unpinned, nil
}

func (n *Node) servers() ([]raft.Server, error) {
	if n.raft == nil {
		return nil, errors.New("cluster: node not started")
	}
	cf := n.raft.GetConfiguration()
	if err := cf.Error(); err != nil {
		return nil, fmt.Errorf("read the cluster configuration: %w", err)
	}
	return cf.Configuration().Servers, nil
}

// checkRotationPin refuses, during a rotation, a hub certificate of the old
// CA other than the one pinned for its hub. A certificate of the new CA was
// issued by a hub holding its key, which only pinned hubs could fetch.
func (n *Node) checkRotationPin(ctx context.Context, cert *x509.Certificate) error {
	rot, err := n.store.CARotations().Active(ctx)
	switch {
	case errors.Is(err, store.ErrNotFound) || errors.Is(err, store.ErrSchemaTooOld):
		return nil
	case err != nil:
		return err
	}
	if issuer := n.cfg.CA.IssuerOf(cert); issuer != nil && pki.FingerprintHex(issuer) == rot.NewCAFP {
		return nil
	}
	if id, err := pki.HubNodeID(cert); err == nil && rot.Pins[id] == pki.FingerprintHex(cert) {
		return nil
	}
	return errNotPinned
}

// CAInfo is a hub's side of a rotation.
type CAInfo struct {
	ServingFP   string
	NextFP      string
	HasNextKey  bool
	HasNextCert bool
	CutOver     bool
}

func (n *Node) localCAInfo() CAInfo {
	ca := n.cfg.CA
	info := CAInfo{
		ServingFP: pki.FingerprintHex(ca.Cert()), HasNextKey: ca.HasNextKey(),
		HasNextCert: n.nextCert.Load() != nil, CutOver: ca.CutOver(),
	}
	if next := ca.Next(); next != nil {
		info.NextFP = pki.FingerprintHex(next)
	}
	return info
}

// hubCAInfo asks hub id for its side of a rotation; this hub answers itself.
func (n *Node) hubCAInfo(ctx context.Context, id, addr string) (CAInfo, error) {
	return n.hubCAInfoServedBy(ctx, id, addr, "")
}

// hubCAInfoServedBy is hubCAInfo over a connection on which hub id shows a
// server certificate of the CA caFP, unless caFP is empty: a hub cannot
// claim to serve the new CA without serving it.
func (n *Node) hubCAInfoServedBy(ctx context.Context, id, addr, caFP string) (CAInfo, error) {
	if id == n.cfg.NodeID {
		return n.localCAInfo(), nil
	}
	hc := n.fwdHTTP
	if caFP != "" {
		hc = newForwardClientServedBy(n.cfg.CA, n.stream.currentCert, n.epoch, caFP)
		defer hc.CloseIdleConnections()
	}
	c, err := n.memberClientWith(ctx, hc, id, addr)
	if err != nil {
		return CAInfo{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, caInfoTimeout)
	defer cancel()
	resp, err := c.CAInfo(ctx, connect.NewRequest(&clusterv1.CAInfoRequest{}))
	if err != nil {
		var ce *connect.Error
		if errors.As(err, &ce) && ce.Code() == connect.CodeUnimplemented {
			return CAInfo{}, errors.New("its hearth predates hub CA rotation; upgrade it first")
		}
		return CAInfo{}, err
	}
	m := resp.Msg
	return CAInfo{
		ServingFP: m.GetServingCaFingerprint(), NextFP: m.GetNextCaFingerprint(), HasNextKey: m.GetHasNextKey(),
		HasNextCert: m.GetHasNextNodeCertificate(), CutOver: m.GetCutOver(),
	}, nil
}

func (n *Node) memberClient(ctx context.Context, id, addr string) (clusterv1connect.ClusterServiceClient, error) {
	return n.memberClientWith(ctx, n.fwdHTTP, id, addr)
}

func (n *Node) memberClientWith(ctx context.Context, hc *http.Client, id, addr string) (clusterv1connect.ClusterServiceClient, error) {
	base := n.agentURL(n.hubURLs(ctx), id, addr)
	if base == "" {
		return nil, errors.New("its URL is unknown")
	}
	return clusterv1connect.NewClusterServiceClient(hc, base), nil
}

// CAStatus is the state of the latest rotation and each hub's side of it.
type CAStatus struct {
	// Rotation is the latest rotation; nil when there has been none.
	Rotation *store.CARotation
	Hubs     []HubCAInfo
	// OldDevices are the devices still on the old CA during a rotation.
	OldDevices []string
}

// HubCAInfo is one hub's side of a rotation, or why it is unknown.
type HubCAInfo struct {
	ID    string
	Info  CAInfo
	Error string `json:",omitempty"`
}

// CAStatus reports the latest rotation, every hub's side of it, and the
// devices it would still cut off.
func (n *Node) CAStatus(ctx context.Context) (CAStatus, error) {
	if err := n.requireRotationSchema(ctx); err != nil {
		return CAStatus{}, err
	}
	var st CAStatus
	rot, err := n.store.CARotations().Latest(ctx)
	switch {
	case err == nil:
		st.Rotation = &rot
	case !errors.Is(err, store.ErrNotFound):
		return st, err
	}
	if st.Rotation != nil && st.Rotation.Active() {
		if st.OldDevices, err = n.store.CARotations().OldCADevices(ctx, rot.NewCAFP); err != nil {
			return st, err
		}
	}
	servers, err := n.servers()
	if err != nil {
		return st, err
	}
	st.Hubs = make([]HubCAInfo, len(servers))
	var wg sync.WaitGroup
	for i, s := range servers {
		st.Hubs[i].ID = string(s.ID)
		wg.Go(func() {
			var err error
			if st.Hubs[i].Info, err = n.hubCAInfo(ctx, string(s.ID), string(s.Address)); err != nil {
				st.Hubs[i].Error = err.Error()
			}
		})
	}
	wg.Wait()
	return st, nil
}

// FinishOptions are the options of FinishCA.
type FinishOptions struct {
	// Force finishes although agents or hubs still hold only old-CA
	// certificates: they are cut off.
	Force bool
	// DryRun checks and plans, and changes nothing.
	DryRun bool
}

// FinishPlan is what FinishCA did or would do.
type FinishPlan struct {
	NewCAFP string
	// OldDevices and OldHubs still hold only old-CA certificates: the
	// finish cuts them off.
	OldDevices []string
	OldHubs    []string
	// Resealed counts the secrets re-sealed with the new CA's key.
	Resealed int
}

// FinishCA finishes the rotation under way: once every hub holds the new
// key and a node certificate of the new CA, it cuts over, re-seals the
// sealed secrets with the new key, and finishes, after which no hub trusts
// the old CA or holds its key. It refuses with ErrOldCAHolders while agents
// or hubs still hold only old-CA certificates, unless forced. Only the
// leader finishes; elsewhere it fails with *ErrNotLeader. A finish that
// stopped part way is resumed by running it again. The caller makes the
// policy decision.
func (n *Node) FinishCA(ctx context.Context, opts FinishOptions) (FinishPlan, error) {
	if !n.IsLeader() {
		return FinishPlan{}, n.notLeader()
	}
	n.rotMu.Lock()
	defer n.rotMu.Unlock()
	if err := n.requireRotationSchema(ctx); err != nil {
		return FinishPlan{}, err
	}
	rot, err := n.store.CARotations().Active(ctx)
	if errors.Is(err, store.ErrNotFound) {
		return FinishPlan{}, ErrNoRotation
	} else if err != nil {
		return FinishPlan{}, err
	}
	plan := FinishPlan{NewCAFP: rot.NewCAFP}
	if plan.OldDevices, err = n.store.CARotations().OldCADevices(ctx, rot.NewCAFP); err != nil {
		return plan, err
	}
	servers, err := n.servers()
	if err != nil {
		return plan, err
	}
	var members []raft.Server
	for _, s := range servers {
		certs, err := n.store.Hubs().Certs(ctx, string(s.ID))
		if err != nil {
			return plan, err
		}
		if slices.ContainsFunc(certs, func(c store.HubCert) bool { return !c.Revoked && c.CAFP == rot.NewCAFP }) {
			members = append(members, s)
		} else {
			plan.OldHubs = append(plan.OldHubs, string(s.ID))
		}
	}
	if (len(plan.OldDevices) > 0 || len(plan.OldHubs) > 0) && !opts.Force {
		return plan, fmt.Errorf("finish the hub CA rotation: %w: %s. Agents renew when they connect, and need a "+
			"hearth that supports rotation; hubs as soon as they are back. Check `hearth cluster ca status`, "+
			"or pass --force to cut them off: an agent then has to enroll again, a hub to join again",
			ErrOldCAHolders, describeOld(plan.OldDevices, plan.OldHubs))
	}
	if opts.DryRun {
		return plan, nil
	}
	if !n.cfg.CA.HasNextKey() {
		return plan, errors.New("finish the hub CA rotation: this hub does not hold the new CA's key yet; try again shortly")
	}
	if rot.Stage == store.CAStageStarted {
		if err := n.waitHubs(ctx, members, "hold the new CA's key and a node certificate of it", "", func(i CAInfo) bool {
			return i.NextFP == rot.NewCAFP && i.HasNextKey && i.HasNextCert
		}); err != nil {
			return plan, err
		}
		if err := n.advanceCA(ctx, rot.NewCAFP, store.CAStageStarted, store.CAStageCutover); err != nil {
			return plan, err
		}
	}
	n.reconcileCA(ctx)
	// Every hub seals with the new key once it cut over; until then one
	// could seal a secret with the old key after the re-seal.
	if err := n.waitHubs(ctx, members, "serve the new CA", rot.NewCAFP, func(i CAInfo) bool {
		return i.CutOver && i.ServingFP == rot.NewCAFP
	}); err != nil {
		return plan, err
	}
	// The finish names the secrets last checked to be sealed with the new key:
	// one sealed since, with whatever key, refuses it, and they are checked
	// again.
	for attempt := 0; ; attempt++ {
		resealed, digest, err := n.resealSecrets(ctx, rot.NewCAFP)
		plan.Resealed += resealed
		if err != nil {
			return plan, err
		}
		_, _, err = n.propose(ctx, store.AdvanceCARotation{
			NewCAFP: rot.NewCAFP, From: store.CAStageCutover, To: store.CAStageFinished,
			Now: time.Now().UnixMilli(), SealedDigest: digest,
		})
		if err == nil {
			break
		}
		if !errors.Is(err, store.ErrCARotationConflict) || attempt == 5 {
			return plan, fmt.Errorf("move the hub CA rotation to %s: %w", store.CAStageFinished, err)
		}
	}
	n.log.InfoContext(ctx, "hub CA rotation moved on", "stage", store.CAStageFinished)
	n.reconcileCA(ctx)
	n.log.InfoContext(ctx, "finished the hub CA rotation", "new_ca", rot.NewCAFP, "resealed", plan.Resealed,
		"cut_off_devices", len(plan.OldDevices), "cut_off_hubs", len(plan.OldHubs))
	return plan, nil
}

func describeOld(devices, hubs []string) string {
	var parts []string
	if len(devices) > 0 {
		parts = append(parts, "devices "+strings.Join(devices, ", "))
	}
	if len(hubs) > 0 {
		parts = append(parts, "hubs "+strings.Join(hubs, ", "))
	}
	return strings.Join(parts, "; ")
}

func (n *Node) advanceCA(ctx context.Context, newCAFP, from, to string) error {
	_, _, err := n.propose(ctx, store.AdvanceCARotation{NewCAFP: newCAFP, From: from, To: to, Now: time.Now().UnixMilli()})
	if err != nil {
		return fmt.Errorf("move the hub CA rotation to %s: %w", to, err)
	}
	n.log.InfoContext(ctx, "hub CA rotation moved on", "stage", to)
	return nil
}

// waitHubs waits until every hub of members reports what ready accepts.
func (n *Node) waitHubs(ctx context.Context, members []raft.Server, what, servedBy string, ready func(CAInfo) bool) error {
	deadline := time.Now().Add(caMemberWait)
	for {
		var waiting []string
		for _, s := range members {
			info, err := n.hubCAInfoServedBy(ctx, string(s.ID), string(s.Address), servedBy)
			switch {
			case err != nil:
				waiting = append(waiting, fmt.Sprintf("%s (cannot ask it: %v)", s.ID, err))
			case !ready(info):
				waiting = append(waiting, string(s.ID))
			}
		}
		if len(waiting) == 0 {
			return nil
		}
		if !time.Now().Before(deadline) {
			return fmt.Errorf("finish the hub CA rotation: these hubs did not %s within %s: %s; "+
				"run the finish again once they are back", what, caMemberWait, strings.Join(waiting, ", "))
		}
		n.kickCA()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(n.cfg.CAReconcileEvery / 2):
		}
	}
}

// resealSecrets re-seals every secret still sealed with the old key, and
// checks that none is left. It returns how many it re-sealed, and the
// store.SealedDigest of the secrets it last checked.
func (n *Node) resealSecrets(ctx context.Context, newCAFP string) (int, string, error) {
	rp := n.resealer.Load()
	total := 0
	for attempt := 0; ; attempt++ {
		secrets, err := n.store.CARotations().Sealed(ctx)
		if err != nil {
			return total, "", err
		}
		if len(secrets) == 0 {
			return total, "", nil
		}
		if rp == nil {
			return total, "", errors.New("finish the hub CA rotation: this hub cannot re-seal secrets")
		}
		stale, err := (*rp)(ctx, secrets)
		if err != nil {
			return total, "", fmt.Errorf("finish the hub CA rotation: re-seal secrets: %w", err)
		}
		if len(stale) == 0 {
			return total, store.SealedDigest(secrets), nil
		}
		if attempt == 5 {
			return total, "", errors.New("finish the hub CA rotation: secrets kept changing while they were re-sealed; try again")
		}
		_, _, err = n.propose(ctx, store.ResealSecrets{NewCAFP: newCAFP, Secrets: stale})
		switch {
		case errors.Is(err, store.ErrCARotationConflict):
			continue // a secret changed since it was read
		case err != nil:
			return total, "", fmt.Errorf("finish the hub CA rotation: re-seal secrets: %w", err)
		}
		total += len(stale)
	}
}

// watchCA starts the loop that reconciles this hub's CA with the replicated
// rotation; stopCA stops it.
func (n *Node) watchCA() {
	n.caKick = make(chan struct{}, 1)
	n.caStop = make(chan struct{})
	n.caDone = make(chan struct{})
	stop, done := n.caStop, n.caDone
	go func() {
		defer close(done)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go func() {
			<-stop
			cancel()
		}()
		t := time.NewTicker(n.cfg.CAReconcileEvery)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
			case <-n.caKick:
			}
			n.reconcileCA(ctx)
		}
	}()
}

func (n *Node) stopCA() {
	if n.caStop == nil {
		return
	}
	close(n.caStop)
	<-n.caDone
	n.caStop = nil
}

// kickCA makes the reconcile loop run soon.
func (n *Node) kickCA() {
	if n.caKick == nil {
		return
	}
	select {
	case n.caKick <- struct{}{}:
	default:
	}
}

// reconcileCA brings this hub's CA, and the node certificate it presents,
// to the stage of the replicated rotation. It is idempotent; a failed step
// is retried on the next run.
func (n *Node) reconcileCA(ctx context.Context) {
	// The loop and FinishCA or AbortCA must not step the CA at once.
	n.recMu.Lock()
	defer n.recMu.Unlock()
	if n.halted.Load() {
		return
	}
	ca := n.cfg.CA
	rot, err := n.store.CARotations().Latest(ctx)
	switch {
	case errors.Is(err, store.ErrNotFound):
		n.dropLeftoverNext(ctx)
		return
	case err != nil:
		if !errors.Is(err, store.ErrSchemaTooOld) && ctx.Err() == nil {
			n.log.WarnContext(ctx, "read the hub CA rotation", "err", err)
		}
		return
	}
	next := ca.Next()
	switch {
	case rot.Stage == store.CAStageAborted && next != nil && pki.FingerprintHex(next) == rot.NewCAFP:
		if err := n.dropNextLocal(ctx); err != nil {
			n.log.ErrorContext(ctx, "drop the CA of the aborted rotation", "err", err)
		}
		return
	case rot.Stage == store.CAStageFinished && next != nil && pki.FingerprintHex(next) == rot.NewCAFP:
		n.finishLocal(ctx, rot)
		return
	case rot.Stage == store.CAStageFinished && pki.FingerprintHex(ca.Cert()) == rot.OldCAFP:
		// The rotation finished without this hub ever trusting the new CA.
		n.missedRotation(ctx, rot)
		return
	case !rot.Active():
		n.dropLeftoverNext(ctx)
		return
	}
	if pki.FingerprintHex(ca.Cert()) == rot.NewCAFP && ca.Next() == nil {
		return // finished here already; the log is behind
	}
	newCA, err := pki.ParseCertPEM([]byte(rot.NewCACert))
	if err != nil || pki.FingerprintHex(newCA) != rot.NewCAFP {
		n.log.ErrorContext(ctx, "the hub CA rotation's certificate does not match its fingerprint", "err", err)
		return
	}
	if next != nil && pki.FingerprintHex(next) != rot.NewCAFP {
		// A next CA of an attempt that did not start: only one rotation
		// is under way at a time.
		if err := n.dropNextLocal(ctx); err != nil {
			n.log.ErrorContext(ctx, "drop a leftover next CA", "err", err)
			return
		}
	}
	if err := ca.TrustNext(newCA); err != nil {
		n.log.ErrorContext(ctx, "trust the new hub CA", "err", err)
		return
	}
	// A connection opened before the rotation by a certificate other than
	// the pinned one (minted with a stolen old key) does not outlive it.
	if k := n.stream.closeRevoked(func(c *x509.Certificate) bool {
		return errors.Is(n.checkPeerCert(c), errNotPinned)
	}); k > 0 {
		n.log.WarnContext(ctx, "closed raft connections of hub certificates this rotation did not pin", "count", k)
	}
	if !ca.HasNextKey() || n.nextCert.Load() == nil {
		if err := n.obtainNext(ctx, rot); err != nil {
			if ctx.Err() == nil {
				n.log.WarnContext(ctx, "fetch the new hub CA; retrying", "err", err)
			}
			return
		}
	}
	if rot.Stage == store.CAStageCutover && !ca.CutOver() && n.nextCert.Load() != nil {
		if err := ca.Cutover(); err != nil {
			n.log.ErrorContext(ctx, "cut over to the new hub CA", "err", err)
			return
		}
		n.stream.setCert(n.nextCert.Load())
		n.fwdHTTP.CloseIdleConnections()
		n.log.InfoContext(ctx, "serving the new hub CA")
	}
}

// resumeRotation, at Start, applies this hub's store to the next CA it
// loaded, which waits for that: it is trusted, and signs, if the store has a
// rotation to it under way, and is served at once if that rotation is at its
// cutover. The CA's cutover is not kept on disk, and a hub that restarted
// must not seal a secret, or present a certificate, of the old CA until the
// reconcile loop runs.
func (n *Node) resumeRotation(ctx context.Context) {
	rot, err := n.store.CARotations().Active(ctx)
	if err != nil {
		return
	}
	ca := n.cfg.CA
	next, nextCert := ca.Next(), n.nextCert.Load()
	if next == nil || pki.FingerprintHex(next) != rot.NewCAFP {
		return
	}
	if err := ca.TrustNext(next); err != nil {
		n.log.ErrorContext(ctx, "trust the new hub CA", "err", err)
		return
	}
	if rot.Stage != store.CAStageCutover || !ca.HasNextKey() || nextCert == nil {
		return // the reconcile loop fetches what is missing first
	}
	if err := ca.Cutover(); err != nil {
		n.log.ErrorContext(ctx, "serve the new hub CA", "err", err)
		return
	}
	n.stream.setCert(nextCert)
	n.log.InfoContext(ctx, "serving the new hub CA: the rotation is at its cutover")
}

// obtainNext gets the new CA's key and this hub's node certificate of it:
// the leader issues its own; other hubs fetch both from the leader, or the
// key alone from another hub while the leader lacks it.
func (n *Node) obtainNext(ctx context.Context, rot store.CARotation) error {
	ca := n.cfg.CA
	key, err := pki.NewKey()
	if err != nil {
		return err
	}
	csr, err := pki.NewCSR(key, n.cfg.NodeID)
	if err != nil {
		return err
	}
	if n.IsLeader() && ca.HasNextKey() {
		cert, err := n.issueNextNodeCert(ctx, csr, n.cfg.NodeID)
		if err != nil {
			return err
		}
		return n.saveNextCert(cert, key)
	}
	servers, err := n.servers()
	if err != nil {
		return err
	}
	leader := n.Leader().ID
	slices.SortStableFunc(servers, func(a, b raft.Server) int {
		switch {
		case string(a.ID) == leader:
			return -1
		case string(b.ID) == leader:
			return 1
		}
		return 0
	})
	var errs []error
	for _, s := range servers {
		if string(s.ID) == n.cfg.NodeID {
			continue
		}
		c, err := n.memberClient(ctx, string(s.ID), string(s.Address))
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", s.ID, err))
			continue
		}
		callCtx, cancel := context.WithTimeout(ctx, caInfoTimeout)
		resp, err := c.FetchCAKey(callCtx, connect.NewRequest(&clusterv1.FetchCAKeyRequest{NewCaFingerprint: rot.NewCAFP, Csr: csr}))
		cancel()
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", s.ID, err))
			continue
		}
		if !ca.HasNextKey() {
			if err := ca.InstallNextKey(resp.Msg.GetCaKey()); err != nil {
				return fmt.Errorf("install the new CA key from %s: %w", s.ID, err)
			}
			n.log.InfoContext(ctx, "fetched the new hub CA key", "from", string(s.ID))
		}
		if der := resp.Msg.GetCertificate(); len(der) > 0 {
			cert, err := n.checkNextNodeCert(der, key)
			if err != nil {
				return fmt.Errorf("node certificate from %s: %w", s.ID, err)
			}
			return n.saveNextCert(cert, key)
		}
	}
	if ca.HasNextKey() && n.nextCert.Load() == nil {
		return errors.New("no node certificate of the new CA yet: the leader issues it")
	}
	return errors.Join(errs...)
}

// issueNextNodeCert signs csr as hub id's node certificate of the new CA,
// in this hub's cluster epoch, and records it, so removing the hub revokes
// it. Only the leader issues one.
func (n *Node) issueNextNodeCert(ctx context.Context, csr []byte, id string) (*x509.Certificate, error) {
	ca := n.cfg.CA
	next := ca.Next()
	if next == nil || !ca.HasNextKey() {
		return nil, pki.ErrNoNextCA
	}
	cert, err := ca.SignHubCSRInEpoch(csr, id, n.epoch, time.Now())
	if err != nil {
		return nil, err
	}
	if cert.CheckSignatureFrom(next) != nil {
		return nil, errors.New("the node certificate is not signed by the new CA")
	}
	if _, _, err := n.propose(ctx, store.RecordHubCert{
		Serial: pki.SerialString(cert), NodeID: id,
		Fingerprint: pki.FingerprintHex(cert), CAFP: pki.FingerprintHex(next),
	}); err != nil {
		return nil, fmt.Errorf("record the node certificate of %s: %w", id, err)
	}
	return cert, nil
}

// checkNextNodeCert checks a node certificate of the new CA received for key.
func (n *Node) checkNextNodeCert(der []byte, key crypto.Signer) (*x509.Certificate, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	next := n.cfg.CA.Next()
	if next == nil || cert.CheckSignatureFrom(next) != nil {
		return nil, errors.New("not signed by the new CA")
	}
	if id, err := pki.HubNodeID(cert); err != nil || id != n.cfg.NodeID {
		return nil, errors.New("issued to another hub")
	}
	if pki.HubEpoch(cert) != n.epoch {
		return nil, errOtherEpoch
	}
	pub, ok := key.Public().(interface{ Equal(crypto.PublicKey) bool })
	if !ok || !pub.Equal(cert.PublicKey) {
		return nil, errors.New("issued for another key")
	}
	return cert, nil
}

// saveNextCert writes this hub's node certificate of the new CA and its key
// into the raft dir and keeps it for the cutover.
func (n *Node) saveNextCert(cert *x509.Certificate, key any) error {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("encode node key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	certPEM := pki.EncodeCertPEM(cert)
	if err := writeFileSync(filepath.Join(n.dir, nextNodeKeyFile), keyPEM, 0o600); err != nil {
		return err
	}
	if err := writeFileSync(filepath.Join(n.dir, nextNodeCertFile), certPEM, 0o644); err != nil {
		return err
	}
	tc, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return err
	}
	n.nextCert.Store(&tc)
	n.log.Info("holding a node certificate of the new hub CA", "serial", pki.SerialString(cert))
	return nil
}

// loadNextCert loads this hub's node certificate of the new CA, if any.
func (n *Node) loadNextCert() error {
	tc, err := tls.LoadX509KeyPair(filepath.Join(n.dir, nextNodeCertFile), filepath.Join(n.dir, nextNodeKeyFile))
	switch {
	case errors.Is(err, os.ErrNotExist):
		return nil
	case err != nil:
		return fmt.Errorf("load the node certificate of the new hub CA: %w", err)
	}
	n.nextCert.Store(&tc)
	return nil
}

// finishLocal ends the rotation on this hub: the CA drops the old CA and its
// key, and the node certificate of the new CA replaces the old one. Open
// connections of old-CA certificates are closed: a handshake checks a
// certificate only once.
func (n *Node) finishLocal(ctx context.Context, rot store.CARotation) {
	ca := n.cfg.CA
	if !ca.HasNextKey() || n.nextCert.Load() == nil {
		n.missedRotation(ctx, rot)
		return
	}
	if err := ca.Finish(); err != nil {
		n.log.ErrorContext(ctx, "finish the hub CA rotation", "err", err)
		return
	}
	if err := recoverNodeCertFinish(n.dir, ca); err != nil {
		n.log.ErrorContext(ctx, "replace the node certificate with the new CA's", "err", err)
	}
	if next := n.nextCert.Load(); next != nil {
		n.stream.setCert(next)
		n.nextCert.Store(nil)
	}
	k := n.stream.closeRevoked(func(c *x509.Certificate) bool { return ca.IssuerOf(c) == nil })
	n.fwdHTTP.CloseIdleConnections()
	n.log.InfoContext(ctx, "finished the hub CA rotation here: the old CA is no longer trusted and its key is deleted",
		"closed_connections", k)
}

// dropLeftoverNext drops a next CA no rotation under way uses, once the log
// shows its start cannot commit any more: on the leader after a barrier, on
// a follower once it has applied every entry of its log and the leader
// committed them all. Until then the next CA neither signs nor is trusted
// (pki.CA.TrustNext). It skips a run while RotateCA, FinishCA or AbortCA
// holds rotMu.
func (n *Node) dropLeftoverNext(ctx context.Context) {
	if n.cfg.CA.Next() == nil || !n.rotMu.TryLock() {
		return
	}
	defer n.rotMu.Unlock()
	var err error
	if n.IsLeader() {
		err = n.dropUncommittedNext(ctx)
	} else if n.caughtUp() {
		err = n.dropOrphanNext(ctx)
	}
	if err != nil && ctx.Err() == nil {
		n.log.WarnContext(ctx, "drop a leftover next CA; retrying", "err", err)
	}
}

// caughtUp reports whether this follower has a leader, and has applied every
// entry of its log, all of them committed: an entry this hub appended as an
// earlier leader is then either applied or gone.
func (n *Node) caughtUp() bool {
	if n.raft == nil || n.Leader().ID == "" {
		return false
	}
	commit, err := strconv.ParseUint(n.raft.Stats()["commit_index"], 10, 64)
	if err != nil {
		return false
	}
	last, applied := n.raft.LastIndex(), n.raft.AppliedIndex()
	return commit > 0 && last == commit && applied == commit
}

// dropOrphanNext drops this follower's next CA unless the store, caught up,
// has a rotation to it that is not aborted.
func (n *Node) dropOrphanNext(ctx context.Context) error {
	next := n.cfg.CA.Next()
	if next == nil {
		return nil
	}
	rot, err := n.store.CARotations().Latest(ctx)
	switch {
	case errors.Is(err, store.ErrNotFound):
	case err != nil:
		return err
	case rot.NewCAFP == pki.FingerprintHex(next) && rot.Stage != store.CAStageAborted:
		return nil
	}
	return n.dropNextLocal(ctx)
}

// errMissedRotation stops a hub that a hub CA rotation finished without: it
// lacks the new CA's key, or a node certificate of it.
var errMissedRotation = errors.New("the hub CA rotation finished without this hub: it holds no key and no " +
	"node certificate of the new CA; remove it (`hearth cluster remove`), wipe its data dir and join it again")

// missedRotation ends a hub the rotation rot finished without: the new CA
// becomes its only CA, without a key, every CA key file of it is deleted, and
// the hub stops (Config.OnFatal). It never serves the old CA again, and
// cannot start until it joins the cluster anew.
func (n *Node) missedRotation(ctx context.Context, rot store.CARotation) {
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
	for _, f := range []string{nextNodeCertFile, nextNodeKeyFile} {
		_ = os.Remove(filepath.Join(n.dir, f))
	}
	n.nextCert.Store(nil)
	k := n.stream.closeRevoked(func(*x509.Certificate) bool { return true })
	n.fwdHTTP.CloseIdleConnections()
	n.log.ErrorContext(ctx, "stopping: closed every raft connection", "closed_connections", k)
	// OnFatal must not block, and the FSM may have called it already.
	go n.cfg.OnFatal(errMissedRotation)
}

// recoverNodeCertFinish moves the node certificate of the new CA over the
// node certificate once the rotation finished on this hub (the CA trusts no
// next CA, and the new CA issued it). It completes a move a crash
// interrupted: the key is moved first, then the certificate.
func recoverNodeCertFinish(dir string, ca *pki.CA) error {
	certPath := filepath.Join(dir, nextNodeCertFile)
	b, err := os.ReadFile(certPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	cert, err := pki.ParseCertPEM(b)
	if err != nil {
		return fmt.Errorf("read %s: %w", nextNodeCertFile, err)
	}
	if ca.Next() != nil || cert.CheckSignatureFrom(ca.Cert()) != nil {
		return nil // the rotation has not finished here
	}
	keyPath := filepath.Join(dir, nextNodeKeyFile)
	if err := os.Rename(keyPath, filepath.Join(dir, nodeKeyFile)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Rename(certPath, filepath.Join(dir, nodeCertFile)); err != nil {
		return err
	}
	syncDirOf(dir)
	return nil
}

// writeFileSync replaces path with data, mode perm, through a temporary file
// that reaches the disk before the rename. A temporary file left by a crash
// is removed first, so the new one is created with perm.
func writeFileSync(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.Remove(tmp); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	syncDirOf(filepath.Dir(path))
	return nil
}

func syncDirOf(dir string) {
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
}
