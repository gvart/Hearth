// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/gvart/hearth/internal/hub"
	"github.com/gvart/hearth/internal/integrations/kubernetes"
	"github.com/gvart/hearth/internal/pki"
	"github.com/gvart/hearth/internal/policy"
	clusterv1 "github.com/gvart/hearth/internal/proto/hearth/cluster/v1"
	"github.com/gvart/hearth/internal/proto/hearth/cluster/v1/clusterv1connect"
	"github.com/gvart/hearth/internal/store"
)

// rotHub is a hub of a rotation test: a node with a CA of its own, loaded
// from its data dir as a real hub's is, and its ClusterService on a TLS
// server whose certificate follows the CA.
type rotHub struct {
	*testNode
	ca      *pki.CA
	url     string
	srvCert atomic.Pointer[tls.Certificate]
	// sealers seal kube, proxmox and runbook secrets with the CA's keys.
	sealers map[string]*kubernetes.Sealer
}

// sealInfos are the purposes of the hub's sealers, by table.
var sealInfos = map[string]string{
	store.SealedKubeClusters:   "hearth kubeconfig seal v1",
	store.SealedProxmoxServers: "hearth proxmox connection seal v1",
	store.SealedRunbookRuns:    "hearth runbook run seal v1",
}

// sealID is the additional data a secret of table is sealed with.
func sealID(table, id string) string {
	if table == store.SealedRunbookRuns {
		return "runbook-run/" + id
	}
	return id
}

// startRotationHubs forms a 3-voter cluster whose hubs each load the same
// CA from their own data dir. It returns the hubs and a copy of the CA as it
// was before any rotation, as someone who stole it would hold it.
func startRotationHubs(t *testing.T) ([]*rotHub, *pki.CA) {
	t.Helper()
	base := t.TempDir()
	if _, err := pki.LoadOrCreateCA(base, time.Now()); err != nil {
		t.Fatal(err)
	}
	loadCopy := func() (string, *pki.CA) {
		dir := t.TempDir()
		for _, f := range []string{pki.CACertFile, pki.CAKeyFile} {
			b, err := os.ReadFile(filepath.Join(base, f))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, f), b, 0o600); err != nil { //nolint:gosec // a test temp dir
				t.Fatal(err)
			}
		}
		ca, err := pki.LoadOrCreateCA(dir, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		return dir, ca
	}
	tune := func(c *Config) {
		c.ForwardWait = 2 * time.Second
		c.CAReconcileEvery = 100 * time.Millisecond
	}
	var hubs []*rotHub
	for i, id := range []string{"n1", "n2", "n3"} {
		dir, ca := loadCopy()
		n := startNodeBound(t, ca, id, dir, "", i == 0, (*Node).BindForwarding, tune)
		if i == 0 {
			leaderOf(t, n)
		} else {
			addVoter(t, hubs[0].testNode, n)
		}
		hubs = append(hubs, &rotHub{testNode: n, ca: ca})
	}
	waitReady(t, hubs[1].testNode, hubs[2].testNode)
	for _, h := range hubs {
		h.serve(t)
	}
	for _, h := range hubs {
		if err := hubs[0].st.Hubs().SetAgentURL(t.Context(), h.ID(), h.url); err != nil {
			t.Fatal(err)
		}
	}
	for _, h := range hubs {
		eventually(t, h.ID()+" to know every hub URL", func() bool { return len(h.AgentURLs()) == 3 })
	}
	_, thief := loadCopy()
	return hubs, thief
}

// serve starts the hub's ClusterService, with a server certificate that is
// issued again whenever the CA it serves changes, and its sealers, rekeyed
// with the CA, and its re-sealer.
func (h *rotHub) serve(t *testing.T) {
	t.Helper()
	issue := func() {
		c, err := h.ca.IssueServerCert([]string{"127.0.0.1"}, time.Now())
		if err != nil {
			t.Error(err)
			return
		}
		h.srvCert.Store(&c)
	}
	issue()
	h.sealers = map[string]*kubernetes.Sealer{}
	keys, err := h.ca.KeyDERs()
	if err != nil {
		t.Fatal(err)
	}
	for table, info := range sealInfos {
		if h.sealers[table], err = kubernetes.NewPurposeSealer(keys[0], info); err != nil {
			t.Fatal(err)
		}
	}
	h.ca.OnChange(func() {
		issue()
		keys, err := h.ca.KeyDERs()
		if err != nil {
			t.Error(err)
			return
		}
		for _, s := range h.sealers {
			if err := s.SetSecrets(keys...); err != nil {
				t.Error(err)
			}
		}
	})
	h.SetResealer(func(_ context.Context, secrets []store.SealedSecret) ([]store.SealedSecret, error) {
		var stale []store.SealedSecret
		for _, s := range secrets {
			out, changed, err := h.sealers[s.Table].Reseal(sealID(s.Table, s.ID), s.Sealed)
			if err != nil {
				return nil, fmt.Errorf("%s %s: %w", s.Table, s.ID, err)
			}
			if changed {
				s.Resealed = out
				stale = append(stale, s)
			}
		}
		return stale, nil
	})
	log := slog.New(slog.DiscardHandler)
	pol := policy.New(h.st.Audit())
	mux := http.NewServeMux()
	mux.Handle(NewJoinServer(h.Node, h.st, h.ca, pol, log).Handler())
	srv := httptest.NewUnstartedServer(mux)
	srv.TLS = hub.TLSConfigFunc(h.ca, h.srvCert.Load)
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	h.url = srv.URL
}

// memberClient is a ClusterService client of url presenting cert and
// trusting the CAs of ca.
func memberClientOf(ca *pki.CA, cert tls.Certificate, url string) (clusterv1connect.ClusterServiceClient, *http.Client) {
	c := newForwardClient(ca, func() *tls.Certificate { return &cert }, "")
	return clusterv1connect.NewClusterServiceClient(c, url), c
}

// mintHubCert issues a node certificate for id with ca, as whoever holds
// that CA's key could.
func mintHubCert(t *testing.T, ca *pki.CA, id string) tls.Certificate {
	t.Helper()
	key, err := pki.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	csr, err := pki.NewCSR(key, id)
	if err != nil {
		t.Fatal(err)
	}
	c, err := ca.SignHubCSR(csr, id, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{c.Raw}, PrivateKey: key, Leaf: c}
}

func rotLeader(t *testing.T, hubs []*rotHub) *rotHub {
	t.Helper()
	nodes := make([]*testNode, len(hubs))
	for i, h := range hubs {
		nodes[i] = h.testNode
	}
	l := leaderOf(t, nodes...)
	for _, h := range hubs {
		if h.testNode == l {
			return h
		}
	}
	return nil
}

func fileContains(t *testing.T, root string, needle []byte) []string {
	t.Helper()
	var hits []string
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil //nolint:nilerr // a file that vanished mid-walk holds nothing
		}
		if b, err := os.ReadFile(path); err == nil && bytes.Contains(b, needle) { //nolint:gosec // a test temp dir
			hits = append(hits, path)
		}
		return nil
	})
	return hits
}

// TestCARotationThreeHubs rotates the CA of a 3-hub cluster end to end:
// the refusals before it starts, the window in which both CAs are trusted
// but an old-CA certificate only if it is the pinned one, and the finish
// after which nothing of the old CA is trusted, every sealed secret opens
// with the new key alone, and Raft carries on.
func TestCARotationThreeHubs(t *testing.T) {
	ctx := t.Context()
	hubs, thief := startRotationHubs(t)
	leader := rotLeader(t, hubs)
	var follower *rotHub
	for _, h := range hubs {
		if h != leader {
			follower = h
			break
		}
	}
	oldFP := pki.FingerprintHex(leader.ca.Cert())

	// Only the leader rotates.
	var nl *ErrNotLeader
	if _, err := follower.RotateCA(ctx, RotateOptions{}); !errors.As(err, &nl) {
		t.Fatalf("RotateCA on a follower = %v, want *ErrNotLeader", err)
	}
	// Hub certificates without a recorded fingerprint refuse the rotation,
	// also through the control socket, which returns the plan with it.
	_, err := leader.RotateCA(ctx, RotateOptions{})
	if !errors.Is(err, ErrUnpinnedCerts) || !strings.Contains(err.Error(), "hub n2") {
		t.Fatalf("RotateCA with unrecorded hub certificates = %v, want ErrUnpinnedCerts naming them", err)
	}
	lc := serveControl(t, leader.testNode)
	if p, err := lc.RotateCA(ctx, RotateOptions{DryRun: true}); !errors.Is(err, ErrUnpinnedCerts) || len(p.Unpinned) != 3 {
		t.Fatalf("RotateCA through the socket = %+v, %v; want ErrUnpinnedCerts with 3 certificates", p, err)
	}
	if _, err := serveControl(t, follower.testNode).RotateCA(ctx, RotateOptions{}); !errors.As(err, &nl) {
		t.Fatalf("RotateCA through a follower's socket = %v, want *ErrNotLeader", err)
	}
	if _, err := lc.FinishCA(ctx, FinishOptions{}); !errors.Is(err, ErrNoRotation) {
		t.Fatalf("FinishCA with no rotation = %v, want ErrNoRotation", err)
	}
	for _, h := range hubs {
		h.RecordNodeCert(ctx)
	}
	for _, h := range hubs {
		eventually(t, "every hub's certificate recorded on "+h.ID(), func() bool {
			for _, o := range hubs {
				certs, err := h.st.Hubs().Certs(ctx, o.ID())
				if err != nil || len(certs) != 1 || certs[0].Fingerprint == "" {
					return false
				}
			}
			return true
		})
	}
	plan, err := leader.RotateCA(ctx, RotateOptions{DryRun: true})
	if err != nil || len(plan.Pins) != 3 || leader.ca.Next() != nil {
		t.Fatalf("dry run = %+v, %v; want 3 pins and no next CA", plan, err)
	}
	for _, h := range hubs {
		if want := pki.FingerprintHex(h.stream.currentCert().Leaf); plan.Pins[h.ID()] != want {
			t.Errorf("pin of %s = %s, want the certificate it presents, %s", h.ID(), plan.Pins[h.ID()], want)
		}
	}

	// A device on the old CA, and a secret of each kind sealed with the old key.
	now := time.Now()
	if err := leader.st.Devices().Upsert(ctx, store.Device{ID: "pi", FirstSeen: now, LastSeen: now}); err != nil {
		t.Fatal(err)
	}
	if err := leader.st.Certs().Record(ctx, store.CertRecord{Serial: "0a", DeviceID: "pi", Fingerprint: "fp", CAFP: oldFP}); err != nil {
		t.Fatal(err)
	}
	secret := []byte("the secret")
	seal := func(table, id string) []byte {
		b, err := leader.sealers[table].Seal(sealID(table, id), secret)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	if err := leader.st.KubeClusters().Add(ctx, store.KubeCluster{ID: "k1", Name: "lab", Sealed: seal(store.SealedKubeClusters, "k1"), CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := leader.st.ProxmoxServers().Add(ctx, store.ProxmoxServer{ID: "p1", Name: "rack", Sealed: seal(store.SealedProxmoxServers, "p1"), CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := leader.st.RunbookRuns().Create(ctx, store.RunbookRun{
		ID: "r1", RunbookID: "rb", Status: "running", StartedBy: "admin", StartedAt: now, UpdatedAt: now,
		Source: seal(store.SealedRunbookRuns, "r1"), State: []byte(`{}`),
	}); err != nil {
		t.Fatal(err)
	}

	oldCert := *follower.stream.currentCert()
	forged := mintHubCert(t, thief, follower.ID())
	oldKey, err := os.ReadFile(filepath.Join(leader.dir, pki.CAKeyFile))
	if err != nil {
		t.Fatal(err)
	}

	// The rotation starts; a second one is refused.
	plan, err = leader.RotateCA(ctx, RotateOptions{})
	if err != nil {
		t.Fatalf("RotateCA: %v", err)
	}
	newFP := plan.NewCAFP
	if _, err := leader.RotateCA(ctx, RotateOptions{}); !errors.Is(err, store.ErrCARotationActive) {
		t.Errorf("a second RotateCA = %v, want ErrCARotationActive", err)
	}
	for _, h := range hubs {
		eventually(t, h.ID()+" to hold the new key and a node certificate of it", func() bool {
			i := h.localCAInfo()
			return i.NextFP == newFP && i.HasNextKey && i.HasNextCert && !i.CutOver
		})
		if fi, err := os.Stat(filepath.Join(h.dir, pki.NextCAKeyFile)); err != nil || fi.Mode().Perm() != 0o600 {
			t.Errorf("%s: next CA key file %v, %v; want mode 0600", h.ID(), fi, err)
		}
	}
	// The new key never reaches the store, the Raft log or a snapshot.
	nextKey, err := leader.ca.NextKeyDER()
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range hubs {
		if hits := fileContains(t, filepath.Join(h.dir, RaftDir), nextKey); len(hits) > 0 {
			t.Errorf("%s: the new CA key is in %v", h.ID(), hits)
		}
		if hits := fileContains(t, filepath.Join(h.dir, "hearth.db"), nextKey); len(hits) > 0 {
			t.Errorf("%s: the new CA key is in the store", h.ID())
		}
	}

	// In the window the pinned old-CA certificate is accepted, on a
	// connection kept open past the finish.
	pinnedClient, pinnedHTTP := memberClientOf(leader.ca, oldCert, leader.url)
	defer pinnedHTTP.CloseIdleConnections()
	if _, err := pinnedClient.CAInfo(ctx, connect.NewRequest(&clusterv1.CAInfoRequest{})); err != nil {
		t.Fatalf("CAInfo with the pinned old-CA certificate in the window: %v", err)
	}
	// A certificate minted with the old key for a real member, with a new
	// serial, gets nothing, and the attempt is audited.
	forgedClient, forgedHTTP := memberClientOf(leader.ca, forged, leader.url)
	defer forgedHTTP.CloseIdleConnections()
	_, err = forgedClient.FetchCAKey(ctx, connect.NewRequest(&clusterv1.FetchCAKeyRequest{NewCaFingerprint: newFP}))
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Errorf("FetchCAKey with a forged old-CA certificate = %v, want PermissionDenied", err)
	}
	entries, err := leader.st.Audit().Query(ctx, store.AuditFilter{Actions: []string{string(policy.ClusterCAFetchKey)}}, 50)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(entries, func(e store.AuditEntry) bool {
		return e.Decision == policy.Deny && e.ActorID == follower.ID() && bytes.Contains(e.Detail, []byte(pki.SerialString(forged.Leaf)))
	}) {
		t.Errorf("no deny audit entry for the forged certificate; entries: %+v", entries)
	}
	if err := leader.checkPeerCert(forged.Leaf); !errors.Is(err, errNotPinned) {
		t.Errorf("Raft peer check of the forged certificate = %v, want errNotPinned", err)
	}
	if err := leader.refuseRevoked(forged.Leaf); err == nil {
		t.Error("the Raft transport accepts the forged certificate in the window")
	}
	// No commands of the rotation through Apply or forwarding, and no join.
	if _, err := leader.Apply(ctx, store.AdvanceCARotation{NewCAFP: newFP, From: store.CAStageStarted, To: store.CAStageCutover}); !errors.Is(err, errRotationViaLog) {
		t.Errorf("Apply(advance_ca_rotation) = %v, want errRotationViaLog", err)
	}
	if _, err := follower.ApplyOrForward(ctx, store.ResealSecrets{NewCAFP: newFP}); err == nil {
		t.Error("a forwarded reseal_secrets was applied")
	}
	tok, err := pki.ParseJoinToken(joinToken(t, leader.testNode, leader.ca, time.Now().Add(time.Hour)))
	if err != nil {
		t.Fatal(err)
	}
	key, _ := pki.NewKey()
	csr, _ := pki.NewCSR(key, "n4")
	_, err = NewJoinServer(leader.Node, leader.st, leader.ca, policy.New(leader.st.Audit()), slog.New(slog.DiscardHandler)).
		Join(ctx, connect.NewRequest(&clusterv1.JoinRequest{
			TokenSecret: tok.Secret, NodeId: "n4", RaftAddress: freeAddr(t), Csr: csr,
			SchemaVersion: store.SchemaVersion(), ClusterEpochs: true,
		}))
	if connect.CodeOf(err) != connect.CodeFailedPrecondition || !strings.Contains(err.Error(), "rotation") {
		t.Errorf("Join in the window = %v, want FailedPrecondition naming the rotation", err)
	}

	// The device on the old CA holds the finish up, unless forced.
	if _, err := leader.FinishCA(ctx, FinishOptions{}); !errors.Is(err, ErrOldCAHolders) || !strings.Contains(err.Error(), "pi") {
		t.Fatalf("FinishCA with a device on the old CA = %v, want ErrOldCAHolders naming it", err)
	}
	fp, err := leader.FinishCA(ctx, FinishOptions{Force: true, DryRun: true})
	if err != nil || !slices.Equal(fp.OldDevices, []string{"pi"}) || len(fp.OldHubs) != 0 || leader.ca.CutOver() {
		t.Fatalf("forced dry run = %+v, %v; want pi listed and nothing changed", fp, err)
	}
	fp, err = leader.FinishCA(ctx, FinishOptions{Force: true})
	if err != nil {
		t.Fatalf("FinishCA: %v", err)
	}
	if fp.Resealed != 3 {
		t.Errorf("re-sealed %d secrets, want 3", fp.Resealed)
	}

	for _, h := range hubs {
		eventually(t, h.ID()+" to finish", func() bool {
			i := h.localCAInfo()
			_, err := os.Stat(filepath.Join(h.dir, RaftDir, nextNodeCertFile))
			issuer := h.ca.IssuerOf(h.stream.currentCert().Leaf)
			return i.ServingFP == newFP && i.NextFP == "" && !h.ca.HasNextKey() && errors.Is(err, os.ErrNotExist) &&
				issuer != nil && pki.FingerprintHex(issuer) == newFP
		})
		key, err := os.ReadFile(filepath.Join(h.dir, pki.CAKeyFile))
		if err != nil || bytes.Equal(key, oldKey) {
			t.Errorf("%s: ca.key %v; want the new key in place of the old", h.ID(), err)
		}
		for _, f := range []string{pki.NextCACertFile, pki.NextCAKeyFile, filepath.Join(RaftDir, nextNodeCertFile), filepath.Join(RaftDir, nextNodeKeyFile)} {
			if _, err := os.Stat(filepath.Join(h.dir, f)); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("%s: %s left behind: %v", h.ID(), f, err)
			}
		}
		if issuer := h.ca.IssuerOf(h.stream.currentCert().Leaf); issuer == nil || pki.FingerprintHex(issuer) != newFP {
			t.Errorf("%s presents a node certificate not of the new CA", h.ID())
		}
	}

	// Nothing of the old CA works any more: the connection opened in the
	// window, a new one with the pinned certificate, and one minted with the
	// old key.
	if _, err := pinnedClient.CAInfo(ctx, connect.NewRequest(&clusterv1.CAInfoRequest{})); err == nil {
		t.Error("the connection opened with the old-CA certificate in the window still works after the finish")
	}
	freshClient, freshHTTP := memberClientOf(leader.ca, oldCert, leader.url)
	defer freshHTTP.CloseIdleConnections()
	if _, err := freshClient.CAInfo(ctx, connect.NewRequest(&clusterv1.CAInfoRequest{})); err == nil {
		t.Error("a new connection with the old-CA certificate is accepted after the finish")
	}
	if err := dialRaft(t, leader.Addr(), forged, leader.ca); err == nil {
		t.Error("the Raft transport accepts a certificate minted with the old key after the finish")
	}
	if err := dialRaft(t, leader.Addr(), oldCert, leader.ca); err == nil {
		t.Error("the Raft transport accepts the old pinned certificate after the finish")
	}

	// Every sealed secret opens with the new key alone.
	newSigner, err := pki.ReadKey(filepath.Join(leader.dir, pki.CAKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	newDER, err := x509.MarshalPKCS8PrivateKey(newSigner)
	if err != nil {
		t.Fatal(err)
	}
	secrets, err := follower.st.CARotations().Sealed(ctx)
	if err != nil || len(secrets) != 3 {
		t.Fatalf("Sealed = %d, %v", len(secrets), err)
	}
	for _, s := range secrets {
		sealer, err := kubernetes.NewPurposeSealer(newDER, sealInfos[s.Table])
		if err != nil {
			t.Fatal(err)
		}
		if got, err := sealer.Open(sealID(s.Table, s.ID), s.Sealed); err != nil || !bytes.Equal(got, secret) {
			t.Errorf("%s %s with the new key alone: %q, %v", s.Table, s.ID, got, err)
		}
	}

	// Every hub answers over the new CA alone.
	st, err := lc.CAStatus(ctx)
	if err != nil || st.Rotation == nil || st.Rotation.Stage != store.CAStageFinished || len(st.Hubs) != 3 {
		t.Fatalf("CAStatus after the finish = %+v, %v", st, err)
	}
	for _, h := range st.Hubs {
		if h.Error != "" || h.Info.ServingFP != newFP || h.Info.NextFP != "" {
			t.Errorf("CAStatus of %s after the finish = %+v", h.ID, h)
		}
	}

	// Raft carries on: a write through a follower reaches every hub.
	if err := follower.st.Hubs().SetAgentURL(ctx, follower.ID(), follower.url+"/after"); err != nil {
		t.Fatalf("write after the finish: %v", err)
	}
	for _, h := range hubs {
		eventually(t, "the write on "+h.ID(), func() bool {
			urls, err := h.st.Hubs().AgentURLs(ctx)
			return err == nil && urls[follower.ID()] == follower.url+"/after"
		})
		if err := h.fsm.haltedErr(); err != nil {
			t.Fatalf("%s halted: %v", h.ID(), err)
		}
	}
}

// dialRaft opens a Raft transport connection to addr presenting cert, and
// reads from it: the server refuses a client certificate after the
// handshake, so the refusal shows on the first read.
func dialRaft(t *testing.T, addr string, cert tls.Certificate, ca *pki.CA) error {
	t.Helper()
	d := &tls.Dialer{NetDialer: &net.Dialer{Timeout: 5 * time.Second}, Config: clientTLS(cert, ca, nil)}
	c, err := d.DialContext(t.Context(), "tcp", addr)
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	_, err = c.Read(make([]byte, 1))
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return nil // the server kept the connection: it accepted the certificate
	}
	return err
}

// A rotation needs every hub at the schema that records rotations.
func TestCARotationBeforeSchema(t *testing.T) {
	h := startMigHub(t, newTestCA(t), "n1", schemaBeforeRotationDir(t), "", true, false)
	leaderOf(t, h.testNode)
	if _, err := h.RotateCA(t.Context(), RotateOptions{}); !errors.Is(err, store.ErrSchemaTooOld) ||
		!strings.Contains(err.Error(), "hearth cluster migrate") {
		t.Fatalf("RotateCA below the schema = %v, want ErrSchemaTooOld saying to migrate", err)
	}
	if _, err := h.FinishCA(t.Context(), FinishOptions{}); !errors.Is(err, store.ErrSchemaTooOld) {
		t.Fatalf("FinishCA below the schema = %v, want ErrSchemaTooOld", err)
	}
	if h.cfg.CA.Next() != nil {
		t.Error("a refused rotation left a next CA")
	}
}

// schemaBeforeRotationDir is a data dir whose database is at the schema
// before hub CA rotations.
func schemaBeforeRotationDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "hearth.db")
	st, err := store.Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	_ = st.Close()
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	if _, err := db.ExecContext(t.Context(), fmt.Sprintf(`DROP TABLE ca_rotations;
		DELETE FROM goose_db_version WHERE version_id >= %d`, store.CARotationSchema)); err != nil {
		t.Fatal(err)
	}
	return dir
}
