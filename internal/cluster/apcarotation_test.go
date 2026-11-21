// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/gvart/hearth/internal/pki"
	"github.com/gvart/hearth/internal/policy"
	clusterv1 "github.com/gvart/hearth/internal/proto/hearth/cluster/v1"
	"github.com/gvart/hearth/internal/proto/hearth/cluster/v1/clusterv1connect"
	"github.com/gvart/hearth/internal/store"
)

// newAPRotationCluster starts an AP cluster for a hub CA rotation: every
// member reconciles its CA often, re-seals with a fake sealer (a secret is
// stale until it starts with "new:"), and its agent URL is recorded.
func newAPRotationCluster(t *testing.T, n int, specs ...apSpec) map[string]*apTestNode {
	t.Helper()
	c := newAPTestCluster(t, n, specs...)
	for _, tn := range c {
		prepareRotation(t, tn)
	}
	for _, tn := range c {
		for _, other := range c {
			waitUntil(t, 5*time.Second, tn.id+" to know "+other.id+"'s URL", func() bool {
				return !other.node.IsMaster() || tn.node.AgentURLOf(t.Context(), other.id) != ""
			})
		}
	}
	return c
}

// prepareRotation sets what the hub layer sets on a member for a rotation.
func prepareRotation(t *testing.T, tn *apTestNode) {
	t.Helper()
	tn.node.SetResealer(fakeResealer)
	tn.node.SetCAPolicy(policy.NewWithConfig(tn.st.Audit(), tn.st.Approvals(), policy.Config{}))
	if tn.node.IsMaster() {
		if err := tn.st.Hubs().SetAgentURL(t.Context(), tn.id, tn.node.cfg.AgentURL); err != nil {
			t.Fatal(err)
		}
	}
	tn.node.kickCA()
}

func fakeResealer(_ context.Context, secrets []store.SealedSecret) ([]store.SealedSecret, error) {
	var stale []store.SealedSecret
	for _, s := range secrets {
		if !bytes.HasPrefix(s.Sealed, []byte("new:")) {
			s.Resealed = append([]byte("new:"), s.Sealed...)
			stale = append(stale, s)
		}
	}
	return stale, nil
}

func caFP(ca *pki.CA) string { return pki.FingerprintHex(ca.Cert()) }

// TestAPCARotation rotates the hub CA of an AP cluster with two masters and
// a storage-only member end to end: the storage member never holds the new
// key, a sealed secret is re-sealed, and the members still see each other
// once the old CA is dropped.
func TestAPCARotation(t *testing.T) {
	ctx := t.Context()
	c := newAPRotationCluster(t, 2,
		apSpec{"a", storageMaster, storageMaster},
		apSpec{"b", storageMaster, storageMaster},
		apSpec{"c", storageOnly, storageMaster},
	)
	a, b, cc := c["a"], c["b"], c["c"]
	if err := a.st.KubeClusters().Add(ctx, store.KubeCluster{ID: "k1", Name: "lab", Sealed: []byte("old-secret"), CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	oldFP := caFP(a.ca)

	// Refusals: not on a storage member; a finish with no rotation.
	if _, err := cc.node.RotateCA(ctx, RotateOptions{}); !errors.Is(err, ErrNotMasterHere) {
		t.Fatalf("rotate on a storage member: %v, want ErrNotMasterHere", err)
	}
	if _, err := a.node.FinishCA(ctx, FinishOptions{}); !errors.Is(err, ErrNoRotation) {
		t.Fatalf("finish without a rotation: %v, want ErrNoRotation", err)
	}

	plan, err := a.node.ChangeCA(ctx, CARequest{Op: CAOpRotate, Actor: "admin@test"})
	if err != nil {
		t.Fatal(err)
	}
	newFP := plan.Rotate.NewCAFP
	if len(plan.Rotate.Pins) != 3 {
		t.Fatalf("pins = %v, want every member", plan.Rotate.Pins)
	}
	// A second rotation, on either master, is refused while one is under way.
	if _, err := b.node.RotateCA(ctx, RotateOptions{}); !errors.Is(err, store.ErrCARotationActive) {
		waitUntil(t, 5*time.Second, "b to see the rotation", func() bool { return b.node.rotationActive() })
		if _, err := b.node.RotateCA(ctx, RotateOptions{}); !errors.Is(err, store.ErrCARotationActive) {
			t.Fatalf("second rotation: %v, want ErrCARotationActive", err)
		}
	}
	// b is no owner while a is alive.
	if _, err := b.node.FinishCA(ctx, FinishOptions{}); !errors.Is(err, ErrRotationOwner) {
		t.Fatalf("finish on b: %v, want ErrRotationOwner", err)
	}
	// Who is a master does not change during a rotation.
	if _, err := a.node.Promote(ctx, "c", RoleMaster); !errors.Is(err, ErrRotationRoles) {
		t.Fatalf("promote during a rotation: %v, want ErrRotationRoles", err)
	}

	waitUntil(t, 10*time.Second, "every member to hold the new CA", func() bool {
		return b.ca.HasNextKey() && cc.node.nextCert.Load() != nil && b.node.nextCert.Load() != nil
	})
	if cc.ca.HasNextKey() || cc.ca.HasKey() {
		t.Fatal("the storage member holds a CA key")
	}
	if _, err := os.Stat(filepath.Join(cc.dir, pki.NextCAKeyFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the storage member has %s: %v", pki.NextCAKeyFile, err)
	}

	res, err := a.node.ChangeCA(ctx, CARequest{Op: CAOpFinish, Actor: "admin@test"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Finish.Resealed != 1 {
		t.Fatalf("resealed %d secrets, want 1", res.Finish.Resealed)
	}
	for _, tn := range []*apTestNode{a, b, cc} {
		waitUntil(t, 10*time.Second, tn.id+" to serve only the new CA", func() bool {
			return caFP(tn.ca) == newFP && tn.ca.Next() == nil
		})
		if tn.ca.IssuerOf(tn.node.cert.Load().Leaf) == nil || pki.FingerprintHex(tn.ca.IssuerOf(tn.node.cert.Load().Leaf)) != newFP {
			t.Fatalf("%s presents a node certificate of another CA", tn.id)
		}
		for _, f := range []string{pki.NextCAKeyFile, nextNodeCertFile, nextNodeKeyFile, caCutoverFile} {
			dir := tn.dir
			if f != pki.NextCAKeyFile {
				dir = filepath.Join(tn.dir, RaftDir)
			}
			waitUntil(t, 5*time.Second, tn.id+" to delete "+f, func() bool {
				_, err := os.Stat(filepath.Join(dir, f))
				return errors.Is(err, os.ErrNotExist)
			})
		}
	}
	if cc.ca.HasKey() || !a.ca.HasKey() || !b.ca.HasKey() {
		t.Fatal("after the finish the masters, and only they, hold the CA key")
	}
	if caFP(a.ca) == oldFP {
		t.Fatal("the CA did not change")
	}
	ks, err := a.st.KubeClusters().List(ctx)
	if err != nil || len(ks) != 1 || string(ks[0].Sealed) != "new:old-secret" {
		t.Fatalf("kube clusters = %+v, %v; want the secret re-sealed", ks, err)
	}
	// The members still gossip, over certificates of the new CA alone.
	for _, tn := range []*apTestNode{a, b, cc} {
		waitUntil(t, 10*time.Second, tn.id+" to see every member alive", func() bool {
			alive := 0
			for _, m := range tn.node.Membership().Members() {
				if m.State == MemberAlive {
					alive++
				}
			}
			return alive == 3
		})
	}
	// A write still replicates.
	if err := a.st.KubeClusters().Add(ctx, store.KubeCluster{ID: "k2", Name: "lab2", Sealed: []byte("x"), CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, 10*time.Second, "c to get the write", func() bool {
		ks, err := cc.st.KubeClusters().List(ctx)
		return err == nil && len(ks) == 2
	})
	entries, err := a.st.Audit().Query(ctx, store.AuditFilter{Actions: []string{string(policy.ClusterCARotate), string(policy.ClusterCAFinish)}}, 10)
	if err != nil || len(entries) < 2 {
		t.Fatalf("audit of the rotation: %+v, %v", entries, err)
	}
}

// rotationTrio starts two masters a and b and a storage-only member c, and
// a sealed secret to re-seal.
func rotationTrio(t *testing.T) (a, b, c *apTestNode) {
	t.Helper()
	m := newAPRotationCluster(t, 2,
		apSpec{"a", storageMaster, storageMaster},
		apSpec{"b", storageMaster, storageMaster},
		apSpec{"c", storageOnly, storageMaster},
	)
	if err := m["a"].st.KubeClusters().Add(t.Context(), store.KubeCluster{
		ID: "k1", Name: "lab", Sealed: []byte("old-secret"), CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	return m["a"], m["b"], m["c"]
}

// TestAPCARotationOwnerLostBeforeTheKey: the owner dies before any other
// master fetched the new key. The finish says so and names the way out, an
// abort from the other master, which every member then follows.
func TestAPCARotationOwnerLostBeforeTheKey(t *testing.T) {
	ctx := t.Context()
	a, b, c := rotationTrio(t)
	// b takes no part until a is gone.
	b.node.halted.Store(true)
	plan, err := a.node.RotateCA(ctx, RotateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	waitUntil(t, 10*time.Second, "c to hold a node certificate of the new CA", func() bool {
		return c.node.nextCert.Load() != nil
	})
	a.stop()
	b.node.halted.Store(false)
	waitUntil(t, 10*time.Second, "b to see a down", func() bool {
		st := a.memberOn(b).State
		return st == MemberDead || st == MemberLeft
	})
	if b.ca.HasNextKey() {
		t.Fatal("b holds the new key")
	}
	_, err = b.node.FinishCA(ctx, FinishOptions{})
	if err == nil || !strings.Contains(err.Error(), "abort") || !strings.Contains(err.Error(), "a, which started") {
		t.Fatalf("finish without the key: %v; want it to name the owner and the abort", err)
	}
	if _, err := b.node.AbortCA(ctx, AbortOptions{}); err != nil {
		t.Fatal(err)
	}
	for _, tn := range []*apTestNode{b, c} {
		waitUntil(t, 10*time.Second, tn.id+" to drop the new CA", func() bool {
			return tn.ca.Next() == nil && tn.node.nextCert.Load() == nil && caFP(tn.ca) != plan.NewCAFP
		})
	}
	if b.node.rotationActive() {
		t.Fatal("b still sees a rotation under way")
	}
}

// TestAPCARotationTakeover: the owner dies after the other master holds the
// new key. The finish names the member down; once it is removed the other
// master finishes the rotation it did not start.
func TestAPCARotationTakeover(t *testing.T) {
	ctx := t.Context()
	a, b, c := rotationTrio(t)
	plan, err := a.node.RotateCA(ctx, RotateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	waitUntil(t, 10*time.Second, "b and c to hold the new CA", func() bool {
		return b.ca.HasNextKey() && b.node.nextCert.Load() != nil && c.node.nextCert.Load() != nil
	})
	a.stop()
	waitUntil(t, 10*time.Second, "b to see a down", func() bool {
		st := a.memberOn(b).State
		return st == MemberDead || st == MemberLeft
	})
	if _, err := b.node.FinishCA(ctx, FinishOptions{}); err == nil || !strings.Contains(err.Error(), "down: a") {
		t.Fatalf("finish with the owner down: %v; want it to name a", err)
	}
	if _, err := b.node.RemoveMember(ctx, "a"); err != nil {
		t.Fatal(err)
	}
	res, err := b.node.FinishCA(ctx, FinishOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Resealed != 1 {
		t.Fatalf("resealed %d, want 1", res.Resealed)
	}
	for _, tn := range []*apTestNode{b, c} {
		waitUntil(t, 10*time.Second, tn.id+" to serve only the new CA", func() bool {
			return caFP(tn.ca) == plan.NewCAFP && tn.ca.Next() == nil
		})
	}
}

// TestAPCARotationResumesAfterRestart: members restarted at the cutover
// present the new CA again (a master before anything else runs), and the
// finish completes.
func TestAPCARotationResumesAfterRestart(t *testing.T) {
	ctx := t.Context()
	a, b, c := rotationTrio(t)
	plan, err := a.node.RotateCA(ctx, RotateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	// c restarts at the start: it gets on with its node certificate on disk.
	waitUntil(t, 10*time.Second, "c to hold a node certificate of the new CA", func() bool {
		return c.node.nextCert.Load() != nil
	})
	c.stop()
	c.start(t, 2, a.addr)
	prepareRotation(t, c)
	waitUntil(t, 10*time.Second, "b and c to hold the new CA", func() bool {
		return b.ca.HasNextKey() && b.node.nextCert.Load() != nil && c.node.nextCert.Load() != nil
	})
	// The cutover, as a finish moves it on. (Hints and anti-entropy run
	// hourly here: c must be up to get the write at once.)
	waitUntil(t, 10*time.Second, "a to see c alive", func() bool { return c.memberOn(a).State == MemberAlive })
	if err := a.st.CARotations().Advance(ctx, plan.NewCAFP, store.CAStageStarted, store.CAStageCutover, time.Now()); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, 10*time.Second, "b to cut over", func() bool { return b.ca.CutOver() })
	b.stop()
	b.start(t, 2, a.addr)
	if !b.ca.CutOver() || pki.FingerprintHex(b.ca.IssuerOf(b.node.cert.Load().Leaf)) != plan.NewCAFP {
		t.Fatal("b restarted at the cutover serves the old CA")
	}
	prepareRotation(t, b)
	// c, keyless, restarted at the cutover: it holds the new CA in memory
	// only, and cuts over again from its node certificate on disk.
	waitUntil(t, 10*time.Second, "c to cut over", func() bool { return c.ca.CutOver() })
	c.stop()
	c.start(t, 2, a.addr)
	prepareRotation(t, c)
	waitUntil(t, 10*time.Second, "c to cut over again", func() bool {
		return c.ca.CutOver() && pki.FingerprintHex(c.ca.IssuerOf(c.node.cert.Load().Leaf)) == plan.NewCAFP
	})
	if c.ca.HasKey() || c.ca.HasNextKey() {
		t.Fatal("c holds a CA key")
	}
	for _, tn := range []*apTestNode{b, c} {
		waitUntil(t, 10*time.Second, "a to see "+tn.id+" alive", func() bool { return tn.memberOn(a).State == MemberAlive })
	}
	if _, err := a.node.FinishCA(ctx, FinishOptions{}); err != nil {
		t.Fatal(err)
	}
	for _, tn := range []*apTestNode{a, b, c} {
		waitUntil(t, 10*time.Second, tn.id+" to serve only the new CA", func() bool {
			return caFP(tn.ca) == plan.NewCAFP && tn.ca.Next() == nil
		})
	}
}

// fetchNextAs calls FetchCAKey on the master at url for caFP, presenting
// cert and trusting the CAs of trust.
func fetchNextAs(t *testing.T, trust *pki.CA, cert tls.Certificate, url, caFP string, proof []byte) (*clusterv1.FetchCAKeyResponse, error) {
	t.Helper()
	key, err := pki.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	csr, err := pki.NewCSR(key, "x")
	if err != nil {
		t.Fatal(err)
	}
	tlsCfg := pki.PinnedAnyTLSConfig(trust.TrustedCerts(), "127.0.0.1")
	tlsCfg.Certificates = []tls.Certificate{cert}
	tr := &http.Transport{TLSClientConfig: tlsCfg}
	defer tr.CloseIdleConnections()
	cl := clusterv1connect.NewClusterServiceClient(&http.Client{Transport: tr, Timeout: 10 * time.Second}, url)
	resp, err := cl.FetchCAKey(t.Context(), connect.NewRequest(&clusterv1.FetchCAKeyRequest{NewCaFingerprint: caFP, Csr: csr, OldCaKeyProof: proof}))
	if err != nil {
		return nil, err
	}
	return resp.Msg, nil
}

// TestAPCARotationRefusals: during a rotation, the new CA goes to no
// certificate other than a live member's pinned one, never its key to a
// member that is no master, and every refusal is audited; no hub joins and
// masters do not change; an isolated master is denied the rotation.
func TestAPCARotationRefusals(t *testing.T) {
	ctx := t.Context()
	a, b, c := rotationTrio(t)
	// Whoever stole the old CA key could mint these.
	stolen, err := pki.LoadCA(a.dir, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	isolated := policy.NewWithConfig(a.st.Audit(), a.st.Approvals(), policy.Config{})
	isolated.FailClosedWhen(func() bool { return true })
	a.node.SetCAPolicy(isolated)
	if _, err := a.node.ChangeCA(ctx, CARequest{Op: CAOpRotate, Actor: "admin@test"}); !errors.Is(err, policy.ErrDenied) {
		t.Fatalf("rotate on an isolated master: %v, want denied", err)
	}
	prepareRotation(t, a)
	oldFP := caFP(a.ca)
	plan, err := a.node.RotateCA(ctx, RotateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	waitUntil(t, 10*time.Second, "c to hold a node certificate of the new CA", func() bool {
		return c.node.nextCert.Load() != nil
	})
	url := a.node.cfg.AgentURL
	for name, cert := range map[string]tls.Certificate{
		"an old-CA certificate other than the pinned one": mintHubCert(t, stolen, "c"),
		"a hub that is no member":                         mintHubCert(t, stolen, "zz"),
	} {
		if _, err := fetchNextAs(t, c.ca, cert, url, plan.NewCAFP, nil); connect.CodeOf(err) != connect.CodePermissionDenied {
			t.Errorf("fetch with %s: %v, want permission denied", name, err)
		}
	}
	// c's own pinned certificate gets a node certificate, not the key, even
	// claiming on the gossip to be a master: holding the current CA key is
	// what makes one, and c cannot prove it.
	if err := c.node.membership.SetLocal(LocalState{Roles: storageMaster}); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, 5*time.Second, "a to hear c claim master", func() bool { return c.memberOn(a).Roles.Has(RoleMaster) })
	cCert := *c.node.cert.Load()
	resp, err := fetchNextAs(t, c.ca, cCert, url, plan.NewCAFP, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.GetCaKey()) != 0 || len(resp.GetCertificate()) == 0 {
		t.Fatal("a storage member was handed the new CA key, or no node certificate")
	}
	// A proof c could make: by another key, or another caller's.
	forged, err := pki.LoadOrCreateCA(t.TempDir(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	badProof, err := forged.ProveKey(caFP(forged), keyProofMessage(plan.NewCAFP, pki.FingerprintHex(cCert.Leaf)))
	if err != nil {
		t.Fatal(err)
	}
	othersProof, err := a.ca.ProveKey(oldFP, keyProofMessage(plan.NewCAFP, pki.FingerprintHex(a.node.cert.Load().Leaf)))
	if err != nil {
		t.Fatal(err)
	}
	for name, proof := range map[string][]byte{"a forged proof": badProof, "another master's proof": othersProof} {
		if _, err := fetchNextAs(t, c.ca, cCert, url, plan.NewCAFP, proof); connect.CodeOf(err) != connect.CodePermissionDenied {
			t.Errorf("fetch with %s: %v, want permission denied", name, err)
		}
	}
	entries, err := a.st.Audit().Query(ctx, store.AuditFilter{Actions: []string{string(policy.ClusterCAFetchKey)}}, 100)
	if err != nil {
		t.Fatal(err)
	}
	refused := 0
	for _, e := range entries {
		if e.Decision == policy.Deny && strings.HasPrefix(e.Result, "refused") {
			refused++
		}
	}
	if refused < 2 {
		t.Fatalf("audit of the key fetches = %+v; want the refusals (one a minute per caller)", entries)
	}
	// No hub joins, and masters do not change.
	tok, err := pki.NewToken(a.ca.Cert())
	if err != nil {
		t.Fatal(err)
	}
	if err := a.st.JoinTokens().Create(ctx, tok.Secret, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	key, err := pki.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	csr, err := pki.NewCSR(key, "d")
	if err != nil {
		t.Fatal(err)
	}
	js := NewAPJoinServer(a.node, a.st, a.ca, policy.NewWithConfig(a.st.Audit(), a.st.Approvals(), policy.Config{}), testLogger(t))
	if _, err := js.Join(ctx, connect.NewRequest(&clusterv1.JoinRequest{
		TokenSecret: tok.Secret, NodeId: "d", Csr: csr, SchemaVersion: store.SchemaVersion(),
	})); connect.CodeOf(err) != connect.CodeFailedPrecondition || !strings.Contains(err.Error(), "rotation") {
		t.Fatalf("join during a rotation: %v, want refused", err)
	}
	if _, err := a.node.Promote(ctx, "c", RoleMaster); !errors.Is(err, ErrRotationRoles) {
		t.Fatalf("promote: %v, want ErrRotationRoles", err)
	}
	if _, err := a.node.Demote(ctx, "b", RoleMaster); !errors.Is(err, ErrRotationRoles) {
		t.Fatalf("demote: %v, want ErrRotationRoles", err)
	}
	if _, err := b.node.AbortCA(ctx, AbortOptions{}); !errors.Is(err, ErrRotationOwner) {
		t.Fatalf("abort on another master while the owner is alive: %v, want ErrRotationOwner", err)
	}
	// A revoked member's pinned certificate gets nothing.
	if _, err := a.st.Hubs().RevokeCerts(ctx, "c", time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := fetchNextAs(t, c.ca, cCert, url, plan.NewCAFP, nil); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("fetch with a revoked certificate: %v, want permission denied", err)
	}
}

// serveAPControl serves tn's control socket from a short dir and returns a
// client for it.
func serveAPControl(t *testing.T, tn *apTestNode) *ControlClient {
	t.Helper()
	dir := shortDir(t)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- ServeAPControl(ctx, dir, tn.node, testLogger(t)) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("ServeAPControl: %v", err)
		}
	})
	waitForSocket(t, ControlSocketPath(dir), done, 20*time.Millisecond)
	c, err := DialControl(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return c
}

// TestAPCARotationControlSocket: the CLI's rotation steps through a master's
// control socket: the plan, the dry run's decision, the step itself, its
// status, refusals keeping their kind, and rotation commands refused on
// /v1/apply.
func TestAPCARotationControlSocket(t *testing.T) {
	ctx := t.Context()
	a, b, c := rotationTrio(t)
	ca, cb := serveAPControl(t, a), serveAPControl(t, b)
	plan, err := ca.ChangeCA(ctx, CARequest{Op: CAOpRotate, Plan: true, Actor: "admin@test"})
	if err != nil || plan.Rotate == nil || len(plan.Rotate.Pins) != 3 {
		t.Fatalf("plan = %+v, %v", plan, err)
	}
	dry, err := ca.ChangeCA(ctx, CARequest{Op: CAOpRotate, DryRun: true, Actor: "admin@test"})
	if err != nil || dry.Decision != policy.Allow {
		t.Fatalf("dry run = %+v, %v; want allow", dry, err)
	}
	if a.ca.Next() != nil {
		t.Fatal("a dry run started a rotation")
	}
	res, err := ca.ChangeCA(ctx, CARequest{Op: CAOpRotate, Actor: "admin@test"})
	if err != nil || res.Rotate == nil || res.Rotate.NewCAFP == "" {
		t.Fatalf("rotate = %+v, %v", res, err)
	}
	st, err := ca.CAStatus(ctx)
	if err != nil || st.Rotation == nil || st.Rotation.NewCAFP != res.Rotate.NewCAFP || len(st.Hubs) != 3 {
		t.Fatalf("status = %+v, %v", st, err)
	}
	waitUntil(t, 5*time.Second, "b to see the rotation", func() bool { return b.node.rotationActive() })
	if _, err := cb.ChangeCA(ctx, CARequest{Op: CAOpFinish, Actor: "admin@test"}); !errors.Is(err, ErrRotationOwner) {
		t.Fatalf("finish on b: %v, want ErrRotationOwner", err)
	}
	if _, err := ca.Apply(ctx, store.RevokeCACerts{CAFP: res.Rotate.NewCAFP}); err == nil {
		t.Fatal("/v1/apply took a rotation command")
	}
	if _, err := ca.ChangeCA(ctx, CARequest{Op: "explode", Actor: "admin@test"}); err == nil {
		t.Fatal("an unknown step was taken")
	}
	b.node.SetCAPolicy(nil) // as when it is no master
	if _, err := cb.ChangeCA(ctx, CARequest{Op: CAOpAbort, Actor: "admin@test"}); !errors.Is(err, ErrNotMasterHere) {
		t.Fatalf("abort with no master layer: %v, want ErrNotMasterHere", err)
	}
	waitUntil(t, 10*time.Second, "every member to hold the new CA", func() bool {
		return b.ca.HasNextKey() && b.node.nextCert.Load() != nil && c.node.nextCert.Load() != nil
	})
	fin, err := ca.ChangeCA(ctx, CARequest{Op: CAOpFinish, Actor: "admin@test"})
	if err != nil || fin.Finish == nil || fin.Finish.Resealed != 1 {
		t.Fatalf("finish = %+v, %v", fin, err)
	}
}

// TestAPCARotationAgents: agents' certificates across the shards: a finish
// refuses while agents hold only old-CA certificates, unless forced; an
// abort lists the agents the rotation renewed and revokes their new-CA
// certificates on every shard.
func TestAPCARotationAgents(t *testing.T) {
	ctx := t.Context()
	a, b, c := rotationTrio(t)
	oldFP := caFP(a.ca)
	devices := []string{"dev0", "dev1", "dev2", "dev3", "dev4"}
	for i, id := range devices {
		if err := a.st.Devices().Upsert(ctx, device(id, id)); err != nil {
			t.Fatal(err)
		}
		if err := a.st.Certs().Record(ctx, store.CertRecord{
			Serial: fmt.Sprintf("old%d", i), DeviceID: id, Fingerprint: fmt.Sprintf("fp-old%d", i), CAFP: oldFP,
		}); err != nil {
			t.Fatal(err)
		}
	}
	plan, err := a.node.RotateCA(ctx, RotateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	waitUntil(t, 10*time.Second, "every member to hold the new CA", func() bool {
		return b.ca.HasNextKey() && b.node.nextCert.Load() != nil && c.node.nextCert.Load() != nil
	})
	// dev0 renews, as an agent does when it connects.
	if err := a.st.Certs().Record(ctx, store.CertRecord{
		Serial: "new0", DeviceID: "dev0", Fingerprint: "fp-new0", CAFP: plan.NewCAFP,
	}); err != nil {
		t.Fatal(err)
	}
	old, err := a.st.CARotations().OldCADevices(ctx, plan.NewCAFP)
	if err != nil || !slices.Equal(old, devices[1:]) {
		t.Fatalf("old-CA devices = %v, %v; want %v", old, err, devices[1:])
	}
	if _, err := a.node.FinishCA(ctx, FinishOptions{}); !errors.Is(err, ErrOldCAHolders) {
		t.Fatalf("finish with agents on the old CA: %v, want ErrOldCAHolders", err)
	}
	ab, err := a.node.AbortCA(ctx, AbortOptions{})
	if err != nil || !slices.Equal(ab.RenewedDevices, []string{"dev0"}) {
		t.Fatalf("abort = %+v, %v; want dev0 renewed", ab, err)
	}
	for _, tn := range []*apTestNode{a, b, c} {
		if err := tn.st.Certs().Check(ctx, "new0", "dev0"); !errors.Is(err, store.ErrCertRevoked) {
			t.Fatalf("%s: the aborted CA's certificate of dev0: %v, want revoked", tn.id, err)
		}
		if err := tn.st.Certs().Check(ctx, "old0", "dev0"); err != nil {
			t.Fatalf("%s: dev0's old-CA certificate: %v, want still valid", tn.id, err)
		}
	}
	// A new rotation, finished by force: the agents on the old CA are cut
	// off.
	for _, tn := range []*apTestNode{a, b, c} {
		waitUntil(t, 10*time.Second, tn.id+" to drop the aborted CA", func() bool { return tn.ca.Next() == nil })
	}
	plan, err = a.node.RotateCA(ctx, RotateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	waitUntil(t, 10*time.Second, "every member to hold the new CA", func() bool {
		return b.ca.HasNextKey() && b.node.nextCert.Load() != nil && c.node.nextCert.Load() != nil
	})
	fin, err := a.node.FinishCA(ctx, FinishOptions{Force: true})
	if err != nil || !slices.Equal(fin.OldDevices, devices) {
		t.Fatalf("forced finish = %+v, %v; want every device cut off", fin, err)
	}
}
