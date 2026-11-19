// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/hashicorp/raft"

	"github.com/gvart/hearth/internal/integrations/kubernetes"
	"github.com/gvart/hearth/internal/pki"
	"github.com/gvart/hearth/internal/policy"
	clusterv1 "github.com/gvart/hearth/internal/proto/hearth/cluster/v1"
	"github.com/gvart/hearth/internal/store"
)

// recordHubCerts records every hub's node certificate and waits until every
// hub sees them all.
func recordHubCerts(t *testing.T, hubs []*rotHub) {
	t.Helper()
	ctx := t.Context()
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
}

// waitNext waits until every hub of hubs holds the new CA's key and a node
// certificate of it.
func waitNext(t *testing.T, hubs []*rotHub, newFP string) {
	t.Helper()
	for _, h := range hubs {
		eventually(t, h.ID()+" to hold the new key and a node certificate of it", func() bool {
			i := h.localCAInfo()
			return i.NextFP == newFP && i.HasNextKey && i.HasNextCert
		})
	}
}

// restartRotHub restarts h on its data dir and address, loading its CA from
// disk as a hub process does, and serves it again.
func restartRotHub(t *testing.T, leader, h *rotHub) *rotHub {
	t.Helper()
	dir, addr, id := h.dir, h.Addr(), h.ID()
	h.stop()
	ca, err := pki.LoadOrCreateCA(dir, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	n := startNodeBound(t, ca, id, dir, addr, false, (*Node).BindForwarding, rotTune)
	r := &rotHub{testNode: n, ca: ca}
	r.serve(t)
	if err := leader.st.Hubs().SetAgentURL(t.Context(), id, r.url); err != nil {
		t.Fatal(err)
	}
	return r
}

func otherHubs(hubs []*rotHub, leader *rotHub) []*rotHub {
	var out []*rotHub
	for _, h := range hubs {
		if h != leader {
			out = append(out, h)
		}
	}
	return out
}

// --accept-unpinned covers agents only: a hub presenting a certificate
// without a recorded fingerprint never gets the new key.
func TestCARotationNeverPinsAnUnrecordedHub(t *testing.T) {
	hubs, _ := startRotationHubs(t)
	leader := rotLeader(t, hubs)
	plan, err := leader.RotateCA(t.Context(), RotateOptions{AcceptUnpinned: true})
	if !errors.Is(err, ErrUnpinnedCerts) || !strings.Contains(err.Error(), "--accept-unpinned or not") {
		t.Fatalf("RotateCA --accept-unpinned with unrecorded hubs = %v, want a refusal", err)
	}
	if len(plan.Pins) != 0 || leader.ca.Next() != nil {
		t.Fatalf("an unrecorded hub was pinned (%v), or a next CA made", plan.Pins)
	}
}

// A start whose propose fails ambiguously (the leadership lost after the
// entry was appended) keeps the new key: the rotation started, and it can
// finish. A next CA no rotation uses is dropped once the log shows none.
func TestCARotationKeepsKeyOnAmbiguousStart(t *testing.T) {
	ctx := t.Context()
	hubs, _ := startRotationHubs(t)
	leader := rotLeader(t, hubs)
	recordHubCerts(t, hubs)

	// A leftover next CA of an attempt that never reached the log.
	if _, err := leader.ca.GenerateNext(time.Now()); err != nil {
		t.Fatal(err)
	}
	leader.kickCA()
	eventually(t, "the leader to drop a next CA no rotation uses", func() bool { return leader.ca.Next() == nil })

	leader.rotateProposed = func(err error) error {
		if err != nil {
			return err
		}
		return applyFailed("start_ca_rotation", raft.ErrLeadershipLost)
	}
	plan, err := leader.RotateCA(ctx, RotateOptions{})
	if !errors.Is(err, raft.ErrLeadershipLost) {
		t.Fatalf("RotateCA = %v, want the lost leadership", err)
	}
	leader.rotateProposed = nil
	if next := leader.ca.Next(); next == nil || pki.FingerprintHex(next) != plan.NewCAFP || !leader.ca.HasNextKey() {
		t.Fatal("the leader dropped the only copy of the new key")
	}
	if rot, err := leader.st.CARotations().Active(ctx); err != nil || rot.NewCAFP != plan.NewCAFP {
		t.Fatalf("the rotation did not start: %+v, %v", rot, err)
	}
	// The reconcile loop keeps a next CA the rotation under way uses.
	leader.reconcileCA(ctx)
	if leader.ca.Next() == nil {
		t.Fatal("the reconcile loop dropped the key of the rotation under way")
	}
	waitNext(t, hubs, plan.NewCAFP)
	if _, err := leader.FinishCA(ctx, FinishOptions{}); err != nil {
		t.Fatalf("FinishCA after the ambiguous start: %v", err)
	}
	for _, h := range hubs {
		eventually(t, h.ID()+" to finish", func() bool { return h.localCAInfo().ServingFP == plan.NewCAFP && h.ca.Next() == nil })
	}
}

// Abort gives up a rotation before its cutover: every hub drops the new CA,
// and joining is allowed again. After the cutover it is refused, and a hub
// that claims to serve the new CA must show it.
func TestCARotationAbort(t *testing.T) {
	ctx := t.Context()
	hubs, _ := startRotationHubs(t)
	leader := rotLeader(t, hubs)
	recordHubCerts(t, hubs)
	follower := otherHubs(hubs, leader)[0]

	var nl *ErrNotLeader
	if _, err := follower.AbortCA(ctx, AbortOptions{}); !errors.As(err, &nl) {
		t.Fatalf("AbortCA on a follower = %v, want *ErrNotLeader", err)
	}
	if _, err := leader.AbortCA(ctx, AbortOptions{}); !errors.Is(err, ErrNoRotation) {
		t.Fatalf("AbortCA with no rotation = %v, want ErrNoRotation", err)
	}
	plan, err := leader.RotateCA(ctx, RotateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	waitNext(t, hubs, plan.NewCAFP)
	now := time.Now()
	if err := leader.st.Devices().Upsert(ctx, store.Device{ID: "pi", FirstSeen: now, LastSeen: now}); err != nil {
		t.Fatal(err)
	}
	if err := leader.st.Certs().Record(ctx, store.CertRecord{Serial: "0b", DeviceID: "pi", CAFP: plan.NewCAFP}); err != nil {
		t.Fatal(err)
	}
	dry, err := serveControl(t, leader.testNode).AbortCA(ctx, AbortOptions{DryRun: true})
	if err != nil || len(dry.RenewedDevices) != 1 || dry.RenewedDevices[0] != "pi" || leader.ca.Next() == nil {
		t.Fatalf("abort dry run = %+v, %v; want pi listed and nothing changed", dry, err)
	}
	// A join is refused for the rotation before the token is checked.
	joinErr := func() error {
		key, err := pki.NewKey()
		if err != nil {
			t.Fatal(err)
		}
		csr, err := pki.NewCSR(key, "n4")
		if err != nil {
			t.Fatal(err)
		}
		_, err = NewJoinServer(leader.Node, leader.st, leader.ca, policy.New(leader.st.Audit()), testLogger(t)).
			Join(ctx, connect.NewRequest(&clusterv1.JoinRequest{
				TokenSecret: "not a token", NodeId: "n4", RaftAddress: freeAddr(t), Csr: csr,
				SchemaVersion: store.SchemaVersion(), ClusterEpochs: true,
			}))
		return err
	}
	if err := joinErr(); err == nil || !strings.Contains(err.Error(), "rotation") {
		t.Fatalf("Join during the rotation = %v, want a refusal naming it", err)
	}
	if _, err := leader.AbortCA(ctx, AbortOptions{}); err != nil {
		t.Fatalf("AbortCA: %v", err)
	}
	if err := joinErr(); err == nil || strings.Contains(err.Error(), "rotation") {
		t.Errorf("Join after the abort = %v, want only the bad token refused", err)
	}
	for _, h := range hubs {
		eventually(t, h.ID()+" to drop the new CA", func() bool {
			i := h.localCAInfo()
			return i.NextFP == "" && !i.HasNextKey && !i.HasNextCert
		})
		for _, f := range []string{pki.NextCACertFile, pki.NextCAKeyFile, filepath.Join(RaftDir, nextNodeCertFile), filepath.Join(RaftDir, nextNodeKeyFile)} {
			if _, err := os.Stat(filepath.Join(h.dir, f)); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("%s: %s left after the abort: %v", h.ID(), f, err)
			}
		}
	}
	if _, err := leader.st.CARotations().Active(ctx); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("a rotation is still under way after the abort: %v", err)
	}

	// Another rotation, taken to its cutover, cannot be aborted. The device
	// renewed by the aborted one must enroll again: it is left out.
	plan, err = leader.RotateCA(ctx, RotateOptions{AcceptUnpinned: true})
	if err != nil {
		t.Fatalf("RotateCA after an abort: %v", err)
	}
	waitNext(t, hubs, plan.NewCAFP)
	// Before the cutover no hub shows a server certificate of the new CA.
	if _, err := leader.hubCAInfoServedBy(ctx, follower.ID(), follower.Addr(), plan.NewCAFP); err == nil {
		t.Error("a hub serving the old CA passed for one serving the new CA")
	}
	if err := leader.advanceCA(ctx, plan.NewCAFP, store.CAStageStarted, store.CAStageCutover); err != nil {
		t.Fatal(err)
	}
	for _, h := range hubs {
		eventually(t, h.ID()+" to cut over", func() bool { return h.localCAInfo().CutOver })
	}
	if _, err := leader.hubCAInfoServedBy(ctx, follower.ID(), follower.Addr(), plan.NewCAFP); err != nil {
		t.Errorf("CAInfo of a hub serving the new CA: %v", err)
	}
	if _, err := leader.AbortCA(ctx, AbortOptions{}); !errors.Is(err, store.ErrCARotationConflict) {
		t.Fatalf("AbortCA after the cutover = %v, want ErrCARotationConflict", err)
	}
	if _, err := leader.FinishCA(ctx, FinishOptions{Force: true}); err != nil {
		t.Fatalf("FinishCA after a refused abort: %v", err)
	}
}

// A hub restarted between the cutover and the finish serves, and seals
// with, the new CA from its start: a secret it seals then opens with the new
// key alone, before and after the finish.
func TestCARotationRestartAtCutover(t *testing.T) {
	ctx := t.Context()
	hubs, _ := startRotationHubs(t)
	leader := rotLeader(t, hubs)
	recordHubCerts(t, hubs)
	plan, err := leader.RotateCA(ctx, RotateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	waitNext(t, hubs, plan.NewCAFP)
	if err := leader.advanceCA(ctx, plan.NewCAFP, store.CAStageStarted, store.CAStageCutover); err != nil {
		t.Fatal(err)
	}
	for _, h := range hubs {
		eventually(t, h.ID()+" to cut over", func() bool { return h.localCAInfo().CutOver })
	}
	restarted := restartRotHub(t, leader, otherHubs(hubs, leader)[0])
	if !restarted.ca.CutOver() {
		t.Fatal("a hub restarted at the cutover does not serve the new CA from its start")
	}
	sealed, err := restarted.sealers[store.SealedKubeClusters].Seal("k1", []byte("kubeconfig"))
	if err != nil {
		t.Fatal(err)
	}
	newKey, err := restarted.ca.NextKeyDER()
	if err != nil {
		t.Fatal(err)
	}
	newOnly, err := kubernetes.NewPurposeSealer(newKey, sealInfos[store.SealedKubeClusters])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newOnly.Open("k1", sealed); err != nil {
		t.Fatalf("a secret sealed by the restarted hub does not open with the new key: %v", err)
	}
	if err := restarted.st.KubeClusters().Add(ctx, store.KubeCluster{ID: "k1", Name: "lab", Sealed: sealed, CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if _, err := leader.FinishCA(ctx, FinishOptions{}); err != nil {
		t.Fatalf("FinishCA: %v", err)
	}
	secrets, err := leader.st.CARotations().Sealed(ctx)
	if err != nil || len(secrets) != 1 {
		t.Fatalf("Sealed = %v, %v", secrets, err)
	}
	if got, err := newOnly.Open("k1", secrets[0].Sealed); err != nil || !bytes.Equal(got, []byte("kubeconfig")) {
		t.Errorf("the kubeconfig after the finish: %q, %v", got, err)
	}
}

// A secret sealed with the old key after the last re-seal check refuses the
// finish, which checks again: no secret is left sealed with a key that goes.
func TestCARotationFinishRechecksLateSeals(t *testing.T) {
	ctx := t.Context()
	hubs, _ := startRotationHubs(t)
	leader := rotLeader(t, hubs)
	recordHubCerts(t, hubs)
	oldKeys, err := leader.ca.KeyDERs()
	if err != nil {
		t.Fatal(err)
	}
	oldOnly, err := kubernetes.NewPurposeSealer(oldKeys[0], sealInfos[store.SealedKubeClusters])
	if err != nil {
		t.Fatal(err)
	}
	plan, err := leader.RotateCA(ctx, RotateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	waitNext(t, hubs, plan.NewCAFP)
	first, err := oldOnly.Seal("k1", []byte("kubeconfig"))
	if err != nil {
		t.Fatal(err)
	}
	if err := leader.st.KubeClusters().Add(ctx, store.KubeCluster{ID: "k1", Name: "lab", Sealed: first, CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	reseal := *leader.resealer.Load()
	injected := false
	leader.SetResealer(func(ctx context.Context, secrets []store.SealedSecret) ([]store.SealedSecret, error) {
		stale, err := reseal(ctx, secrets)
		if err != nil || len(stale) > 0 || injected {
			return stale, err
		}
		injected = true // after the check that finds none left
		late, err := oldOnly.Seal("late", []byte("late kubeconfig"))
		if err != nil {
			return nil, err
		}
		return nil, leader.st.KubeClusters().Add(ctx, store.KubeCluster{ID: "late", Name: "late", Sealed: late, CreatedAt: time.Now()})
	})
	if _, err := leader.FinishCA(ctx, FinishOptions{}); err != nil {
		t.Fatalf("FinishCA: %v", err)
	}
	if !injected {
		t.Fatal("no secret was sealed after the check")
	}
	newKeys, err := leader.ca.KeyDERs()
	if err != nil {
		t.Fatal(err)
	}
	newOnly, err := kubernetes.NewPurposeSealer(newKeys[0], sealInfos[store.SealedKubeClusters])
	if err != nil {
		t.Fatal(err)
	}
	secrets, err := leader.st.CARotations().Sealed(ctx)
	if err != nil || len(secrets) != 2 || secrets[1].ID != "late" {
		t.Fatalf("Sealed = %v, %v", secrets, err)
	}
	if got, err := newOnly.Open("late", secrets[1].Sealed); err != nil || string(got) != "late kubeconfig" {
		t.Errorf("the secret sealed after the check, after the finish: %q, %v", got, err)
	}
}

// A hub a rotation finished without (it never got the new key) drops the
// old CA and every CA key, and stops: it never serves the old CA again.
func TestCARotationMissedHubStops(t *testing.T) {
	ctx := t.Context()
	hubs, _ := startRotationHubs(t)
	leader := rotLeader(t, hubs)
	recordHubCerts(t, hubs)
	missed := otherHubs(hubs, leader)[1]
	missed.stopCA() // it never fetches the new key
	plan, err := leader.RotateCA(ctx, RotateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	waitNext(t, otherHubs(hubs, missed), plan.NewCAFP)
	eventually(t, "the rotation to reach the hub left behind", func() bool {
		rot, err := missed.st.CARotations().Latest(ctx)
		return err == nil && rot.NewCAFP == plan.NewCAFP
	})
	fp, err := leader.FinishCA(ctx, FinishOptions{Force: true})
	if err != nil {
		t.Fatalf("forced FinishCA: %v", err)
	}
	if len(fp.OldHubs) != 1 || fp.OldHubs[0] != missed.ID() {
		t.Fatalf("FinishCA cut off %v, want %s", fp.OldHubs, missed.ID())
	}
	// The leader cut the hub off as it finished, so the log may never reach
	// it: hand it the entries it lacks as if they had, and run its loop once.
	for _, step := range [][2]string{{store.CAStageStarted, store.CAStageCutover}, {store.CAStageCutover, store.CAStageFinished}} {
		if rot, _ := missed.st.CARotations().Latest(ctx); rot.Stage != step[0] {
			continue
		}
		if _, err := missed.st.ApplyLocal(ctx, store.AdvanceCARotation{NewCAFP: plan.NewCAFP, From: step[0], To: step[1]}); err != nil {
			t.Fatal(err)
		}
	}
	missed.reconcileCA(ctx)
	select {
	case err := <-missed.fatal:
		if !errors.Is(err, errMissedRotation) {
			t.Errorf("stopped with %v, want errMissedRotation", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the hub that missed the rotation did not stop")
	}
	if pki.FingerprintHex(missed.ca.Cert()) != plan.NewCAFP || missed.ca.Next() != nil {
		t.Error("the hub that missed the rotation still trusts the old CA")
	}
	for _, f := range []string{pki.CAKeyFile, pki.NextCAKeyFile} {
		if _, err := os.Stat(filepath.Join(missed.dir, f)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s left on the hub that missed the rotation: %v", f, err)
		}
	}
	if _, err := pki.LoadOrCreateCA(missed.dir, time.Now()); err == nil {
		t.Error("the hub that missed the rotation can start again")
	}
}
