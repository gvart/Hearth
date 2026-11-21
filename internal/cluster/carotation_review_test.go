// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
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
			// The log may also reach it between the read and this write:
			// then the stage moved on by itself.
			if rot, _ := missed.st.CARotations().Latest(ctx); !errors.Is(err, store.ErrCARotationConflict) || rot.Stage == step[0] {
				t.Fatal(err)
			}
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

// A next CA whose rotation never started (a leader made it, its start was
// lost with its leadership) is never trusted or used to sign on the hub, now
// a follower, that holds it, and that hub drops it once it has caught up.
func TestCARotationOrphanNextOnFollower(t *testing.T) {
	ctx := t.Context()
	hubs, _ := startRotationHubs(t)
	leader := rotLeader(t, hubs)
	follower := otherHubs(hubs, leader)[0]
	oldCA := follower.ca.Cert()
	orphan, err := follower.ca.GenerateNext(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	key, err := pki.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	signed, err := follower.ca.SignClientKey(key.Public(), "pi", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if signed.CheckSignatureFrom(oldCA) != nil || signed.CheckSignatureFrom(orphan) == nil {
		t.Error("the orphan next CA signed a certificate")
	}
	if follower.ca.NextActive() || len(follower.ca.TrustedCerts()) != 1 {
		t.Error("the orphan next CA is trusted")
	}
	follower.kickCA()
	eventually(t, "the follower to drop the orphan next CA", func() bool { return follower.ca.Next() == nil })
	for _, f := range []string{pki.NextCACertFile, pki.NextCAKeyFile} {
		if _, err := os.Stat(filepath.Join(follower.dir, f)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s left after the drop: %v", f, err)
		}
	}
	// A rotation still works afterwards.
	recordHubCerts(t, hubs)
	plan, err := leader.RotateCA(ctx, RotateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	waitNext(t, hubs, plan.NewCAFP)
}

// A hub that restarts restores a snapshot and replays the log after it.
// Taken during a rotation that was then aborted, the snapshot shows that
// rotation under way, not the one that followed: until the replay is done, the hub
// must keep the next CA of the later rotation, key, node certificate and
// files (#230).
func TestCARotationRestartKeepsNextOfALaterRotation(t *testing.T) {
	ctx := t.Context()
	hubs, _ := startRotationHubs(t)
	leader := rotLeader(t, hubs)
	recordHubCerts(t, hubs)
	follower := otherHubs(hubs, leader)[0]

	first, err := leader.RotateCA(ctx, RotateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	waitNext(t, hubs, first.NewCAFP)
	if err := follower.raft.Snapshot().Error(); err != nil {
		t.Fatalf("snapshot with the first rotation under way: %v", err)
	}
	// The gate entry follows the snapshot, so a replay held on it still
	// shows the first rotation under way.
	upsert(t, leader.testNode, "pi")
	gate := time.UnixMilli(1_000_000).UTC()
	if _, err := leader.st.Devices().SetBootTime(ctx, "pi", gate); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the gate entry on "+follower.ID(), func() bool {
		d, err := follower.st.Devices().Get(ctx, "pi")
		return err == nil && d.BootTime.Equal(gate)
	})
	if _, err := leader.AbortCA(ctx, AbortOptions{}); err != nil {
		t.Fatalf("AbortCA: %v", err)
	}
	eventually(t, follower.ID()+" to drop the first rotation's CA", func() bool {
		return follower.localCAInfo().NextFP == ""
	})
	second, err := leader.RotateCA(ctx, RotateOptions{})
	if err != nil {
		t.Fatalf("RotateCA after the abort: %v", err)
	}
	waitNext(t, hubs, second.NewCAFP)

	// Restart the follower with its apply held on the gate entry.
	obs := &gatedObserver{
		gate: gate.UnixMilli(), entered: make(chan struct{}), release: make(chan struct{}),
		local: map[int64]bool{},
	}
	dir, addr, id := follower.dir, follower.Addr(), follower.ID()
	follower.stop()
	ca, err := pki.LoadOrCreateCA(dir, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	bind := func(n *Node, s *store.Store) store.Applier {
		n.ObserveApplies(obs)
		return n.BindForwarding(s)
	}
	restarted := &rotHub{testNode: startNodeBound(t, ca, id, dir, addr, false, bind, rotTune), ca: ca}
	var release sync.Once
	open := func() { release.Do(func() { close(obs.release) }) }
	t.Cleanup(open)
	select {
	case <-obs.entered:
	case <-time.After(waitFor):
		t.Fatal("the restarted hub did not replay the gate entry")
	}
	rot, err := restarted.st.CARotations().Latest(ctx)
	if err != nil || rot.NewCAFP != first.NewCAFP || !rot.Active() {
		t.Fatalf("the replaying store shows %+v, %v; want the first rotation under way", rot, err)
	}

	holdsSecond := func() error {
		i := restarted.localCAInfo()
		if i.NextFP != second.NewCAFP || !i.HasNextKey || !i.HasNextCert {
			return fmt.Errorf("next CA %s, key %v, node certificate %v; want %s with both",
				i.NextFP, i.HasNextKey, i.HasNextCert, second.NewCAFP)
		}
		for _, f := range []string{pki.NextCACertFile, pki.NextCAKeyFile, filepath.Join(RaftDir, nextNodeCertFile), filepath.Join(RaftDir, nextNodeKeyFile)} {
			if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
				return fmt.Errorf("%s: %w", f, err)
			}
		}
		return nil
	}
	// A follower drops a next CA no earlier than its second run (#234).
	for range 3 {
		restarted.reconcileCA(ctx)
	}
	if err := holdsSecond(); err != nil {
		t.Fatalf("the hub dropped the next CA of the later rotation while replaying: %v", err)
	}
	open()
	eventually(t, id+" to catch up", func() bool {
		rot, err := restarted.st.CARotations().Latest(ctx)
		return err == nil && rot.NewCAFP == second.NewCAFP && restarted.caughtUp()
	})
	restarted.reconcileCA(ctx)
	if err := holdsSecond(); err != nil {
		t.Fatalf("after the replay: %v", err)
	}
}

// A hub restarted from a snapshot taken during a rotation that was aborted
// since replays a store that shows it under way. It must not trust the
// aborted rotation's CA meanwhile: the abort cut off the certificates that
// CA signed (#232).
func TestCARotationReplayDoesNotTrustAnAbortedCA(t *testing.T) {
	ctx := t.Context()
	hubs, thief := startRotationHubs(t)
	leader := rotLeader(t, hubs)
	recordHubCerts(t, hubs)
	follower := otherHubs(hubs, leader)[0]

	aborted, err := leader.RotateCA(ctx, RotateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	waitNext(t, hubs, aborted.NewCAFP)
	// A node certificate the aborted rotation's CA signed.
	signed, err := x509.ParseCertificate(follower.nextCert.Load().Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := follower.raft.Snapshot().Error(); err != nil {
		t.Fatalf("snapshot with the rotation under way: %v", err)
	}
	// The gate entry follows the snapshot, so a replay held on it still
	// shows the rotation under way.
	upsert(t, leader.testNode, "pi")
	gate := time.UnixMilli(1_000_000).UTC()
	if _, err := leader.st.Devices().SetBootTime(ctx, "pi", gate); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the gate entry on "+follower.ID(), func() bool {
		d, err := follower.st.Devices().Get(ctx, "pi")
		return err == nil && d.BootTime.Equal(gate)
	})
	if _, err := leader.AbortCA(ctx, AbortOptions{}); err != nil {
		t.Fatalf("AbortCA: %v", err)
	}
	eventually(t, follower.ID()+" to drop the aborted rotation's CA", func() bool {
		return follower.localCAInfo().NextFP == ""
	})

	// Restart the follower with its apply held on the gate entry.
	obs := &gatedObserver{
		gate: gate.UnixMilli(), entered: make(chan struct{}), release: make(chan struct{}),
		local: map[int64]bool{},
	}
	dir, addr, id := follower.dir, follower.Addr(), follower.ID()
	follower.stop()
	ca, err := pki.LoadOrCreateCA(dir, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	bind := func(n *Node, s *store.Store) store.Applier {
		n.ObserveApplies(obs)
		return n.BindForwarding(s)
	}
	restarted := &rotHub{testNode: startNodeBound(t, ca, id, dir, addr, false, bind, rotTune), ca: ca}
	var release sync.Once
	open := func() { release.Do(func() { close(obs.release) }) }
	t.Cleanup(open)
	select {
	case <-obs.entered:
	case <-time.After(waitFor):
		t.Fatal("the restarted hub did not replay the gate entry")
	}
	rot, err := restarted.st.CARotations().Latest(ctx)
	if err != nil || rot.NewCAFP != aborted.NewCAFP || !rot.Active() {
		t.Fatalf("the replaying store shows %+v, %v; want the aborted rotation under way", rot, err)
	}
	trusts := func() error {
		if fp := restarted.localCAInfo().NextFP; fp != "" {
			return fmt.Errorf("next CA %s", fp)
		}
		if issuer := restarted.ca.IssuerOf(signed); issuer != nil {
			return fmt.Errorf("trusted CA %s issued a certificate of the aborted CA", pki.FingerprintHex(issuer))
		}
		if _, err := signed.Verify(x509.VerifyOptions{Roots: restarted.ca.Pool(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err == nil {
			return errors.New("the trust pool accepts a certificate of the aborted CA")
		}
		return nil
	}
	// A run takes the index the store must reach; later runs check it.
	for range 3 {
		restarted.reconcileCA(ctx)
	}
	if err := trusts(); err != nil {
		t.Fatalf("the replaying hub trusts the aborted rotation's CA: %v", err)
	}
	// The pins still hold meanwhile (#216): an old-CA hub certificate other
	// than the pinned one is refused.
	if err := restarted.checkPeerCert(mintHubCert(t, thief, leader.ID()).Leaf); !errors.Is(err, errNotPinned) {
		t.Fatalf("peer check of an unpinned old-CA certificate while replaying = %v, want errNotPinned", err)
	}
	open()
	eventually(t, restarted.ID()+" to catch up", func() bool {
		rot, err := restarted.st.CARotations().Latest(ctx)
		return err == nil && rot.Stage == store.CAStageAborted && restarted.caughtUp()
	})
	restarted.reconcileCA(ctx)
	if err := trusts(); err != nil {
		t.Fatalf("after the replay: %v", err)
	}
}

// Under steady writes a follower's store rarely reflects the commit index of
// the moment, but every follower still trusts the new CA and fetches its key.
func TestCARotationTrustsTheNewCAUnderSteadyWrites(t *testing.T) {
	ctx := t.Context()
	hubs, _ := startRotationHubs(t)
	leader := rotLeader(t, hubs)
	recordHubCerts(t, hubs)

	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			now := time.Now()
			id := fmt.Sprintf("d%d", i%50)
			_ = leader.st.Devices().Upsert(ctx, store.Device{ID: id, Name: id, FirstSeen: now, LastSeen: now})
		}
	}()
	defer func() {
		close(stop)
		<-done
	}()
	plan, err := leader.RotateCA(ctx, RotateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	waitNext(t, hubs, plan.NewCAFP)
}

// Under steady writes a follower's log rarely holds no entry past the commit
// index, yet a follower still drops a leftover next CA in bounded time
// (#234).
func TestCARotationDropsAnOrphanNextUnderSteadyWrites(t *testing.T) {
	ctx := t.Context()
	hubs, _ := startRotationHubs(t)
	leader := rotLeader(t, hubs)
	follower := otherHubs(hubs, leader)[0]

	var writes atomic.Int64
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		tick := time.NewTicker(time.Second / 60)
		defer tick.Stop()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			case <-tick.C:
			}
			now := time.Now()
			id := fmt.Sprintf("d%d", i%50)
			if leader.st.Devices().Upsert(ctx, store.Device{ID: id, Name: id, FirstSeen: now, LastSeen: now}) == nil {
				writes.Add(1)
			}
		}
	}()
	defer func() {
		close(stop)
		<-done
	}()
	eventually(t, "the writes to flow", func() bool { return writes.Load() >= 10 })

	if _, err := follower.ca.GenerateNext(time.Now()); err != nil {
		t.Fatal(err)
	}
	start, before := time.Now(), writes.Load()
	const bound = 5 * time.Second // 50 reconcile periods
	for follower.ca.Next() != nil {
		if time.Since(start) > bound {
			t.Fatalf("the follower still holds the orphan next CA after %v (%d writes meanwhile)",
				bound, writes.Load()-before)
		}
		time.Sleep(10 * time.Millisecond)
	}
	elapsed := time.Since(start)
	t.Logf("dropped after %v, %.0f writes/s", elapsed, float64(writes.Load()-before)/elapsed.Seconds())
	for _, f := range []string{pki.NextCACertFile, pki.NextCAKeyFile} {
		if _, err := os.Stat(filepath.Join(follower.dir, f)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s left after the drop: %v", f, err)
		}
	}
}

// The point a follower waits for before it drops a leftover next CA belongs
// to that CA. A hub that, as leader in between, made another next CA and
// proposed its start after that point must keep the new one until its log
// has settled past it too (#234).
func TestCARotationDropWaitsAgainForAnotherNextCA(t *testing.T) {
	ctx := t.Context()
	hubs, _ := startRotationHubs(t)
	leader := rotLeader(t, hubs)
	f := otherHubs(hubs, leader)[0]
	// Restarted so that only this test runs the follower's reconcile.
	dir, addr, id := f.dir, f.Addr(), f.ID()
	f.stop()
	ca, err := pki.LoadOrCreateCA(dir, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	slow := func(c *Config) { c.CAReconcileEvery = time.Hour }
	follower := startNodeBound(t, ca, id, dir, addr, false, (*Node).BindForwarding, rotTune, slow)
	upsert(t, leader.testNode, "pi")
	eventually(t, id+" to catch up", follower.caughtUp)

	setBoot := func(ms int64) {
		t.Helper()
		if _, err := leader.st.Devices().SetBootTime(ctx, "pi", time.UnixMilli(ms).UTC()); err != nil {
			t.Fatal(err)
		}
	}
	// gate makes the follower's store stop after the entry, written through
	// the leader, that sets the boot time to ms. It returns a wait for that
	// entry and the release.
	gate := func(ms int64) (wait, open func()) {
		obs := &gatedObserver{gate: ms, entered: make(chan struct{}), release: make(chan struct{}), local: map[int64]bool{}}
		follower.ObserveApplies(obs)
		var once sync.Once
		open = func() { once.Do(func() { close(obs.release) }) }
		t.Cleanup(open)
		setBoot(ms)
		wait = func() {
			select {
			case <-obs.entered:
			case <-time.After(waitFor):
				t.Fatal("the gate entry was not applied on the follower")
			}
			setBoot(ms + 1) // the store is behind the log by this entry
			last := leader.raft.LastIndex()
			eventually(t, id+" to hold the entry its store is behind by", func() bool {
				return follower.raft.LastIndex() >= last
			})
		}
		return wait, open
	}

	waitFirst, openFirst := gate(1_000_000)
	waitFirst()
	if _, err := ca.GenerateNext(time.Now()); err != nil {
		t.Fatal(err)
	}
	follower.reconcileCA(ctx) // takes the point to wait for
	if ca.Next() == nil {
		t.Fatal("dropped the next CA while the store was behind")
	}
	// Past that point now, with the store still behind the log.
	waitSecond, openSecond := gate(2_000_000)
	openFirst()
	waitSecond()
	eventually(t, "the store past the point", func() bool {
		follower.recMu.Lock()
		defer follower.recMu.Unlock()
		return follower.appliedThrough(follower.dropAt)
	})
	if follower.caughtUp() {
		t.Fatal("caught up while the store holds the second gate")
	}
	// Another next CA, as RotateCA would make it.
	if err := ca.DropNext(); err != nil {
		t.Fatal(err)
	}
	other, err := ca.GenerateNext(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for range 3 {
		follower.reconcileCA(ctx)
	}
	if next := ca.Next(); next == nil || !next.Equal(other) {
		t.Fatal("dropped another next CA at the point taken for the first one")
	}
	openSecond()
	eventually(t, id+" to drop the other next CA once settled", func() bool {
		follower.reconcileCA(ctx)
		return ca.Next() == nil
	})
}

// A hub that cut over to a new CA, and next reconciles only after the
// rotation finished and another one started, finishes the first rotation:
// its next CA is the cluster's CA now, not a leftover of another rotation.
func TestCARotationFinishOvertakenByTheNextRotation(t *testing.T) {
	ctx := t.Context()
	hubs, _ := startRotationHubs(t)
	leader := rotLeader(t, hubs)
	recordHubCerts(t, hubs)
	f := otherHubs(hubs, leader)[0]

	first, err := leader.RotateCA(ctx, RotateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	waitNext(t, hubs, first.NewCAFP)
	finished := make(chan error, 1)
	go func() {
		_, err := leader.FinishCA(ctx, FinishOptions{})
		finished <- err
	}()
	// Hold the follower's reconcile from the moment it cut over.
	for {
		f.recMu.Lock()
		if f.ca.CutOver() {
			break
		}
		f.recMu.Unlock()
		time.Sleep(time.Millisecond)
	}
	held := true
	unhold := func() {
		if held {
			held = false
			f.recMu.Unlock()
		}
	}
	defer unhold()
	select {
	case err := <-finished:
		if err != nil {
			t.Fatalf("FinishCA: %v", err)
		}
	case <-time.After(waitFor):
		t.Fatal("FinishCA did not return")
	}
	// The finish closed the old-CA connections; the hubs reconnect.
	var second RotatePlan
	var rotErr error
	eventually(t, "a second rotation to start", func() bool {
		second, rotErr = leader.RotateCA(ctx, RotateOptions{})
		return rotErr == nil
	})
	eventually(t, f.ID()+"'s store to show the second rotation", func() bool {
		rot, err := f.st.CARotations().Latest(ctx)
		return err == nil && rot.NewCAFP == second.NewCAFP
	})
	if fp := pki.FingerprintHex(f.ca.Next()); fp != first.NewCAFP || !f.ca.CutOver() {
		t.Fatalf("precondition: next CA %s, cut over %v; want %s, cut over", fp, f.ca.CutOver(), first.NewCAFP)
	}

	unhold()
	eventually(t, f.ID()+" on the first rotation's CA, with the second one's next", func() bool {
		f.kickCA()
		next := f.ca.Next()
		return pki.FingerprintHex(f.ca.Cert()) == first.NewCAFP &&
			next != nil && pki.FingerprintHex(next) == second.NewCAFP
	})
	if f.halted.Load() {
		t.Fatal("the hub stopped")
	}
}
