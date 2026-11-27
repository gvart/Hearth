// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/pki"
	"github.com/gvart/hearth/internal/store"
	"github.com/gvart/hearth/internal/store/storetest"
)

// newSeekingNode prepares, without running it, an AP member told to join
// the cluster at seed: its store is bound and its gossip not started, as a
// hub is between opening its store and finding the others.
func newSeekingNode(t *testing.T, ca *pki.CA, id, seed string) (*APNode, *store.Store, func()) {
	t.Helper()
	dir := t.TempDir()
	if err := saveLocalRoles(dir, LocalRoles{Roles: storageMaster}); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	node, err := NewAPNode(t.Context(), APConfig{
		DataDir: dir, NodeID: id, CA: ca, Allowed: storageMaster,
		Listen: ln.Addr().String(), Listener: ln, Advertise: ln.Addr().String(), Seeds: []string{seed},
		Log: testLogger(t),
		Gossip: ReplicatorConfig{
			RequestTimeout: 2 * time.Second, AntiEntropyEvery: time.Hour, HintsEvery: time.Hour, GCEvery: time.Hour,
			LoneMasterWait: time.Nanosecond,
		},
		tuneGossip: func(c *MembershipConfig) {
			c.ProbeInterval, c.ProbeTimeout = 100*time.Millisecond, 80*time.Millisecond
			c.GossipInterval, c.PushPullInterval, c.SuspicionMult = 20*time.Millisecond, time.Second, 2
			c.TCPTimeout, c.RefreshEvery = time.Second, 200*time.Millisecond
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	st := storetest.Open(t, node.StoreOptions()...)
	if err := node.Bind(t.Context(), st); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	run := func() { go func() { _ = node.Run(ctx); close(done) }() }
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
		}
	})
	return node, st, run
}

// criticalWrites are a critical write of each route: a keyed one (an audit
// entry) and a global one (a hub certificate).
func criticalWrites(ctx context.Context, st *store.Store, tag string) []error {
	_, errAudit := st.Audit().Append(ctx, store.AuditEntry{
		TS: time.Now(), ActorKind: "hub", ActorID: "c", Action: "config.import.first", Target: tag,
		Decision: "allow", Result: "ok",
	})
	errCert := st.Hubs().Record(ctx, store.HubCert{Serial: "serial-" + tag, NodeID: "c", Fingerprint: "fp", CAFP: "cafp"})
	return []error{errAudit, errCert}
}

func localCount(t *testing.T, st *store.Store, query string) int64 {
	t.Helper()
	rows, err := st.ReadLocal(t.Context(), query, nil)
	if err != nil {
		t.Fatal(err)
	}
	return rows.Vals[0][0].(int64)
}

// A member told to join a cluster sees a ring of itself alone until its
// gossip finds the others: a critical write it acknowledged then would have
// one copy, lost with the member (the e2e's config.import.first entry of a
// joining hub). It fails fast instead, and writes nothing, until a member
// is found; then it reaches W real copies.
func TestCriticalWriteWaitsForTheCluster(t *testing.T) {
	ctx := t.Context()
	c := newAPTestCluster(t, 2, apSpec{"a", storageMaster, storageMaster})
	a := c["a"]

	node, st, run := newSeekingNode(t, a.ca, "c", a.addr)
	for i, err := range criticalWrites(ctx, st, "before-gossip") {
		if !errors.Is(err, store.ErrUnavailable) {
			t.Errorf("critical write %d before the gossip started: %v, want ErrUnavailable", i, err)
		}
	}
	if n := localCount(t, st, `SELECT count(*) FROM audit_log`); n != 0 {
		t.Errorf("a refused critical write left %d audit entries here", n)
	}
	if n := localCount(t, st, `SELECT count(*) FROM hub_certs WHERE serial = 'serial-before-gossip'`); n != 0 {
		t.Error("a refused critical write left its hub certificate here")
	}

	run()
	if err := node.WaitPeers(ctx, 10*time.Second); err != nil {
		t.Fatal(err)
	}
	if err := node.Replicator().WaitSynced(ctx, 10*time.Second); err != nil {
		t.Fatal(err)
	}
	for i, err := range criticalWrites(ctx, st, "joined") {
		if err != nil {
			t.Fatalf("critical write %d once in the cluster: %v", i, err)
		}
	}
	// Both copies are real: on a too, not a hint on c.
	if n := localCount(t, a.st, `SELECT count(*) FROM audit_log WHERE target = 'joined'`); n != 1 {
		t.Errorf("a holds %d copies of the acknowledged audit entry, want 1", n)
	}
	if n := localCount(t, a.st, `SELECT count(*) FROM hub_certs WHERE serial = 'serial-joined'`); n != 1 {
		t.Error("a does not hold the acknowledged hub certificate")
	}
}

// A member whose seeds lead nowhere refuses critical writes while it looks
// for the cluster, and takes them once it starts alone (StartAlone).
func TestCriticalWriteAloneAfterSeeking(t *testing.T) {
	ctx := t.Context()
	ca := newTestCA(t)
	node, st, run := newSeekingNode(t, ca, "c", freeAddr(t))
	run()
	if err := node.WaitPeers(ctx, 300*time.Millisecond); err == nil {
		t.Fatal("found a member behind a dead seed")
	}
	for i, err := range criticalWrites(ctx, st, "seeking") {
		if !errors.Is(err, store.ErrUnavailable) {
			t.Errorf("critical write %d while seeking: %v, want ErrUnavailable", i, err)
		}
	}
	node.StartAlone()
	for i, err := range criticalWrites(ctx, st, "alone") {
		if err != nil {
			t.Errorf("critical write %d alone: %v", i, err)
		}
	}
}
