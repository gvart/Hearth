// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/raft"

	"github.com/gvart/hearth/internal/store"
)

func TestReplicatesToFollowers(t *testing.T) {
	nodes := threeNodes(t, newTestCA(t))
	leader := leaderOf(t, nodes...)
	if leader.ID() != "n1" {
		t.Fatalf("leader = %s, want the bootstrap node", leader.ID())
	}
	upsert(t, leader, "pi")
	for _, n := range nodes {
		eventually(t, "pi on "+n.ID(), func() bool { return hasDevice(n, "pi") })
	}
	st, err := nodes[2].Status()
	if err != nil {
		t.Fatal(err)
	}
	if st.State != "Follower" || st.LeaderID != "n1" || len(st.Peers) != 3 || st.AppliedIndex == 0 {
		t.Fatalf("follower status = %+v", st)
	}
	for _, p := range st.Peers {
		if p.Suffrage != "Voter" {
			t.Errorf("peer %s is %s, want Voter", p.ID, p.Suffrage)
		}
	}
}

func TestBootstrapKeepsPreClusterState(t *testing.T) {
	ca := newTestCA(t)
	// A standalone hub with data, then clustered.
	dir := t.TempDir()
	st, err := store.Open(t.Context(), dir+"/hearth.db")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if err := st.Devices().Upsert(t.Context(), store.Device{ID: "old", FirstSeen: now, LastSeen: now}); err != nil {
		t.Fatal(err)
	}
	_ = st.Close()

	n1 := startNode(t, ca, "n1", dir, "", true)
	leaderOf(t, n1)
	if !hasDevice(n1, "old") {
		t.Fatal("bootstrap lost the pre-cluster device")
	}
	// A node that joins later gets it through the bootstrap snapshot.
	n2 := startNode(t, ca, "n2", "", "", false)
	addVoter(t, n1, n2)
	eventually(t, "pre-cluster device on n2", func() bool { return hasDevice(n2, "old") })
}

func TestFollowerApplierReturnsErrNotLeader(t *testing.T) {
	nodes := threeNodes(t, newTestCA(t))
	leader := leaderOf(t, nodes...)
	for _, n := range nodes {
		if n == leader {
			continue
		}
		eventually(t, n.ID()+" to know the leader", func() bool { return n.Leader().ID != "" })
		now := time.Now()
		err := n.st.Devices().Upsert(t.Context(), store.Device{ID: "x", FirstSeen: now, LastSeen: now})
		var nl *ErrNotLeader
		if !errors.As(err, &nl) {
			t.Fatalf("%s: err = %v, want *ErrNotLeader", n.ID(), err)
		}
		if nl.LeaderID != leader.ID() || nl.LeaderAddr != leader.Addr() {
			t.Errorf("%s: ErrNotLeader = %+v, want %s at %s", n.ID(), nl, leader.ID(), leader.Addr())
		}
		if hasDevice(n, "x") {
			t.Errorf("%s wrote locally despite not being the leader", n.ID())
		}
	}
}

func TestLeaderFailoverKeepsCommittedWrites(t *testing.T) {
	nodes := threeNodes(t, newTestCA(t))
	old := leaderOf(t, nodes...)
	changes := make(chan LeaderInfo, 16)
	for _, n := range nodes {
		if n != old {
			n.OnLeaderChange(func(l LeaderInfo) { changes <- l })
		}
	}
	const writes = 20
	for i := range writes {
		upsert(t, old, fmt.Sprintf("d%02d", i))
	}
	old.stop() // crash: no leadership transfer

	leader := leaderOf(t, nodes...)
	if leader == old {
		t.Fatal("no new leader")
	}
	// A new leader may still be applying entries committed under the old one.
	if err := leader.WaitReady(t.Context()); err != nil {
		t.Fatal(err)
	}
	for i := range writes {
		if !hasDevice(leader, fmt.Sprintf("d%02d", i)) {
			t.Fatalf("new leader %s lost committed write d%02d", leader.ID(), i)
		}
	}
	// The cluster keeps working with two of three.
	upsert(t, leader, "after")
	for _, n := range nodes {
		if !n.down {
			eventually(t, "after on "+n.ID(), func() bool { return hasDevice(n, "after") })
		}
	}
	deadline := time.After(waitFor)
	for {
		select {
		case l := <-changes:
			if l.ID == leader.ID() {
				return
			}
		case <-deadline:
			t.Fatal("no leader-change notification for the new leader")
		}
	}
}

func TestTokenSingleUseAcrossCluster(t *testing.T) {
	nodes := threeNodes(t, newTestCA(t))
	leader := leaderOf(t, nodes...)
	ctx := t.Context()
	now := time.Now()
	if err := leader.st.Tokens().Create(ctx, "tok", nil, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	// Concurrent consumers on the leader: exactly one wins.
	var wins atomic.Int32
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			if _, err := leader.st.Tokens().Consume(ctx, "tok", now); err == nil {
				wins.Add(1)
			} else if !errors.Is(err, store.ErrTokenUsed) {
				t.Errorf("consume: %v", err)
			}
		})
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("%d consumes won, want 1", wins.Load())
	}
	// After failover the new leader agrees the token is spent.
	leader.stop()
	next := leaderOf(t, nodes...)
	if _, err := next.st.Tokens().Consume(ctx, "tok", now); !errors.Is(err, store.ErrTokenUsed) {
		t.Fatalf("consume on new leader: err = %v, want ErrTokenUsed", err)
	}
}

func TestLateJoinerInstallsSnapshot(t *testing.T) {
	ca := newTestCA(t)
	compact := func(c *Config) { c.TrailingLogs = 2 }
	n1 := startNode(t, ca, "n1", "", "", true, compact)
	leaderOf(t, n1)
	n2 := startNode(t, ca, "n2", "", "", false, compact)
	addVoter(t, n1, n2)
	for i := range 30 {
		upsert(t, n1, fmt.Sprintf("d%02d", i))
	}
	if err := n1.raft.Snapshot().Error(); err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	first, err := n1.bolt.FirstIndex()
	if err != nil {
		t.Fatal(err)
	}
	if first <= 3 {
		t.Fatalf("log not compacted (first index %d); the test would not need a snapshot", first)
	}

	n3 := startNode(t, ca, "n3", "", "", false, compact)
	addVoter(t, n1, n3)
	eventually(t, "every write on the late joiner", func() bool { return hasDevice(n3, "d29") && hasDevice(n3, "d00") })
	snaps, err := raft.NewFileSnapshotStore(n3.dir+"/raft", 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	if list, err := snaps.List(); err != nil || len(list) == 0 {
		t.Fatalf("late joiner has no installed snapshot: %v, %v", list, err)
	}
	// Restarting the late joiner restores its snapshot and keeps the data.
	n3.stop()
	n3 = startNode(t, ca, "n3", n3.dir, n3.Addr(), false, compact)
	eventually(t, "data after restart", func() bool { return hasDevice(n3, "d29") })
	upsert(t, n1, "after-restart")
	eventually(t, "new write after restart", func() bool { return hasDevice(n3, "after-restart") })
}

func TestRestartReplaysWithoutDuplicates(t *testing.T) {
	ca := newTestCA(t)
	n1 := startNode(t, ca, "n1", "", "", true)
	leaderOf(t, n1)
	ctx := t.Context()
	for i := range 3 {
		if _, err := n1.st.Audit().Append(ctx, store.AuditEntry{ActorKind: "a", ActorID: "b", Action: fmt.Sprint(i), Decision: "allow"}); err != nil {
			t.Fatal(err)
		}
	}
	dir, addr := n1.dir, n1.Addr()
	n1.stop()
	n1 = startNode(t, ca, "n1", dir, addr, false)
	if err := n1.WaitReady(t.Context()); err != nil {
		t.Fatal(err)
	}
	entries, err := n1.st.Audit().List(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 {
		t.Fatalf("after restart: %d audit entries, want 3 (log replayed onto the old state?)", len(entries))
	}
}
