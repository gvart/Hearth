// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

// seedsOn reads tn's seeds file: each entry's address by node id ("" for
// an address alone).
func seedsOn(tn *apTestNode) map[string]string {
	out := map[string]string{}
	for _, e := range readSeeds(filepath.Join(tn.dir, StateDir, seedsFile)) {
		out[e.id] = e.addr
	}
	return out
}

// hasSeed reports whether tn's seeds file has member id at addr.
func hasSeed(tn *apTestNode, id, addr string) bool {
	got, ok := seedsOn(tn)[id]
	return ok && got == addr
}

// A member back at a new address replaces its old one in the seeds.
func TestSeedsFollowAddressChange(t *testing.T) {
	c := newAPTestCluster(t, 2,
		apSpec{"a", storageMaster, storageMaster},
		apSpec{"b", storageMaster, storageMaster},
	)
	a, b := c["a"], c["b"]
	old := a.addr
	waitUntil(t, 5*time.Second, "b to save a's address", func() bool { return hasSeed(b, "a", old) })
	a.stop()
	a.start(t, 2, "") // a new port, the cluster found by its own seeds
	if a.addr == old {
		t.Fatal("a restarted at its old address")
	}
	waitUntil(t, 10*time.Second, "b to save a's new address", func() bool { return hasSeed(b, "a", a.addr) })
	if got := seedsOn(b); len(got) != 1 {
		t.Errorf("b's seeds = %v, want a's new address only", got)
	}
}

// A removed member leaves the seeds of every member, also of one that has
// not heard of it on the gossip since it restarted.
func TestSeedsPruneRemovedMember(t *testing.T) {
	ctx := t.Context()
	c := newAPTestCluster(t, 2,
		apSpec{"a", storageMaster, storageMaster},
		apSpec{"b", storageMaster, storageMaster},
		apSpec{"c", storageMaster, storageMaster},
	)
	a, b, gone := c["a"], c["b"], c["c"]
	for _, tn := range []*apTestNode{a, b} {
		waitUntil(t, 5*time.Second, tn.id+" to save c's address", func() bool { return hasSeed(tn, "c", gone.addr) })
	}
	gone.stop()
	b.stop()
	b.start(t, 2, "")
	waitUntil(t, 10*time.Second, "b to find a again", func() bool { return a.memberOn(b).State == MemberAlive })
	waitUntil(t, 10*time.Second, "a to see c down", func() bool {
		st := gone.memberOn(a).State
		return st == MemberDead || st == MemberLeft
	})
	if _, err := a.node.RemoveMember(ctx, "c"); err != nil {
		t.Fatal(err)
	}
	for _, tn := range []*apTestNode{a, b} {
		waitUntil(t, 10*time.Second, tn.id+" to drop c from its seeds", func() bool {
			_, ok := seedsOn(tn)["c"]
			return !ok
		})
	}
	if !hasSeed(b, "a", a.addr) {
		t.Errorf("b's seeds = %v, want a's address kept", seedsOn(b))
	}
}

// A member down, or stopped (it left the gossip), keeps its seed: after the
// whole cluster lost power, a hub back first still knows where the others
// were.
func TestSeedsKeepMemberDown(t *testing.T) {
	c := newAPTestCluster(t, 2,
		apSpec{"a", storageMaster, storageMaster},
		apSpec{"b", storageMaster, storageMaster},
		apSpec{"c", storageMaster, storageMaster},
	)
	a, b, down := c["a"], c["b"], c["c"]
	want := map[string]string{"a": a.addr, "c": down.addr}
	waitUntil(t, 5*time.Second, "b to save a's and c's addresses", func() bool {
		got := seedsOn(b)
		return len(got) == 2 && got["a"] == want["a"] && got["c"] == want["c"]
	})
	down.stop()
	waitUntil(t, 10*time.Second, "b to see c down", func() bool {
		st := down.memberOn(b).State
		return st == MemberDead || st == MemberLeft
	})
	time.Sleep(time.Second) // several refreshes
	if !hasSeed(b, "c", down.addr) {
		t.Fatalf("b dropped c, only down, from its seeds: %v", seedsOn(b))
	}

	// The power cut: all down, b back first.
	a.stop()
	b.stop()
	b.start(t, 2, "")
	time.Sleep(time.Second)
	got := seedsOn(b)
	if len(got) != 2 || got["a"] != want["a"] || got["c"] != want["c"] {
		t.Fatalf("b's seeds after a restart alone = %v, want %v", got, want)
	}
	if err := b.node.WaitPeers(t.Context(), 300*time.Millisecond); err == nil {
		t.Fatal("b found a member with all of them down")
	}
}

// The restart of #375: a hub whose only other member was removed does not
// look for it again, up to 30 s, when it restarts.
func TestRestartAfterRemovalDoesNotWait(t *testing.T) {
	ctx := t.Context()
	c := newAPTestCluster(t, 2,
		apSpec{"a", storageMaster, storageMaster},
		apSpec{"b", storageMaster, storageMaster},
	)
	a, b := c["a"], c["b"]
	waitUntil(t, 5*time.Second, "b to save a's address", func() bool { return hasSeed(b, "a", a.addr) })
	a.stop()
	waitUntil(t, 10*time.Second, "b to see a down", func() bool {
		st := a.memberOn(b).State
		return st == MemberDead || st == MemberLeft
	})
	if _, err := b.node.RemoveMember(ctx, "a"); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, 5*time.Second, "b to drop a from its seeds", func() bool { return len(seedsOn(b)) == 0 })
	b.stop()
	b.start(t, 2, "")
	start := time.Now()
	if err := b.node.WaitPeers(ctx, 30*time.Second); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("b waited %v for its removed member", d)
	}
	if b.node.rep.seeking.Load() {
		t.Error("b looks for a cluster it has no other member of")
	}
}

// updateSeeds gives the address alone a join response named its member's
// id once the gossip shows the member there, and keeps one it does not.
func TestSeedsAttachJoinAddress(t *testing.T) {
	c := newAPTestCluster(t, 2,
		apSpec{"a", storageMaster, storageMaster},
		apSpec{"b", storageMaster, storageMaster},
	)
	a, b := c["a"], c["b"]
	path := filepath.Join(b.dir, StateDir, seedsFile)
	want := []seedEntry{{"a", a.addr}, {"", "192.0.2.1:7444"}}
	// b's own refresh may write over the file between the two steps: again.
	waitUntil(t, 5*time.Second, "the join address to get a's id", func() bool {
		if err := os.WriteFile(path, []byte(a.addr+"\n192.0.2.1:7444\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		b.node.updateSeeds()
		return slices.Equal(readSeeds(path), want)
	})
}
