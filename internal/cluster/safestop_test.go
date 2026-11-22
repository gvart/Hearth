// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import (
	"slices"
	"strings"
	"testing"

	"github.com/gvart/hearth/internal/store"
)

func TestSafeToStop(t *testing.T) {
	allBuckets := make([]int, store.ShardBuckets)
	for i := range allBuckets {
		allBuckets[i] = i
	}
	caughtUp := func(id string, master bool) safeStopPeer {
		return safeStopPeer{ID: id, Master: master, Live: true, Synced: true}
	}
	three := NewRing([]string{"a", "b", "c"})
	// notOwned are the buckets a does not own on the ring of a, b and c.
	var notOwned, withB []int
	for _, b := range allBuckets {
		owners := three.Owners(b, 2)
		switch {
		case !slices.Contains(owners, "a"):
			notOwned = append(notOwned, b)
		case slices.Contains(owners, "b"):
			withB = append(withB, b)
		}
	}

	tests := []struct {
		name  string
		in    safeStopInput
		safe  bool
		kinds []string
		// member names the member of the replica_behind reason, if one.
		member string
		// says is a part of a reason's message.
		says string
	}{
		{
			name:  "single hub: only copy and no other master",
			in:    safeStopInput{Self: "a", Ring: NewRing([]string{"a"}), N: 1, Held: []int{1, 2, 3}, HoldsGlobal: true},
			kinds: []string{SafeStopNoMaster, SafeStopOnlyCopy},
			says:  "only copy of the rows in 3 buckets",
		},
		{
			name:  "single hub with no rows: still no other master",
			in:    safeStopInput{Self: "a", Ring: NewRing([]string{"a"}), N: 1},
			kinds: []string{SafeStopNoMaster},
		},
		{
			name: "2 storage, 2 masters, caught up: safe",
			in: safeStopInput{
				Self: "a", Ring: NewRing([]string{"a", "b"}), N: 2, Held: allBuckets, HoldsGlobal: true,
				Peers: []safeStopPeer{caughtUp("b", true)},
			},
			safe: true,
		},
		{
			name: "replica behind: no anti-entropy round yet (just joined)",
			in: safeStopInput{
				Self: "a", Ring: NewRing([]string{"a", "b"}), N: 2, Held: []int{7}, HoldsGlobal: true,
				Peers: []safeStopPeer{{ID: "b", Master: true, Live: true}},
			},
			kinds: []string{SafeStopBehind}, member: "b", says: "not finished an anti-entropy round",
		},
		{
			name: "replica behind: syncing after its promotion",
			in: safeStopInput{
				Self: "a", Ring: NewRing([]string{"a", "b"}), N: 2, Held: []int{7, 8},
				Peers: []safeStopPeer{{ID: "b", Master: true, Live: true, Synced: true, Syncing: true}},
			},
			kinds: []string{SafeStopBehind}, member: "b", says: "still copying its rows",
		},
		{
			name: "replica behind: hints waiting for it",
			in: safeStopInput{
				Self: "a", Ring: NewRing([]string{"a", "b"}), N: 2, Held: []int{7},
				Peers: []safeStopPeer{{ID: "b", Master: true, Live: true, Synced: true, Hints: 3}},
			},
			kinds: []string{SafeStopBehind}, member: "b", says: "3 write batches waiting",
		},
		{
			name: "replica down: not safe, and no other master",
			in: safeStopInput{
				Self: "a", Ring: NewRing([]string{"a", "b"}), N: 2, Held: []int{7},
				Peers: []safeStopPeer{{ID: "b", Master: true, Synced: true}},
			},
			kinds: []string{SafeStopNoMaster, SafeStopBehind}, member: "b", says: "is down",
		},
		{
			name: "the other storage member is caught up but no other master",
			in: safeStopInput{
				Self: "a", Ring: NewRing([]string{"a", "b"}), N: 2, Held: allBuckets, HoldsGlobal: true,
				Peers: []safeStopPeer{caughtUp("b", false)},
			},
			kinds: []string{SafeStopNoMaster},
		},
		{
			name: "another master but this hub the only storage member",
			in: safeStopInput{
				Self: "a", Ring: NewRing([]string{"a"}), N: 1, Held: []int{1}, HoldsGlobal: true,
				Peers: []safeStopPeer{caughtUp("m", true)},
			},
			kinds: []string{SafeStopOnlyCopy},
		},
		{
			name: "global rows only, the other member behind",
			in: safeStopInput{
				Self: "a", Ring: NewRing([]string{"b"}), N: 1, HoldsGlobal: true,
				Peers: []safeStopPeer{{ID: "b", Master: true, Live: true}},
			},
			kinds: []string{SafeStopBehind}, member: "b", says: "cluster-wide rows",
		},
		{
			name: "3 storage, c behind: safe while every bucket held is one a shares with b",
			in: safeStopInput{
				Self: "a", Ring: three, N: 2, Held: withB,
				Peers: []safeStopPeer{caughtUp("b", true), {ID: "c", Live: true}},
			},
			safe: true,
		},
		{
			name: "3 storage, c behind: the buckets a shares with c alone are not covered",
			in: safeStopInput{
				Self: "a", Ring: three, N: 2, Held: allBuckets, HandedOff: func(int) bool { return true },
				Peers: []safeStopPeer{caughtUp("b", true), {ID: "c", Live: true}},
			},
			kinds: []string{SafeStopBehind}, member: "c",
		},
		{
			name: "rows held for other owners not handed off",
			in: safeStopInput{
				Self: "a", Ring: three, N: 2, Held: notOwned[:5],
				Peers: []safeStopPeer{caughtUp("b", true), caughtUp("c", false)},
			},
			kinds: []string{SafeStopHandOff}, says: "5 buckets",
		},
		{
			name: "rows held for other owners handed off: safe",
			in: safeStopInput{
				Self: "a", Ring: three, N: 2, Held: notOwned[:5], HandedOff: func(int) bool { return true },
				Peers: []safeStopPeer{caughtUp("b", true), caughtUp("c", false)},
			},
			safe: true,
		},
		{
			name: "writes in flight",
			in: safeStopInput{
				Self: "a", Ring: NewRing([]string{"a", "b"}), N: 2, Held: []int{1}, InFlight: 1,
				Peers: []safeStopPeer{caughtUp("b", true)},
			},
			kinds: []string{SafeStopInFlight}, says: "1 write still",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := safeToStop(tt.in)
			if got.Safe != tt.safe {
				t.Fatalf("safe = %v, want %v (reasons %+v)", got.Safe, tt.safe, got.Reasons)
			}
			var kinds []string
			said := tt.says == ""
			for _, r := range got.Reasons {
				if !slices.Contains(kinds, r.Kind) {
					kinds = append(kinds, r.Kind)
				}
				if r.Message == "" {
					t.Errorf("reason %s has no message", r.Kind)
				}
				if r.Kind == SafeStopBehind && tt.member != "" && r.Member != tt.member {
					t.Errorf("replica_behind names %q, want %q", r.Member, tt.member)
				}
				said = said || strings.Contains(r.Message, tt.says)
			}
			if !slices.Equal(kinds, tt.kinds) {
				t.Errorf("kinds = %v, want %v (reasons %+v)", kinds, tt.kinds, got.Reasons)
			}
			if !said {
				t.Errorf("no reason says %q: %+v", tt.says, got.Reasons)
			}
		})
	}
}

func TestNoteSynced(t *testing.T) {
	r := &Replicator{}
	if r.syncedOn("b", "a,b") {
		t.Fatal("synced before any round")
	}
	r.noteSynced("b", "a,b", true)
	if !r.syncedOn("b", "a,b") {
		t.Fatal("not synced after a round")
	}
	if r.syncedOn("b", "a,b,c") {
		t.Fatal("synced on a ring the round did not run on")
	}
	r.noteSynced("b", "a,b", false)
	if r.syncedOn("b", "a,b") {
		t.Fatal("still synced after a failed round")
	}
}

// Two members: safe once both are caught up, not while the other is down
// or has hints waiting, safe again once it has them.
func TestSafeToStopTwoMembers(t *testing.T) {
	ctx := t.Context()
	an := newAPNet(t, 2, "a", "b")
	a := an.m("a")
	check := func() SafeStop {
		t.Helper()
		in, err := a.rep.safeStopInput(ctx, apPeers{net: an, self: "a"}.Members())
		if err != nil {
			t.Fatal(err)
		}
		return safeToStop(in)
	}
	if err := a.st.Devices().Upsert(ctx, device("dev-1", "v1")); err != nil {
		t.Fatal(err)
	}
	// Until a round with b (as when b has just joined), b counts as
	// catching up.
	a.rep.noteSynced("b", "", false)
	if ss := check(); ss.Safe {
		t.Fatal("safe to stop before any anti-entropy round with b")
	}
	a.rep.antiEntropy(ctx)
	apEventually(t, "a safe to stop", func() bool { return check().Safe })

	an.setDown("b", true)
	if err := a.st.Devices().Upsert(ctx, device("dev-1", "v2")); err != nil {
		t.Fatal(err)
	}
	a.rep.antiEntropy(ctx)
	if ss := check(); ss.Safe {
		t.Fatal("safe to stop while the only other member is down")
	}

	an.setDown("b", false)
	a.rep.antiEntropy(ctx)
	if n, _ := a.hints.Count(ctx, "b"); n == 0 {
		t.Fatal("no hint kept for b while it was down")
	}
	if ss := check(); ss.Safe {
		t.Fatal("safe to stop with hints waiting for b")
	}
	a.rep.deliverHints(ctx)
	if ss := check(); !ss.Safe {
		t.Fatalf("not safe once b caught up: %+v", ss.Reasons)
	}

	// b leaves (off the ring: no hints kept for it), a writes, b comes
	// back on the same ring: not safe until a round with it.
	an.mu.Lock()
	an.unknown[[2]string{"a", "b"}] = true
	an.mu.Unlock()
	a.rep.view()
	if err := a.st.Devices().Upsert(ctx, device("dev-1", "v3")); err != nil {
		t.Fatal(err)
	}
	an.mu.Lock()
	delete(an.unknown, [2]string{"a", "b"})
	an.mu.Unlock()
	if ss := check(); ss.Safe {
		t.Fatal("safe to stop right after b came back, before a round with it")
	}
	a.rep.antiEntropy(ctx)
	if ss := check(); !ss.Safe {
		t.Fatalf("not safe after a round with b: %+v", ss.Reasons)
	}
}
