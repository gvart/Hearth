// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import (
	"context"
	"errors"
	"maps"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/pki"
	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

func TestPlanKeepMasters(t *testing.T) {
	t0 := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	in := func(id string, r RoleSet, state string) MemberInfo {
		return MemberInfo{ID: id, Roles: r, AllowedRoles: storageMaster, State: state}
	}
	alive := func(id string, r RoleSet) MemberInfo { return in(id, r, MemberAlive) }
	two := []MemberInfo{alive("a", storageMaster), alive("b", storageMaster)}
	with := func(ms ...MemberInfo) []MemberInfo { return append(slices.Clone(two), ms...) }
	el := map[string]time.Time{"c": t0, "d": t0.Add(time.Minute), "e": t0.Add(time.Minute)}
	tests := []struct {
		name     string
		members  []MemberInfo
		down     map[string]downMember
		coming   int
		eligible map[string]time.Time
		keep     int
		// pick is the member promoted; refused, if set, a part of why none is.
		pick, refused string
	}{
		{name: "2 masters and an eligible storage member", members: with(alive("c", storageOnly)), eligible: el, keep: 3, pick: "c"},
		{name: "3 masters", members: with(alive("m", storageMaster), alive("c", storageOnly)), eligible: el, keep: 3},
		{
			name:    "manual-joined storage members are not eligible",
			members: with(alive("x", storageOnly), alive("y", storageOnly)), eligible: el, keep: 3,
			refused: "hub-eligible",
		},
		{
			// A hub stopped cleanly leaves: it counts until it is removed.
			name:    "a master that left counts until removed",
			members: with(in("m", storageMaster, MemberLeft), alive("c", storageOnly)), eligible: el, keep: 3,
		},
		{
			name:    "a master recorded down counts until removed",
			members: with(alive("c", storageOnly)), down: map[string]downMember{"m": {Since: t0, Roles: storageMaster}},
			eligible: el, keep: 3,
		},
		{
			name:    "a master on its way counts",
			members: with(alive("c", storageOnly)), coming: 1, eligible: el, keep: 3,
		},
		{
			name:    "never past the cap of 3",
			members: with(alive("m", storageMaster), alive("c", storageOnly)), eligible: el, keep: 5,
		},
		{name: "keep 2", members: with(alive("c", storageOnly)), eligible: el, keep: 2},
		{name: "keep 0 never promotes", members: []MemberInfo{alive("a", storageMaster), alive("c", storageOnly)}, eligible: el},
		{
			name: "minority side never promotes",
			members: []MemberInfo{
				alive("a", storageMaster), alive("c", storageOnly),
				in("x", storageOnly, MemberDead), in("y", storageOnly, MemberDead), in("z", storageOnly, MemberDead),
			},
			eligible: el, keep: 3, refused: "not a majority",
		},
		{
			name: "only a live storage member that allows master, not syncing nor draining",
			members: with(
				in("c", storageOnly, MemberSuspect),
				MemberInfo{ID: "d", Roles: storageOnly, AllowedRoles: storageOnly, State: MemberAlive},
				MemberInfo{ID: "e", Roles: storageOnly, AllowedRoles: storageMaster, State: MemberAlive, Draining: true},
				MemberInfo{ID: "f", Roles: storageOnly, AllowedRoles: storageMaster, State: MemberAlive, Syncing: true},
			),
			eligible: map[string]time.Time{"c": t0, "d": t0, "e": t0, "f": t0}, keep: 3, refused: "hub-eligible",
		},
		{
			name:    "the one that joined first",
			members: with(alive("e", storageOnly), alive("d", storageOnly), alive("c", storageOnly)), eligible: el, keep: 3,
			pick: "c",
		},
		{
			name:    "then the lowest node ID",
			members: with(alive("e", storageOnly), alive("d", storageOnly)), eligible: el, keep: 3, pick: "d",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			for range 3 {
				p := planKeepMasters("a", tc.members, tc.down, tc.coming, tc.eligible, tc.keep)
				if p.Pick != tc.pick || (tc.refused == "") != (p.Refused == "") || !strings.Contains(p.Refused, tc.refused) {
					t.Fatalf("plan = %+v, want pick %q refused %q", p, tc.pick, tc.refused)
				}
				// The pick does not depend on the order the gossip lists.
				slices.Reverse(tc.members)
			}
		})
	}
}

// keepCluster starts masters a, b and m, and storage member c, which allows
// master and is hub-eligible if eligible says so, with --keep-masters 3 on
// a, and returns the loop of a with pol. Only a and c hold rows, both
// copies of each: a reads its own, and m's removal moves none.
func keepCluster(t *testing.T, eligible bool, polCfg policy.Config) (map[string]*apTestNode, *masterKeeper) {
	t.Helper()
	ca, err := pki.LoadOrCreateCA(t.TempDir(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	c := map[string]*apTestNode{}
	var seed string
	for _, s := range []apSpec{
		{"a", storageMaster, storageMaster},
		{"b", masterOnly, masterOnly},
		{"m", masterOnly, masterOnly},
		{"c", storageOnly, storageMaster},
	} {
		tn := prepareAPTestNode(t, ca, s)
		tn.keepMasters = 3
		tn.start(t, 2, seed)
		if seed == "" {
			seed = tn.addr
		}
		c[s.id] = tn
	}
	for _, tn := range c {
		waitUntil(t, 20*time.Second, tn.id+" to see every member", func() bool {
			n := 0
			for _, m := range tn.node.Membership().Members() {
				if m.State == MemberAlive {
					n++
				}
			}
			return n == 4
		})
	}
	// Critical writes need both replicas: under load a write may find one
	// unreachable for a moment, so the setup's writes are tried again.
	for _, tn := range c {
		waitUntil(t, 15*time.Second, "the node certificate of "+tn.id+" recorded", func() bool {
			return recordNodeCert(t.Context(), tn, slices.Collect(maps.Values(c))...) == nil
		})
	}
	// c joined with a join token: minted for it as a device, or an admin's.
	ctx := t.Context()
	device := ""
	if eligible {
		device = "dev-c"
	}
	var last error
	defer func() {
		if t.Failed() {
			t.Log("last error:", last)
		}
	}()
	waitUntil(t, 30*time.Second, "c's join token created", func() bool {
		last = c["a"].st.JoinTokens().CreateFor(ctx, "join-c", time.Now().Add(time.Hour), "storage", device)
		return last == nil || strings.Contains(last.Error(), "already exists")
	})
	waitUntil(t, 30*time.Second, "c's join token used", func() bool {
		_, last = c["a"].st.JoinTokens().Use(ctx, "join-c", "c", time.Now())
		return last == nil || errors.Is(last, store.ErrTokenUsed)
	})
	pol := policy.NewWithConfig(c["a"].st.Audit(), c["a"].st.Approvals(), polCfg)
	return c, &masterKeeper{n: c["a"].node, pol: pol, retryAfter: time.Hour, waitFor: time.Minute}
}

// removeMaster stops m and removes it from the cluster, as an admin does,
// once a sees it down: until then it counts.
func removeMaster(t *testing.T, c map[string]*apTestNode, k *masterKeeper) {
	t.Helper()
	c["m"].stop()
	waitUntil(t, 15*time.Second, "a to see m down", func() bool {
		s := c["m"].memberOn(c["a"]).State
		return s == MemberDead || s == MemberLeft
	})
	again(k)
	if c["c"].memberOn(c["a"]).Roles.Has(RoleMaster) || promotes(t, c["a"]) != nil {
		t.Fatal("c promoted while m, down, was not removed")
	}
	waitUntil(t, 15*time.Second, "m removed", func() bool {
		_, err := c["a"].node.RemoveMember(t.Context(), "m")
		return err == nil
	})
	waitUntil(t, 15*time.Second, "a to drop m from the members down", func() bool {
		_, down := c["a"].node.down.snapshot()["m"]
		return !down
	})
}

// again runs a round of k now, as if no promotion had failed before.
func again(k *masterKeeper) {
	k.retry = time.Time{}
	k.round(context.Background(), time.Now())
}

// promotes returns the cluster.promote audit entries on tn.
func promotes(t *testing.T, tn *apTestNode) []store.AuditEntry {
	t.Helper()
	var entries []store.AuditEntry
	waitUntil(t, 15*time.Second, "the audit log read", func() bool {
		var err error
		entries, err = tn.st.Audit().Query(t.Context(), store.AuditFilter{Actions: []string{string(policy.ClusterPromote)}}, 10)
		return err == nil
	})
	return entries
}

// TestKeepMastersPromotes: once a master is removed and 2 are left, the
// hub-eligible storage member c is promoted to master, audited as
// cluster.promote by the hub with its reason; it holds the CA key, and no
// further member is promoted.
func TestKeepMastersPromotes(t *testing.T) {
	c, k := keepCluster(t, true, policy.Config{})
	removeMaster(t, c, k)
	waitUntil(t, 30*time.Second, "c promoted", func() bool { again(k); return c["c"].node.IsMaster() })
	if !c["c"].ca.HasKey() {
		t.Fatal("c is a master without the CA key")
	}
	found := false
	for _, e := range promotes(t, c["a"]) {
		if e.ActorKind == policy.ActorHub && e.ActorID == "a" && e.Target == "c" && e.Decision == policy.Allow &&
			strings.Contains(string(e.Detail), "keep 3 masters") {
			found = true
		}
	}
	if !found {
		t.Fatalf("no cluster.promote of c by hub a with its reason: %+v", promotes(t, c["a"]))
	}
	waitUntil(t, 15*time.Second, "a to see c master", func() bool { return c["c"].memberOn(c["a"]).Roles.Has(RoleMaster) })
	before := len(promotes(t, c["a"]))
	again(k)
	if got := len(promotes(t, c["a"])); got != before {
		t.Fatalf("%d cluster.promote entries after a round with 3 masters, want %d", got, before)
	}
}

// TestKeepMastersLoop: the loop itself promotes c once m is removed.
func TestKeepMastersLoop(t *testing.T) {
	c, k := keepCluster(t, true, policy.Config{})
	removeMaster(t, c, k)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = c["a"].node.RunKeepMasters(ctx, k.pol); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	waitUntil(t, 30*time.Second, "c to be promoted", func() bool { return c["c"].node.IsMaster() })
}

// TestKeepMastersNotEligible: a storage member that joined with an admin's
// join token is never promoted, and nothing is asked of the policy.
func TestKeepMastersNotEligible(t *testing.T) {
	c, k := keepCluster(t, false, policy.Config{})
	removeMaster(t, c, k)
	again(k)
	if c["c"].node.IsMaster() || len(promotes(t, c["a"])) != 0 {
		t.Fatalf("c promoted, or tried, though it is not hub-eligible: %+v", promotes(t, c["a"]))
	}
	if !strings.Contains(k.logged, "hub-eligible") {
		t.Fatalf("the round logged %q, want that no member is hub-eligible", k.logged)
	}
}

// TestKeepMastersPolicyDenied: a policy that denies dangerous actions
// denies the promotion too; c stays storage, the denial is audited, and the
// next try waits.
func TestKeepMastersPolicyDenied(t *testing.T) {
	c, k := keepCluster(t, true, policy.Config{Classes: map[policy.Class]policy.Mode{policy.Dangerous: policy.ModeDeny}})
	removeMaster(t, c, k)
	var entries []store.AuditEntry
	waitUntil(t, 30*time.Second, "the promotion denied", func() bool {
		again(k)
		entries = promotes(t, c["a"])
		return len(entries) > 0
	})
	for _, e := range entries {
		if e.Decision != policy.Deny || e.ActorKind != policy.ActorHub || e.Target != "c" {
			t.Fatalf("cluster.promote entry %+v, want a denial of c by the hub", e)
		}
	}
	if c["c"].node.IsMaster() || c["c"].ca.HasKey() {
		t.Fatal("c promoted though the policy denies it")
	}
	// The next try waits.
	k.round(t.Context(), time.Now())
	if got := len(promotes(t, c["a"])); got != len(entries) {
		t.Fatalf("%d cluster.promote entries right after a denial, want %d", got, len(entries))
	}
}

// TestKeepMastersNotDuringRotation: no promotion while a hub CA rotation is
// under way; the one after it is.
func TestKeepMastersNotDuringRotation(t *testing.T) {
	c, k := keepCluster(t, true, policy.Config{})
	removeMaster(t, c, k)
	c["a"].node.rot.Store(&store.CARotation{Stage: store.CAStageStarted})
	again(k)
	c["a"].node.rot.Store(nil)
	if c["c"].node.IsMaster() || len(promotes(t, c["a"])) != 0 {
		t.Fatal("c promoted, or tried, during a hub CA rotation")
	}
	waitUntil(t, 30*time.Second, "c promoted after the rotation", func() bool { again(k); return c["c"].node.IsMaster() })
}

// TestKeepMastersOnAnotherMaster: the master keeping the masters need not
// be the one that removed m: b promotes c once a removed m.
func TestKeepMastersOnAnotherMaster(t *testing.T) {
	c, ka := keepCluster(t, true, policy.Config{})
	removeMaster(t, c, ka)
	pol := policy.NewWithConfig(c["b"].st.Audit(), c["b"].st.Approvals(), policy.Config{})
	kb := &masterKeeper{n: c["b"].node, pol: pol, retryAfter: time.Hour, waitFor: time.Minute}
	waitUntil(t, 30*time.Second, "b to promote c", func() bool { again(kb); return c["c"].node.IsMaster() })
}
