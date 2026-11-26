// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/pki"
	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

func TestPlanDead(t *testing.T) {
	t0 := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	const after = time.Hour
	alive := func(id string, r RoleSet) MemberInfo { return MemberInfo{ID: id, Roles: r, State: MemberAlive} }
	in := func(id string, r RoleSet, state string) MemberInfo { return MemberInfo{ID: id, Roles: r, State: state} }
	down := func(r RoleSet) downMember { return downMember{Since: t0, Roles: r} }
	tests := []struct {
		name    string
		members []MemberInfo
		down    map[string]downMember
		// want is the verdict on each member down: "" if it may be removed,
		// else a part of the refusal.
		want map[string]string
	}{
		{
			name:    "majority removes",
			members: []MemberInfo{alive("a", storageMaster), alive("b", storageMaster), in("c", storageMaster, MemberDead)},
			down:    map[string]downMember{"c": down(storageMaster)},
			want:    map[string]string{"c": ""},
		},
		{
			name:    "a member that left counts as down",
			members: []MemberInfo{alive("a", storageMaster), alive("b", storageMaster), in("c", storageOnly, MemberLeft)},
			down:    map[string]downMember{"c": down(storageOnly)},
			want:    map[string]string{"c": ""},
		},
		{
			name:    "two hubs: one alive is no majority",
			members: []MemberInfo{alive("a", storageMaster), in("b", storageMaster, MemberDead)},
			down:    map[string]downMember{"b": down(storageMaster)},
			want:    map[string]string{"b": "not a majority"},
		},
		{
			name: "minority side of a split never removes",
			members: []MemberInfo{
				alive("a", storageMaster), in("b", storageMaster, MemberDead), in("c", storageMaster, MemberDead),
			},
			down: map[string]downMember{"b": down(storageMaster), "c": down(storageMaster)},
			want: map[string]string{"b": "not a majority", "c": "not a majority"},
		},
		{
			name: "even split never removes",
			members: []MemberInfo{
				alive("a", storageMaster), alive("b", storageMaster),
				in("c", storageMaster, MemberDead), in("d", storageMaster, MemberDead),
			},
			down: map[string]downMember{"c": down(storageMaster), "d": down(storageMaster)},
			want: map[string]string{"c": "not a majority", "d": "not a majority"},
		},
		{
			// After a restart the gossip knows no dead member: the record does.
			name:    "restarted minority master counts the members it recorded",
			members: []MemberInfo{alive("a", storageMaster)},
			down:    map[string]downMember{"b": down(storageMaster), "c": down(storageMaster)},
			want:    map[string]string{"b": "not a majority", "c": "not a majority"},
		},
		{
			name: "suspect is not counted alive",
			members: []MemberInfo{
				alive("a", storageMaster), in("b", storageMaster, MemberSuspect), in("c", storageMaster, MemberDead),
			},
			down: map[string]downMember{"c": down(storageMaster)},
			want: map[string]string{"c": "not a majority"},
		},
		{
			name: "last live storage member is never removed",
			members: []MemberInfo{
				alive("a", masterOnly), alive("b", masterOnly), in("c", storageOnly, MemberDead),
			},
			down: map[string]downMember{"c": down(storageOnly)},
			want: map[string]string{"c": "last live storage member"},
		},
		{
			name: "a draining storage member does not count",
			members: []MemberInfo{
				alive("a", masterOnly),
				{ID: "b", Roles: storageOnly, State: MemberAlive, Draining: true},
				in("c", storageOnly, MemberDead),
			},
			down: map[string]downMember{"c": down(storageOnly)},
			want: map[string]string{"c": "last live storage member"},
		},
		{
			name: "roles come from the record when the gossip forgot them",
			members: []MemberInfo{
				alive("a", masterOnly), alive("b", masterOnly), alive("d", masterOnly),
			},
			down: map[string]downMember{"c": down(storageOnly)},
			want: map[string]string{"c": "last live storage member"},
		},
		{
			name:    "a member back alive is not planned",
			members: []MemberInfo{alive("a", storageMaster), alive("b", storageMaster), alive("c", storageMaster)},
			down:    map[string]downMember{"c": down(storageMaster)},
			want:    map[string]string{},
		},
		{
			name:    "itself is never planned",
			members: []MemberInfo{alive("a", storageMaster), alive("b", storageMaster), alive("c", storageMaster)},
			down:    map[string]downMember{"a": down(storageMaster)},
			want:    map[string]string{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := map[string]string{}
			for _, v := range planDead("a", tt.members, tt.down, after) {
				if !v.At.Equal(t0.Add(after)) {
					t.Errorf("%s due at %v, want %v", v.ID, v.At, t0.Add(after))
				}
				got[v.ID] = v.Refused
			}
			if len(got) != len(tt.want) {
				t.Fatalf("verdicts %v, want %v", got, tt.want)
			}
			for id, want := range tt.want {
				refused, ok := got[id]
				switch {
				case !ok:
					t.Errorf("no verdict on %s", id)
				case want == "" && refused != "":
					t.Errorf("%s refused (%s), want removed", id, refused)
				case want != "" && !strings.Contains(refused, want):
					t.Errorf("%s: refused %q, want %q", id, refused, want)
				}
			}
		})
	}
}

// TestDownTracker: a member is down from when it was first seen down; one
// that comes back starts over; the record survives a restart, unless it
// went unwatched for too long.
func TestDownTracker(t *testing.T) {
	t0 := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	st := func(id, state string) []MemberInfo {
		return []MemberInfo{{ID: "a", State: MemberAlive}, {ID: id, Roles: storageMaster, State: state}}
	}
	type step struct {
		at      time.Duration
		members []MemberInfo
	}
	tests := []struct {
		name  string
		steps []step
		// reload, if set, reloads the record this long after the last step.
		reload time.Duration
		// wantSince is when b is down since, relative to t0; -1: not down.
		wantSince time.Duration
	}{
		{name: "down from the first sight", steps: []step{{0, st("b", MemberDead)}, {time.Minute, st("b", MemberDead)}}, wantSince: 0},
		{name: "suspect is up", steps: []step{{0, st("b", MemberSuspect)}}, wantSince: -1},
		{
			name:      "a flap starts the timer over",
			steps:     []step{{0, st("b", MemberDead)}, {time.Hour, st("b", MemberAlive)}, {2 * time.Hour, st("b", MemberLeft)}},
			wantSince: 2 * time.Hour,
		},
		{
			name:      "kept by the gossip forgetting it (a restart)",
			steps:     []step{{0, st("b", MemberDead)}, {time.Minute, []MemberInfo{{ID: "a", State: MemberAlive}}}},
			wantSince: 0,
		},
		{name: "survives a short restart", steps: []step{{0, st("b", MemberDead)}}, reload: time.Minute, wantSince: 0},
		{
			name: "a long stop starts the timer over", steps: []step{{0, st("b", MemberDead)}},
			reload: downWatchGap + time.Minute, wantSince: downWatchGap + time.Minute,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			tr, err := loadDownTracker(dir, "a", t0)
			if err != nil {
				t.Fatal(err)
			}
			last := t0
			for _, s := range tt.steps {
				last = t0.Add(s.at)
				if err := tr.observe(s.members, nil, last); err != nil {
					t.Fatal(err)
				}
			}
			if tt.reload > 0 {
				if tr, err = loadDownTracker(dir, "a", last.Add(tt.reload)); err != nil {
					t.Fatal(err)
				}
			}
			d, ok := tr.snapshot()["b"]
			switch {
			case tt.wantSince < 0 && ok:
				t.Fatalf("b down since %v, want up", d.Since)
			case tt.wantSince >= 0 && !ok:
				t.Fatal("b not down")
			case tt.wantSince >= 0 && !d.Since.Equal(t0.Add(tt.wantSince)):
				t.Fatalf("b down since %v, want %v", d.Since, t0.Add(tt.wantSince))
			}
			if ok && d.Roles != storageMaster {
				t.Fatalf("b's roles %s, want %s", d.Roles, storageMaster)
			}
		})
	}
}

func TestDownTrackerForgetsRemoved(t *testing.T) {
	now := time.Now()
	tr, err := loadDownTracker(t.TempDir(), "a", now)
	if err != nil {
		t.Fatal(err)
	}
	_ = tr.observe([]MemberInfo{{ID: "b", State: MemberDead}}, nil, now)
	_ = tr.observe(nil, func(id string) bool { return id == "b" }, now)
	if _, ok := tr.snapshot()["b"]; ok {
		t.Fatal("a removed member stayed in the record")
	}
}

func TestDownTrackerCorruptRecord(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, downMembersFile), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	tr, err := loadDownTracker(dir, "a", time.Now())
	if err == nil || tr == nil || len(tr.snapshot()) != 0 {
		t.Fatalf("corrupt record: %v, %v; want an empty record and the error", tr, err)
	}
}

// deadCluster starts members a, b and c, masters and storage, with
// --member-dead-after deadAfter, and runs the removal loop on a with pol.
func deadCluster(t *testing.T, deadAfter time.Duration, polCfg policy.Config) (map[string]*apTestNode, *policy.Engine) {
	t.Helper()
	ca, err := pki.LoadOrCreateCA(t.TempDir(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	c := map[string]*apTestNode{}
	var seed string
	for _, id := range []string{"a", "b", "c"} {
		tn := prepareAPTestNode(t, ca, apSpec{id, storageMaster, storageMaster})
		tn.deadAfter = deadAfter
		tn.start(t, 2, seed)
		if seed == "" {
			seed = tn.addr
		}
		c[id] = tn
	}
	for _, tn := range c {
		waitUntil(t, 10*time.Second, tn.id+" to see every member", func() bool {
			n := 0
			for _, m := range tn.node.Membership().Members() {
				if m.State == MemberAlive {
					n++
				}
			}
			return n == 3
		})
		if err := tn.node.RecordNodeCert(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	pol := policy.NewWithConfig(c["a"].st.Audit(), c["a"].st.Approvals(), polCfg)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = c["a"].node.RunDeadMemberRemoval(ctx, pol); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	return c, pol
}

func revokedOn(t *testing.T, on *apTestNode, id string) bool {
	t.Helper()
	certs, err := on.st.Hubs().Certs(t.Context(), id)
	if err != nil || len(certs) == 0 {
		return false
	}
	for _, c := range certs {
		if !c.Revoked {
			return false
		}
	}
	return true
}

// TestDeadMemberRemoved: a member down for --member-dead-after is removed
// as `hearth cluster remove` does, audited as cluster.remove by the hub,
// not before; a member that comes back in time stays.
func TestDeadMemberRemoved(t *testing.T) {
	const deadAfter = 2 * time.Second
	c, _ := deadCluster(t, deadAfter, policy.Config{})
	// a may see c leave, and start its timer, while stop is still running:
	// the timer starts no earlier than the stop began.
	stopping := time.Now()
	c["c"].stop()
	waitUntil(t, 10*time.Second, "a to see c down", func() bool {
		s := c["c"].memberOn(c["a"]).State
		return s == MemberDead || s == MemberLeft
	})
	// The record of the members down follows the gossip asynchronously.
	var at *time.Time
	waitUntil(t, 5*time.Second, "a to plan c's removal", func() bool {
		for _, m := range c["a"].node.Status().Members {
			if m.ID == "c" {
				at = m.AutoRemoveAt
			}
		}
		return at != nil
	})
	if at.Before(stopping.Add(deadAfter)) || at.After(time.Now().Add(deadAfter)) {
		t.Fatalf("c's auto_remove_at %v, want %v after it was seen down", at, deadAfter)
	}
	waitUntil(t, 15*time.Second, "a to remove c", func() bool { return revokedOn(t, c["a"], "c") })
	if now := time.Now(); now.Before(*at) {
		t.Fatalf("c removed %v before its auto_remove_at, --member-dead-after %v after it was seen down", at.Sub(now), deadAfter)
	}
	waitUntil(t, 5*time.Second, "b to forget c", func() bool { return c["c"].memberOn(c["b"]).ID == "" })
	entries, err := c["a"].st.Audit().Query(t.Context(), store.AuditFilter{Actions: []string{string(policy.ClusterRemove)}}, 10)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range entries {
		if e.ActorKind == policy.ActorHub && e.ActorID == "a" && e.Target == "c" && e.Decision == policy.Allow &&
			strings.Contains(string(e.Detail), "down for 2s") {
			found = true
		}
	}
	if !found {
		t.Fatalf("no cluster.remove by hub a with its reason in the audit log: %+v", entries)
	}
	// a and b stay: neither was down.
	for _, id := range []string{"a", "b"} {
		if revokedOn(t, c["a"], id) {
			t.Fatalf("%s removed", id)
		}
	}
}

// TestDeadMemberBackInTime: a member that comes back before
// --member-dead-after stays, and its timer starts over.
func TestDeadMemberBackInTime(t *testing.T) {
	const deadAfter = 4 * time.Second
	c, _ := deadCluster(t, deadAfter, policy.Config{})
	c["c"].stop()
	waitUntil(t, 10*time.Second, "a to see c down", func() bool {
		s := c["c"].memberOn(c["a"]).State
		return s == MemberDead || s == MemberLeft
	})
	c["c"].start(t, 2, c["a"].addr)
	waitUntil(t, 10*time.Second, "a to see c back", func() bool { return c["c"].memberOn(c["a"]).State == MemberAlive })
	waitUntil(t, 5*time.Second, "a to drop c from the members down", func() bool {
		_, down := c["a"].node.down.snapshot()["c"]
		return !down
	})
	time.Sleep(deadAfter)
	if revokedOn(t, c["a"], "c") {
		t.Fatal("c removed though it came back")
	}
}

// TestDeadMemberPolicyDenied: a policy that denies dangerous actions denies
// the removal too; the member stays, and the denial is audited.
func TestDeadMemberPolicyDenied(t *testing.T) {
	const deadAfter = time.Second
	c, _ := deadCluster(t, deadAfter, policy.Config{Classes: map[policy.Class]policy.Mode{policy.Dangerous: policy.ModeDeny}})
	c["c"].stop()
	ctx := t.Context()
	waitUntil(t, 15*time.Second, "a to try to remove c", func() bool {
		entries, err := c["a"].st.Audit().Query(ctx, store.AuditFilter{Actions: []string{string(policy.ClusterRemove)}}, 10)
		return err == nil && len(entries) > 0 && entries[0].Decision == policy.Deny && entries[0].ActorKind == policy.ActorHub
	})
	time.Sleep(500 * time.Millisecond)
	if revokedOn(t, c["a"], "c") {
		t.Fatal("c removed though the policy denies it")
	}
	if c["c"].memberOn(c["a"]).ID == "" {
		t.Fatal("a forgot c though the policy denied its removal")
	}
}

// syncBuffer is a log sink safe for concurrent writes.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// TestRemovedMemberComesBack: a member removed while it was down is refused
// when it comes back, and says once in its log how to rejoin.
func TestRemovedMemberComesBack(t *testing.T) {
	c, _ := deadCluster(t, time.Second, policy.Config{})
	c["c"].stop()
	waitUntil(t, 15*time.Second, "a to remove c", func() bool { return revokedOn(t, c["a"], "c") })
	var logs syncBuffer
	c["c"].log = slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	c["c"].start(t, 2, c["a"].addr)
	defer func() {
		if t.Failed() {
			t.Log(logs.String())
		}
	}()
	waitUntil(t, 15*time.Second, "c to log that it was refused", func() bool {
		return strings.Contains(logs.String(), "wipe its data dir")
	})
	time.Sleep(time.Second)
	for _, on := range []string{"a", "b"} {
		if m := c["c"].memberOn(c[on]); m.ID != "" {
			t.Fatalf("%s lists the removed member c: %+v", on, m)
		}
	}
	if n := strings.Count(logs.String(), "wipe its data dir"); n != 1 {
		t.Fatalf("the rejoin line logged %d times, want once:\n%s", n, logs.String())
	}
}
