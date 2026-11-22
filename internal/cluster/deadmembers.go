// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/gvart/hearth/internal/policy"
)

// Removing a member that stays down (docs/cluster.md, "A hub that stays
// down").
//
// Every member records, in DataDir/cluster/down-members, since when each
// other member it knows is down (dead or left) and the roles it had. A
// member seen alive again is dropped from the record, so one that flaps
// starts over. The record survives a restart, when the gossip knows no dead
// member; time the hub was not watching (stopped longer than downWatchGap)
// is not counted: the timers start again.
//
// One master, the owner of the "dead-members" loop on the master ring,
// removes a member down for --member-dead-after as `hearth cluster remove`
// does, decided and audited as cluster.remove by the hub. It removes only
// while it sees a strict majority of the members it knows alive, the down
// ones counted, so the minority side of a split never removes, and never the
// last live master or storage member.

const (
	// DefaultMemberDeadAfter is how long a member stays down before it is
	// removed (--member-dead-after).
	DefaultMemberDeadAfter = 24 * time.Hour
	// downMembersFile records the members down, in DataDir/cluster.
	downMembersFile = "down-members"
	// downWatchGap is the longest the record may go unwatched (the hub
	// stopped) and still count: a member could have come back meanwhile.
	downWatchGap = 10 * time.Minute
	// defaultDeadEvery is how often the record is refreshed and the loop
	// looks for members to remove.
	defaultDeadEvery = time.Minute
)

// errNoLongerDead stops a removal whose member came back, or whose guard
// no longer holds, while it waited (an approval).
var errNoLongerDead = errors.New("the member is no longer due for removal")

// downMember is a member down, as the record keeps it.
type downMember struct {
	Since time.Time `json:"since"`
	Roles RoleSet   `json:"roles"`
}

// downRecord is the file: when the hub last watched, and the members down.
type downRecord struct {
	Watched time.Time             `json:"watched"`
	Members map[string]downMember `json:"members"`
}

// downTracker keeps the record of the members down.
type downTracker struct {
	path string
	self string
	// mu guards down and started.
	mu   sync.Mutex
	down map[string]downMember
	// started is when this hub began watching: nothing is removed until it
	// has watched for a while (the gossip finds the live members first).
	started time.Time
}

// loadDownTracker reads the record in dir. A record unwatched for longer
// than downWatchGap keeps its members, but their timers start at now.
func loadDownTracker(dir, self string, now time.Time) (*downTracker, error) {
	t := &downTracker{path: filepath.Join(dir, downMembersFile), self: self, down: map[string]downMember{}, started: now}
	b, err := os.ReadFile(t.path)
	if errors.Is(err, os.ErrNotExist) {
		return t, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read the members down: %w", err)
	}
	var rec downRecord
	if err := json.Unmarshal(b, &rec); err != nil {
		return t, fmt.Errorf("read the members down: %w (starting over)", err)
	}
	stale := now.Sub(rec.Watched) > downWatchGap
	for id, d := range rec.Members {
		if ValidNodeID(id) != nil || id == self {
			continue
		}
		if stale || d.Since.After(now) {
			d.Since = now
		}
		t.down[id] = d
	}
	return t, nil
}

// observe updates the record from the members the gossip shows: a member
// alive or suspect is up, one dead or left is down since now unless it was
// already. A recorded member the gossip no longer shows stays down, unless
// removed says it was removed.
func (t *downTracker) observe(members []MemberInfo, removed func(string) bool, now time.Time) error {
	t.mu.Lock()
	shown := map[string]bool{}
	for _, m := range members {
		if m.ID == t.self {
			continue
		}
		shown[m.ID] = true
		switch m.State {
		case MemberAlive, MemberSuspect:
			delete(t.down, m.ID)
		default:
			d, ok := t.down[m.ID]
			if !ok {
				d.Since = now
			}
			if m.Roles != 0 {
				d.Roles = m.Roles
			}
			t.down[m.ID] = d
		}
	}
	var gone []string
	for id := range t.down {
		if !shown[id] {
			gone = append(gone, id)
		}
	}
	t.mu.Unlock()
	// The store is read outside the lock.
	for _, id := range gone {
		if removed != nil && removed(id) {
			t.forget(id)
		}
	}
	return t.save(now)
}

// forget drops id from the record: it was removed.
func (t *downTracker) forget(id string) {
	t.mu.Lock()
	delete(t.down, id)
	t.mu.Unlock()
}

// snapshot returns a copy of the members down.
func (t *downTracker) snapshot() map[string]downMember {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make(map[string]downMember, len(t.down))
	for id, d := range t.down {
		out[id] = d
	}
	return out
}

func (t *downTracker) save(now time.Time) error {
	t.mu.Lock()
	b, err := json.Marshal(downRecord{Watched: now, Members: t.down})
	t.mu.Unlock()
	if err != nil {
		return err
	}
	tmp := t.path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return fmt.Errorf("record the members down: %w", err)
	}
	if err := os.Rename(tmp, t.path); err != nil {
		return fmt.Errorf("record the members down: %w", err)
	}
	return nil
}

// deadVerdict is what may happen to a member down: removed at At, unless
// Refused says why not.
type deadVerdict struct {
	ID    string
	Since time.Time
	At    time.Time
	// Refused is why the member is not removed; empty if it may be.
	Refused string
}

// planDead decides, for each member down, when it is due and whether this
// hub (self) may remove it. self sees members (itself included) and the
// record down. The members it knows are those it sees and those recorded
// down; it may remove only while those alive, itself included, are a strict
// majority of them, and never the last live master or storage member.
func planDead(self string, members []MemberInfo, down map[string]downMember, deadAfter time.Duration) []deadVerdict {
	live, known, majority := seesMajority(self, members, down)
	ids := make([]string, 0, len(down))
	for id := range down {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	var out []deadVerdict
	for _, id := range ids {
		d := down[id]
		if _, up := live[id]; up || id == self {
			continue
		}
		v := deadVerdict{ID: id, Since: d.Since, At: d.Since.Add(deadAfter)}
		switch {
		case !majority:
			v.Refused = notMajority(len(live), known)
		case d.Roles.Has(RoleMaster) && !hasLive(live, id, RoleMaster):
			v.Refused = "it is the last master"
		case d.Roles.Has(RoleStorage) && !hasLive(live, id, RoleStorage):
			v.Refused = "it is the last live storage member"
		}
		out = append(out, v)
	}
	return out
}

// seesMajority returns the members self sees alive (itself included), how
// many members it knows (those it sees and those recorded down), and whether
// those alive are a strict majority of them: the minority side of a split,
// or an even half, is not.
func seesMajority(self string, members []MemberInfo, down map[string]downMember) (live map[string]MemberInfo, known int, ok bool) {
	ids := map[string]bool{self: true}
	live = map[string]MemberInfo{}
	for _, m := range members {
		ids[m.ID] = true
		if m.ID == self || m.State == MemberAlive {
			live[m.ID] = m
		}
	}
	for id := range down {
		ids[id] = true
	}
	return live, len(ids), 2*len(live) > len(ids)
}

// notMajority says why a hub that sees live of the known members alive does
// not act.
func notMajority(live, known int) string {
	return fmt.Sprintf("this hub sees %d of the %d members it knows alive, not a majority", live, known)
}

// hasLive reports whether a live member other than but holds role (a
// storage member being drained does not count).
func hasLive(live map[string]MemberInfo, but string, role Role) bool {
	for id, m := range live {
		if id != but && m.Roles.Has(role) && (role != RoleStorage || !m.Draining) {
			return true
		}
	}
	return false
}

// MemberDeadAfter is how long a member stays down before it is removed;
// zero if this hub never removes one.
func (n *APNode) MemberDeadAfter() time.Duration {
	if n.down == nil {
		return 0
	}
	return n.cfg.MemberDeadAfter
}

func (n *APNode) deadEvery() time.Duration {
	if n.cfg.deadEvery > 0 {
		return n.cfg.deadEvery
	}
	return defaultDeadEvery
}

// localMembers is the gossip members this hub sees; none before Bind.
func (n *APNode) localMembers() []MemberInfo {
	if n.membership == nil {
		return nil
	}
	return n.membership.Members()
}

// runDownTracker keeps the record of the members down until ctx ends: at
// each change of the membership and every deadEvery.
func (n *APNode) runDownTracker(ctx context.Context, changes <-chan struct{}) {
	t := time.NewTicker(n.deadEvery())
	defer t.Stop()
	for {
		if err := n.down.observe(n.localMembers(), n.removed, time.Now()); err != nil {
			n.log.WarnContext(ctx, "record the members down", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-changes:
		case <-t.C:
		}
	}
}

// autoRemoveAt returns, by member, when the members down are removed
// automatically; a member this hub would not remove is left out.
func (n *APNode) autoRemoveAt(members []MemberInfo) map[string]time.Time {
	if n.MemberDeadAfter() <= 0 {
		return nil
	}
	out := map[string]time.Time{}
	for _, v := range planDead(n.cfg.NodeID, members, n.down.snapshot(), n.cfg.MemberDeadAfter) {
		if v.Refused == "" {
			out[v.ID] = v.At
		}
	}
	return out
}

// RunDeadMemberRemoval removes the members down for MemberDeadAfter until
// ctx ends, each through pol as cluster.remove by this hub. It runs on the
// one master owning the loop. A removal refused or failed is tried again
// after deadRetry; a guard that holds a member back is logged once.
func (n *APNode) RunDeadMemberRemoval(ctx context.Context, pol *policy.Engine) error {
	if n.MemberDeadAfter() <= 0 {
		return nil
	}
	every := n.deadEvery()
	t := time.NewTicker(every)
	defer t.Stop()
	r := deadRemover{
		n: n, pol: pol, retry: map[string]time.Time{}, logged: map[string]string{},
		grace: time.Now().Add(2 * every), retryAfter: 60 * every,
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			r.round(ctx, time.Now())
		}
	}
}

// deadRemover is the state of the removal loop.
type deadRemover struct {
	n   *APNode
	pol *policy.Engine
	// grace: nothing is removed before it, while the gossip finds the live
	// members after a start.
	grace time.Time
	// retry is when a member whose removal was refused or failed is tried
	// again; retryAfter how long that waits.
	retry      map[string]time.Time
	retryAfter time.Duration
	// logged is the guard last logged for each member.
	logged map[string]string
}

func (r *deadRemover) round(ctx context.Context, now time.Time) {
	n := r.n
	if now.Before(r.grace) || !n.IsMaster() {
		return
	}
	for _, v := range planDead(n.cfg.NodeID, n.localMembers(), n.down.snapshot(), n.cfg.MemberDeadAfter) {
		if now.Before(v.At) || now.Before(r.retry[v.ID]) {
			continue
		}
		if v.Refused != "" {
			if r.logged[v.ID] != v.Refused {
				r.logged[v.ID] = v.Refused
				n.log.WarnContext(ctx, "a member is down for longer than --member-dead-after but is not removed",
					"member", v.ID, "down_since", v.Since, "reason", v.Refused)
			}
			continue
		}
		delete(r.logged, v.ID)
		if err := n.removeDead(ctx, r.pol, v); err != nil {
			r.retry[v.ID] = now.Add(r.retryAfter)
			n.log.WarnContext(ctx, "remove a member down", "member", v.ID, "err", err)
			continue
		}
		delete(r.retry, v.ID)
	}
}

// removeDead removes the member of v through pol, as cluster.remove by this
// hub, once it checked again that it is still due: a removal held for
// approval may be approved after the member came back.
func (n *APNode) removeDead(ctx context.Context, pol *policy.Engine, v deadVerdict) error {
	reason := "down for " + shortDuration(n.cfg.MemberDeadAfter)
	req := policy.Request{
		ActorKind: policy.ActorHub, ActorID: n.cfg.NodeID, Action: policy.ClusterRemove, Target: v.ID,
		Detail: map[string]any{"reason": reason, "down_since": v.Since.UTC().Format(time.RFC3339)},
	}
	return pol.Do(ctx, req, func(ctx context.Context) error {
		still := false
		for _, w := range planDead(n.cfg.NodeID, n.localMembers(), n.down.snapshot(), n.cfg.MemberDeadAfter) {
			if w.ID == v.ID && w.Refused == "" && !time.Now().Before(w.At) {
				still = true
			}
		}
		if !still {
			return errNoLongerDead
		}
		got, err := n.RemoveMember(ctx, v.ID)
		if err != nil {
			return err
		}
		n.down.forget(v.ID)
		n.log.InfoContext(ctx, "removed a member automatically", "member", v.ID, "reason", reason,
			"down_since", v.Since, "certs_revoked", got.Revoked)
		return nil
	})
}

// shortDuration writes d as 24h, 90m or 1m30s.
func shortDuration(d time.Duration) string {
	switch {
	case d >= time.Hour && d%time.Hour == 0:
		return fmt.Sprintf("%dh", d/time.Hour)
	case d >= time.Minute && d%time.Minute == 0:
		return fmt.Sprintf("%dm", d/time.Minute)
	}
	return d.String()
}
