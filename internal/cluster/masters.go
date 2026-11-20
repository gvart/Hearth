// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import (
	"context"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/gvart/hearth/internal/store"
)

// The masters of an AP cluster (docs/design/ap-cluster.md §6). Work one hub
// of a Raft cluster did as its leader has an owner among the live masters
// instead: a consistent-hash ring over them places each key (an automation,
// a runbook, an approval, a device without a stream, or the fixed key of a
// singleton loop) on one master. When a master dies its keys move to the
// others; during a split both sides may own a key (AP: accepted).

// masterRefresh is how often a MasterRing re-reads the members besides on
// gossip events: a member turning suspect raises none.
const masterRefresh = time.Second

// MasterRing is the consistent-hash ring over the live masters, as this
// member sees them. It is safe for concurrent use.
type MasterRing struct {
	self    string
	members func() []MemberInfo
	now     func() time.Time

	mu    sync.Mutex
	key   string
	ring  *Ring
	since time.Time
	subs  []chan struct{}
}

// NewMasterRing returns the ring of the live masters members returns,
// with self always on it.
func NewMasterRing(self string, members func() []MemberInfo, now func() time.Time) *MasterRing {
	if now == nil {
		now = time.Now
	}
	r := &MasterRing{self: self, members: members, now: now}
	r.refresh()
	return r
}

// refresh re-reads the live masters and tells the subscribers if they
// changed.
func (r *MasterRing) refresh() {
	ids := []string{r.self}
	for _, m := range r.members() {
		if m.Roles.Has(RoleMaster) && (m.State == MemberAlive || m.State == MemberSuspect) {
			ids = append(ids, m.ID)
		}
	}
	slices.Sort(ids)
	ids = slices.Compact(ids)
	key := strings.Join(ids, ",")
	r.mu.Lock()
	if key == r.key {
		r.mu.Unlock()
		return
	}
	r.key, r.ring, r.since = key, NewRing(ids), r.now()
	subs := slices.Clone(r.subs)
	r.mu.Unlock()
	for _, ch := range subs {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

// Run keeps the ring current until ctx ends: on every change in changes,
// and every second.
func (r *MasterRing) Run(ctx context.Context, changes <-chan struct{}) {
	t := time.NewTicker(masterRefresh)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-changes:
		case <-t.C:
		}
		r.refresh()
	}
}

// Subscribe returns a channel signalled whenever the live masters change,
// and a function that stops it.
func (r *MasterRing) Subscribe() (<-chan struct{}, func()) {
	ch := make(chan struct{}, 1)
	r.mu.Lock()
	r.subs = append(r.subs, ch)
	r.mu.Unlock()
	return ch, func() {
		r.mu.Lock()
		defer r.mu.Unlock()
		r.subs = slices.DeleteFunc(r.subs, func(c chan struct{}) bool { return c == ch })
	}
}

// Owner is the master that owns key.
func (r *MasterRing) Owner(key string) string {
	r.mu.Lock()
	ring := r.ring
	r.mu.Unlock()
	return ring.Preference(store.BucketOf(store.Token(key)))[0]
}

// Owns reports whether this master owns key.
func (r *MasterRing) Owns(key string) bool { return r.Owner(key) == r.self }

// Masters returns the live masters, this one included, sorted.
func (r *MasterRing) Masters() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.ring.Members())
}

// Live reports whether id is a live master.
func (r *MasterRing) Live(id string) bool { return slices.Contains(r.Masters(), id) }

// Since is when the live masters last changed: a master that took over a
// key acts on it only some time after (see Registry presence).
func (r *MasterRing) Since() time.Time {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.since
}

// Self is this master's id.
func (r *MasterRing) Self() string { return r.self }

// Singleton returns the owner of a loop that runs on one master: it leads
// while this master owns key. It has the shape of automation.LeaderNode,
// for automation.RunWhileLeading; ready is closed once the hub has caught
// up with the cluster.
func (r *MasterRing) Singleton(key string, ready <-chan struct{}) *Singleton {
	return &Singleton{ring: r, key: key, ready: ready}
}

// Singleton is a loop's ownership on the master ring (MasterRing.Singleton).
type Singleton struct {
	ring  *MasterRing
	key   string
	ready <-chan struct{}
}

// IsLeader reports whether this master owns the loop now.
func (s *Singleton) IsLeader() bool { return s.ring.Owns(s.key) }

// WaitReady waits until the hub has caught up with the cluster.
func (s *Singleton) WaitReady(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-s.ready:
		return nil
	}
}

// IsolationBound is how long a master may go without reaching any other
// member before it fails closed (docs/design/ap-cluster.md §5.4).
const IsolationBound = 60 * time.Second

// Isolation tells whether a master is cut off from its cluster: it knows of
// other members (from the gossip or its seeds) yet has heard from none for
// IsolationBound. A member alone in its cluster is never isolated.
type Isolation struct {
	// LastContact is when the member last heard from another one, or
	// started (Membership.LastContact); zero before it started.
	LastContact func() time.Time
	// Others reports whether the member knows of any other member.
	Others func() bool
	Now    func() time.Time
	Bound  time.Duration
}

// Isolated reports whether the member is isolated now.
func (i Isolation) Isolated() bool {
	last := i.LastContact()
	if last.IsZero() || !i.Others() {
		return false
	}
	return i.Now().Sub(last) >= i.Bound
}
