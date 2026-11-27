// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/gvart/hearth/internal/store"
)

// Safe to stop (docs/cluster.md, "Is it safe to stop this hub?"): whether
// this hub can stop now, with no handoff step, without the cluster losing a
// row or its last master. It is safe when every row this hub holds has a
// copy on another live member that is caught up with it, and another
// master is live.
//
// The check works on buckets, not rows: a bucket this hub holds rows of is
// covered when one of its other replicas is caught up. A member counts as
// caught up when it is live, not syncing after a promotion, no hint waits
// here for it, and its last anti-entropy round with this hub, on the
// current ring, compared every bucket both hold and copied what differed.
// A bucket this hub holds but does not own is covered once its rows were
// handed off to the owners.

// Reasons a hub is not safe to stop.
const (
	// SafeStopNoMaster: no other master is live.
	SafeStopNoMaster = "no_other_master"
	// SafeStopOnlyCopy: no other storage member holds some of the rows.
	SafeStopOnlyCopy = "only_copy"
	// SafeStopBehind: the other replicas of some rows are not caught up.
	SafeStopBehind = "replica_behind"
	// SafeStopHandOff: rows held for other owners are not handed off yet.
	SafeStopHandOff = "hand_off"
	// SafeStopInFlight: writes are still being sent to other replicas.
	SafeStopInFlight = "writes_in_flight"
)

// SafeStop says whether this hub can stop now, and if not, why.
type SafeStop struct {
	Safe    bool             `json:"safe"`
	Reasons []SafeStopReason `json:"reasons,omitempty"`
}

// SafeStopReason is one thing missing before this hub can stop.
type SafeStopReason struct {
	Kind string `json:"kind"`
	// Member is the member the reason is about, if one.
	Member string `json:"member,omitempty"`
	// Buckets counts the shard buckets of rows concerned.
	Buckets int `json:"buckets,omitempty"`
	// Message says it in a sentence, for the CLI and the web UI.
	Message string `json:"message"`
}

// safeStopPeer is another member, as the check needs it.
type safeStopPeer struct {
	ID     string
	Master bool
	// Live: reachable now (gossip alive or suspect, no request just failed).
	Live bool
	// Syncing: promoted to storage, still copying its rows.
	Syncing bool
	// Synced: its last anti-entropy round with this hub, on the current
	// ring, succeeded.
	Synced bool
	// Hints waiting here for it.
	Hints int
}

func (p safeStopPeer) caughtUp() bool { return p.Live && !p.Syncing && p.Synced && p.Hints == 0 }

// why says why p is not caught up.
func (p safeStopPeer) why() string {
	switch {
	case !p.Live:
		return "is down"
	case p.Syncing:
		return "is still copying its rows after its promotion to storage"
	case p.Hints > 0:
		return fmt.Sprintf("has %d write batch%s waiting for it here", p.Hints, plural(p.Hints, "es"))
	default:
		return "has not finished an anti-entropy round with this hub yet"
	}
}

// safeStopInput is what the check looks at.
type safeStopInput struct {
	Self string
	Ring *Ring
	N    int
	// Held are the shard buckets this hub holds rows of.
	Held []int
	// HandedOff reports whether the rows of a bucket this hub does not own
	// were handed off to its owners at their current version.
	HandedOff func(bucket int) bool
	// HoldsGlobal: this hub holds global rows.
	HoldsGlobal bool
	// KeyHolder: this hub holds the hub CA key, so other members take its
	// global rows; with other masters, only they hand them on.
	KeyHolder bool
	// InFlight counts the background writes not yet sent.
	InFlight int
	// Peers are the other members that have not left.
	Peers []safeStopPeer
}

// safeToStop decides whether this hub is safe to stop.
func safeToStop(in safeStopInput) SafeStop {
	peers := map[string]safeStopPeer{}
	var reasons []SafeStopReason
	master := false
	for _, p := range in.Peers {
		peers[p.ID] = p
		master = master || (p.Master && p.Live)
	}
	if !master {
		reasons = append(reasons, SafeStopReason{
			Kind:    SafeStopNoMaster,
			Message: "no other master is live: nothing would serve the UI, the API or the agents; promote another hub to master",
		})
	}

	onlyCopy, handOff := 0, 0
	behind := map[string]int{}
	for _, b := range in.Held {
		owners := in.Ring.Owners(b, in.N)
		if !slices.Contains(owners, in.Self) {
			if in.HandedOff == nil || !in.HandedOff(b) {
				handOff++
			}
			continue
		}
		var others []string
		for _, o := range owners {
			if o != in.Self {
				others = append(others, o)
			}
		}
		if len(others) == 0 {
			onlyCopy++
			continue
		}
		if slices.ContainsFunc(others, func(o string) bool { return peers[o].caughtUp() }) {
			continue
		}
		for _, o := range others {
			behind[o]++
		}
	}
	// The global rows (users, settings, policy) are on every member: one
	// other caught-up member holds them. A storage member hands none on
	// (replauth.go): a master's are held once another master is caught up,
	// if there is one.
	globalBehind := false
	holders := in.Peers
	if in.KeyHolder && slices.ContainsFunc(in.Peers, func(p safeStopPeer) bool { return p.Master }) {
		holders = slices.DeleteFunc(slices.Clone(in.Peers), func(p safeStopPeer) bool { return !p.Master })
	}
	if in.HoldsGlobal && !slices.ContainsFunc(holders, safeStopPeer.caughtUp) {
		if len(holders) == 0 {
			onlyCopy = max(onlyCopy, 1)
		} else if len(behind) == 0 {
			globalBehind = true
			for _, p := range holders {
				behind[p.ID] = 0
			}
		}
	}
	if onlyCopy > 0 {
		msg := "this hub holds the only copy of its rows: add a hub with the storage role, or promote one to storage"
		if len(in.Held) > 0 {
			msg = fmt.Sprintf("this hub holds the only copy of the rows in %d bucket%s: add a hub with the storage role, "+
				"or promote one to storage", onlyCopy, plural(onlyCopy, "s"))
		}
		reasons = append(reasons, SafeStopReason{Kind: SafeStopOnlyCopy, Buckets: onlyCopy, Message: msg})
	}
	ids := slices.Sorted(maps.Keys(behind))
	for _, id := range ids {
		rows := fmt.Sprintf("the rows in %d bucket%s", behind[id], plural(behind[id], "s"))
		if globalBehind {
			rows = "the cluster-wide rows (users, settings, policy)"
		}
		reasons = append(reasons, SafeStopReason{
			Kind: SafeStopBehind, Member: id, Buckets: behind[id],
			Message: fmt.Sprintf("replica %s %s; until it catches up, this hub holds the only up-to-date copy of %s",
				id, peers[id].why(), rows),
		})
	}
	if handOff > 0 {
		reasons = append(reasons, SafeStopReason{
			Kind: SafeStopHandOff, Buckets: handOff,
			Message: fmt.Sprintf("the rows in %d bucket%s this hub holds for other members are not handed off to them yet",
				handOff, plural(handOff, "s")),
		})
	}
	if in.InFlight > 0 {
		reasons = append(reasons, SafeStopReason{
			Kind:    SafeStopInFlight,
			Message: fmt.Sprintf("%d write%s still being sent to other replicas", in.InFlight, plural(in.InFlight, "s")),
		})
	}
	return SafeStop{Safe: len(reasons) == 0, Reasons: reasons}
}

func plural(n int, suffix string) string {
	if n == 1 {
		return ""
	}
	return suffix
}

// ringKeyOf names the members of a ring.
func ringKeyOf(r *Ring) string { return strings.Join(r.Members(), ",") }

// noteSynced records the outcome of an anti-entropy round with peer on the
// ring named ringKey; a failed one, or a peer found down, forgets it.
func (r *Replicator) noteSynced(peer, ringKey string, ok bool) {
	r.syncedMu.Lock()
	defer r.syncedMu.Unlock()
	if !ok {
		delete(r.synced, peer)
		return
	}
	if r.synced == nil {
		r.synced = map[string]string{}
	}
	r.synced[peer] = ringKey
}

// forgetSynced forgets every round: the ring changed, so a member that left
// and came back (its old ring again) may have missed writes no hint kept.
func (r *Replicator) forgetSynced() {
	r.syncedMu.Lock()
	clear(r.synced)
	r.syncedMu.Unlock()
}

// syncedOn reports whether the last anti-entropy round with peer succeeded
// on the ring named ringKey.
func (r *Replicator) syncedOn(peer, ringKey string) bool {
	r.syncedMu.Lock()
	defer r.syncedMu.Unlock()
	k, ok := r.synced[peer]
	return ok && k == ringKey
}

// safeStopInput gathers what the check looks at; masters are the members
// holding the master role.
func (r *Replicator) safeStopInput(ctx context.Context, members []MemberInfo) (safeStopInput, error) {
	v := r.view()
	in := safeStopInput{Self: v.self, Ring: v.ring, N: v.n, InFlight: len(r.jobs)}
	if st := r.store(); st != nil {
		all := make([]int, store.ShardBuckets)
		for i := range all {
			all[i] = i
		}
		digests := st.BucketDigests(store.SpaceShard, all)
		for b, d := range digests {
			if d != 0 {
				in.Held = append(in.Held, b)
			}
		}
		r.handedMu.Lock()
		handed := make(map[int]uint64, len(r.handed))
		for b, d := range r.handed {
			handed[b] = d
		}
		r.handedMu.Unlock()
		in.HandedOff = func(b int) bool { return digests[b] != 0 && handed[b] == digests[b] }
		for _, d := range st.BucketDigests(store.SpaceGlobal, all[:store.GlobalBuckets]) {
			if d != 0 {
				in.HoldsGlobal = true
				break
			}
		}
	}
	hints := map[string]int{}
	if h := r.cfg.Hints; h != nil {
		ids, err := h.Members(ctx)
		if err != nil {
			return in, fmt.Errorf("read hints: %w", err)
		}
		for _, id := range ids {
			if hints[id], err = h.Count(ctx, id); err != nil {
				return in, fmt.Errorf("read hints of %s: %w", id, err)
			}
		}
	}
	in.KeyHolder = r.holdsKey()
	key := ringKeyOf(v.ring)
	for _, m := range members {
		if m.ID == v.self || !m.Roles.Gossips() || m.State == MemberLeft {
			continue
		}
		in.Peers = append(in.Peers, safeStopPeer{
			ID: m.ID, Master: m.Roles.Has(RoleMaster), Live: v.live[m.ID],
			Syncing: v.syncing[m.ID], Synced: r.syncedOn(m.ID, key), Hints: hints[m.ID],
		})
	}
	return in, nil
}

// SafeToStop reports whether this hub can stop now without the cluster
// losing a row or its last master, and if not, what is missing.
func (n *APNode) SafeToStop(ctx context.Context) (SafeStop, error) {
	var members []MemberInfo
	if n.membership != nil {
		members = n.membership.Members()
	}
	in, err := n.rep.safeStopInput(ctx, members)
	if err != nil {
		return SafeStop{}, err
	}
	return safeToStop(in), nil
}

// StatusWithSafeStop is Status with SafeToStop filled in; a failure to read
// the hints leaves it out and is logged.
func (n *APNode) StatusWithSafeStop(ctx context.Context) Status {
	st := n.Status()
	ss, err := n.SafeToStop(ctx)
	if err != nil {
		n.log.WarnContext(ctx, "check whether this hub is safe to stop", "err", err)
		return st
	}
	st.SafeToStop = &ss
	return st
}
