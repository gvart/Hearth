// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/fnv"
	"slices"
	"time"

	"github.com/gvart/hearth/internal/hlc"
	"github.com/gvart/hearth/internal/store"
)

// Anti-entropy (docs/design/ap-cluster.md §5.2): every round, this member
// compares the rows it shares with each live peer and copies the newer
// versions both ways. The comparison walks a tree of digests the store
// keeps up to date as it writes (store.BucketDigests), so a round between
// replicas that agree reads no rows:
//
//  1. the shared bucket ranges, cut into chunks of chunkBuckets buckets: one
//     hash per chunk;
//  2. for each chunk that differs, the digest of each of its buckets;
//  3. for each bucket that differs, the version of each of its rows;
//  4. the rows that differ, fetched from the newer side and merged.
//
// Only steps 3 and 4 read the database, and only for the buckets that
// differ.

// chunkBuckets is how many buckets one tree node above the leaves covers.
const chunkBuckets = 256

// refBatch bounds the rows fetched or pushed in one request.
const refBatch = 500

// bucketRange is the buckets [Start, End).
type bucketRange struct {
	Start int `json:"start"`
	End   int `json:"end"`
}

// chunks cuts ranges into chunks of at most chunkBuckets buckets.
func chunks(ranges []bucketRange) []bucketRange {
	var out []bucketRange
	for _, rg := range ranges {
		for s := rg.Start; s < rg.End; s += chunkBuckets {
			out = append(out, bucketRange{s, min(s+chunkBuckets, rg.End)})
		}
	}
	return out
}

func bucketsOf(ranges []bucketRange) []int {
	var out []int
	for _, rg := range ranges {
		for b := rg.Start; b < rg.End; b++ {
			out = append(out, b)
		}
	}
	return out
}

// checkRanges refuses ranges outside sp.
func checkRanges(sp store.Space, ranges []bucketRange) error {
	if !sp.Valid() {
		return fmt.Errorf("unknown digest space %d", sp)
	}
	for _, rg := range ranges {
		if rg.Start < 0 || rg.End > sp.Buckets() || rg.Start >= rg.End {
			return fmt.Errorf("bucket range %d-%d out of space", rg.Start, rg.End)
		}
	}
	return nil
}

// chunkHashes hashes the bucket digests of each chunk.
func chunkHashes(st *store.Store, sp store.Space, cs []bucketRange) []uint64 {
	out := make([]uint64, len(cs))
	for i, c := range cs {
		h := fnv.New64a()
		var b [8]byte
		for _, d := range st.BucketDigests(sp, bucketsOf([]bucketRange{c})) {
			binary.BigEndian.PutUint64(b[:], d)
			_, _ = h.Write(b[:])
		}
		out[i] = h.Sum64()
	}
	return out
}

// sharedRanges are the shard buckets both this member and peer hold.
func (v view) sharedRanges(peer string) []bucketRange {
	var out []bucketRange
	for _, seg := range v.ring.Segments() {
		owners := v.ring.Owners(seg.Start, v.n)
		if slices.Contains(owners, v.self) && slices.Contains(owners, peer) {
			if k := len(out); k > 0 && out[k-1].End == seg.Start {
				out[k-1].End = seg.End
			} else {
				out = append(out, bucketRange(seg))
			}
		}
	}
	return out
}

// antiEntropy runs one round with every live peer.
func (r *Replicator) antiEntropy(ctx context.Context) {
	st := r.store()
	if st == nil {
		return
	}
	v := r.view()
	key := ringKeyOf(v.ring)
	peers := 0
	for _, p := range v.everyone {
		if p == v.self || !v.live[p] {
			r.noteSynced(p, key, false)
			continue
		}
		peers++
		proved, err := r.syncWith(ctx, p)
		if err != nil {
			r.log.DebugContext(ctx, "anti-entropy", "peer", p, "err", err)
		}
		// A member that says it is a master holds the global rows only if
		// it proved it: then they were compared with it (safe stop).
		r.noteSynced(p, key, err == nil && (proved || !v.masters[p]))
	}
	if peers == 0 && len(v.everyone) == 1 {
		// Alone in the cluster: in contact with all of it.
		r.touchContact()
	}
	if v.syncing[v.self] {
		r.CatchUp(ctx)
	}
	if err := r.handOff(ctx, v); err != nil {
		r.log.DebugContext(ctx, "hand-off", "err", err)
	}
	r.aeRounds.Add(1)
}

// handOff copies the rows this member holds in buckets it does not own to
// their owners: rows written while the ring was smaller (a hub that started
// before it found the others), by a stand-in, or before a member joined
// and took the bucket. Anti-entropy compares only the buckets both sides
// own, so without it those rows would stay here alone. A bucket handed off
// is not read again until its digest changes.
func (r *Replicator) handOff(ctx context.Context, v view) error {
	st := r.store()
	if st == nil {
		return nil
	}
	var buckets []int
	for _, seg := range v.ring.Segments() {
		if slices.Contains(v.ring.Owners(seg.Start, v.n), v.self) {
			continue
		}
		for b := seg.Start; b < seg.End; b++ {
			buckets = append(buckets, b)
		}
	}
	digests := st.BucketDigests(store.SpaceShard, buckets)
	r.handedMu.Lock()
	var todo []int
	want := map[int]uint64{}
	for i, b := range buckets {
		if d := digests[i]; d != 0 && r.handed[b] != d {
			todo = append(todo, b)
			want[b] = d
		}
	}
	r.handedMu.Unlock()
	if len(todo) == 0 {
		return nil
	}
	in := func(b int) bool { _, ok := slices.BinarySearch(todo, b); return ok }
	ds, err := st.BucketRows(ctx, store.SpaceShard, in)
	if err != nil {
		return err
	}
	refs := make([]store.RowRef, len(ds))
	for i, d := range ds {
		refs[i] = d.RowRef
	}
	cutoff := hlc.New(r.cfg.Now().Add(-store.TombstoneTTL))
	failed := map[int]bool{}
	for chunk := range slices.Chunk(refs, refBatch) {
		ms, err := st.ReadRows(ctx, chunk)
		if err != nil {
			return err
		}
		byOwner := map[string][]store.Mutation{}
		bucketOf := map[string][]int{}
		for _, m := range liveOrRecent(ms, cutoff) {
			p, err := m.Placement()
			if err != nil || p.Global {
				continue
			}
			b := store.BucketOf(store.Token(p.Key))
			for _, o := range v.ring.Owners(b, v.n) {
				if !v.live[o] {
					failed[b] = true
					continue
				}
				byOwner[o] = append(byOwner[o], m)
				bucketOf[o] = append(bucketOf[o], b)
			}
		}
		for o, ms := range byOwner {
			if err := r.mergeOn(ctx, o, ms); err != nil {
				for _, b := range bucketOf[o] {
					failed[b] = true
				}
				r.log.DebugContext(ctx, "hand-off", "member", o, "err", err)
			}
		}
	}
	r.handedMu.Lock()
	for _, b := range todo {
		if !failed[b] {
			r.handed[b] = want[b]
		}
	}
	r.handedMu.Unlock()
	r.log.DebugContext(ctx, "handed off rows to their owners", "rows", len(refs), "buckets", len(todo))
	return nil
}

// SyncWith runs one anti-entropy round with peer: the global rows, and the
// shard buckets both hold.
func (r *Replicator) SyncWith(ctx context.Context, peer string) error {
	_, err := r.syncWith(ctx, peer)
	return err
}

// syncWith is SyncWith, and reports whether peer proved it holds the hub CA
// key, so the global rows were compared with a master.
func (r *Replicator) syncWith(ctx context.Context, peer string) (bool, error) {
	v := r.view()
	proved, err := r.syncGlobal(ctx, peer)
	if err != nil {
		return false, err
	}
	if ranges := v.sharedRanges(peer); len(ranges) > 0 {
		return proved, r.syncSpace(ctx, peer, store.SpaceShard, ranges, false)
	}
	return proved, nil
}

// SyncGlobal runs one anti-entropy round of the global rows with peer.
func (r *Replicator) SyncGlobal(ctx context.Context, peer string) error {
	_, err := r.syncGlobal(ctx, peer)
	return err
}

// syncGlobal is SyncGlobal, and reports whether peer proved it holds the
// hub CA key: whether the rows were compared with a master's. Between two
// masters it compares the master tables' rows too.
func (r *Replicator) syncGlobal(ctx context.Context, peer string) (bool, error) {
	proved, err := r.syncSpaceProved(ctx, r.store(), peer, store.SpaceGlobal, []bucketRange{{0, store.GlobalBuckets}}, false)
	if err == nil && proved {
		err = r.syncMasterRows(ctx, r.store(), peer, false)
	}
	if err == nil && proved {
		r.masterSynced.Store(true)
	}
	return proved, err
}

// syncMasterRows compares the master tables' rows of st with peer's, if
// both are masters that proved the hub CA key: they are compared with no
// other member (replauth.go).
func (r *Replicator) syncMasterRows(ctx context.Context, st *store.Store, peer string, pullOnly bool) error {
	if !r.holdsKey() || !r.saysMaster(peer) || !r.provedLast(peer) {
		return nil
	}
	return r.syncSpaceOf(ctx, st, peer, store.SpaceMaster, []bucketRange{{0, store.GlobalBuckets}}, pullOnly)
}

// SyncedWithAMaster reports whether this member compared the global rows
// with a master that proved the hub CA key since it started.
func (r *Replicator) SyncedWithAMaster() bool { return r.masterSynced.Load() }

// errNoMasterSynced fails a sync of the global rows that reached no master
// proving the hub CA key while one is live: global rows come from masters
// only.
var errNoMasterSynced = errors.New("no master that proves the hub CA key took part")

// syncGlobalWithAMaster compares the global rows with one live master that
// proves it holds the hub CA key, if any other master is live (a master
// without storage is no member of the ring). It fails if none does while
// one did not answer; one that answers without a proof is no master.
func (r *Replicator) syncGlobalWithAMaster(ctx context.Context, v view) error {
	unanswered := false
	for _, m := range v.otherLiveMasters() {
		known := r.provedLast(m)
		proved, err := r.syncGlobal(ctx, m)
		if err == nil && proved {
			return nil
		}
		// One that never proved the key does not hold it back.
		unanswered = unanswered || (err != nil && known)
	}
	if unanswered {
		return fmt.Errorf("global rows: %w", errNoMasterSynced)
	}
	return nil
}

// ownedRanges are the shard buckets this member owns.
func (v view) ownedRanges() []bucketRange {
	var out []bucketRange
	for _, seg := range v.ring.Segments() {
		if !slices.Contains(v.ring.Owners(seg.Start, v.n), v.self) {
			continue
		}
		if k := len(out); k > 0 && out[k-1].End == seg.Start {
			out[k-1].End = seg.End
		} else {
			out = append(out, bucketRange(seg))
		}
	}
	return out
}

// CatchUp copies, to a member promoted to storage, the rows of every
// bucket it owns from every live storage member, whether that one owns the
// bucket or held it before the promotion moved it. Once a round reached
// every one of them, the member has caught up: it serves reads again
// (OnSynced). It reports whether the member has caught up; a round already
// running elsewhere makes it return false at once.
func (r *Replicator) CatchUp(ctx context.Context) bool {
	if !r.catchUpMu.TryLock() {
		return false
	}
	defer r.catchUpMu.Unlock()
	if !r.Syncing() {
		return true
	}
	v := r.view()
	ranges := v.ownedRanges()
	ok := true
	masterSynced := false
	for _, p := range v.ring.Members() {
		if p == v.self {
			continue
		}
		if !v.live[p] {
			// A member that is down may hold the only copy of some rows: wait
			// for it.
			ok = false
			continue
		}
		proved, err := r.syncGlobal(ctx, p)
		if err != nil {
			r.log.DebugContext(ctx, "catch up after the promotion", "peer", p, "err", err)
			ok = false
			continue
		}
		masterSynced = masterSynced || proved
		if len(ranges) == 0 {
			continue
		}
		if err := r.syncSpace(ctx, p, store.SpaceShard, ranges, true); err != nil {
			r.log.DebugContext(ctx, "catch up after the promotion", "peer", p, "err", err)
			ok = false
		}
	}
	if ok && !masterSynced {
		if err := r.syncGlobalWithAMaster(ctx, v); err != nil {
			r.log.DebugContext(ctx, "catch up after the promotion", "err", err)
			ok = false
		}
	}
	if !ok || ctx.Err() != nil || !r.Syncing() {
		return false
	}
	r.SetLocal(true, false)
	r.log.InfoContext(ctx, "caught up after the promotion to storage: serving reads", "buckets", len(bucketsOf(ranges)))
	if r.cfg.OnSynced != nil {
		r.cfg.OnSynced()
	}
	return true
}

// syncSpace compares the ranges of sp with peer and copies the rows that
// differ both ways; with pullOnly, only from peer to this member.
func (r *Replicator) syncSpace(ctx context.Context, peer string, sp store.Space, ranges []bucketRange, pullOnly bool) error {
	return r.syncSpaceOf(ctx, r.store(), peer, sp, ranges, pullOnly)
}

// syncSpaceOf is syncSpace for st: this member's store, or a copy of it (a
// backup's, see PullAll), which only pulls: the rows of peer that differ
// merge into the copy, and nothing goes back to peer.
func (r *Replicator) syncSpaceOf(ctx context.Context, st *store.Store, peer string, sp store.Space, ranges []bucketRange,
	pullOnly bool,
) error {
	_, err := r.syncSpaceProved(ctx, st, peer, sp, ranges, pullOnly)
	return err
}

// syncSpaceProved is syncSpaceOf, and reports, for the global rows, whether
// they were compared with a master that proved it holds the hub CA key: the
// only members global rows come from.
func (r *Replicator) syncSpaceProved(ctx context.Context, st *store.Store, peer string, sp store.Space, ranges []bucketRange,
	pullOnly bool,
) (proved bool, err error) {
	own := st == r.store()
	pullOnly = pullOnly || !own
	cs := chunks(ranges)
	resp, err := r.call(ctx, peer, apRequest{Op: opTree, Space: sp, Ranges: ranges})
	if err != nil {
		return false, err
	}
	// Global rows go from masters only (replauth.go): none is taken from a
	// peer that did not prove it holds the hub CA key, and a member that
	// holds none sends none. The master tables' rows go between masters
	// only.
	global := sp == store.SpaceGlobal || sp == store.SpaceMaster
	pullGlobal, pushGlobal := resp.fromMaster, r.holdsKey()
	if sp == store.SpaceMaster && (!pullGlobal || !pushGlobal) {
		return false, nil
	}
	proved = global && resp.fromMaster
	if global && !pullGlobal && (!pushGlobal || pullOnly) {
		return proved, nil
	}
	mine := chunkHashes(st, sp, cs)
	if len(resp.Hashes) != len(cs) {
		return false, errors.New("anti-entropy: the peer cut the ranges differently")
	}
	var diffChunks []bucketRange
	for i := range cs {
		if mine[i] != resp.Hashes[i] {
			diffChunks = append(diffChunks, cs[i])
		}
	}
	if len(diffChunks) == 0 {
		return proved, nil
	}
	resp, err = r.call(ctx, peer, apRequest{Op: opLeaves, Space: sp, Ranges: diffChunks})
	if err != nil {
		return false, err
	}
	buckets := bucketsOf(diffChunks)
	leaves := st.BucketDigests(sp, buckets)
	if len(resp.Hashes) != len(buckets) {
		return false, errors.New("anti-entropy: leaf count differs")
	}
	var diff []int
	for i, b := range buckets {
		if leaves[i] != resp.Hashes[i] {
			diff = append(diff, b)
		}
	}
	if len(diff) == 0 {
		return proved, nil
	}
	resp, err = r.call(ctx, peer, apRequest{Op: opRows, Space: sp, Buckets: diff})
	if err != nil {
		return false, err
	}
	in := func(b int) bool { _, ok := slices.BinarySearch(diff, b); return ok }
	ours, err := st.BucketRows(ctx, sp, in)
	if err != nil {
		return false, err
	}
	pull, push := diffRows(ours, resp.Digests)
	if pullOnly || (global && !pushGlobal) {
		push = nil
	}
	if global && !pullGlobal {
		pull = nil
	}
	cutoff := hlc.New(r.cfg.Now().Add(-store.TombstoneTTL))
	for refs := range slices.Chunk(pull, refBatch) {
		ms, err := r.fetch(ctx, peer, refs)
		if err != nil {
			return false, err
		}
		ms = liveOrRecent(ms, cutoff)
		if own {
			err = r.mergeOn(ctx, r.cfg.NodeID, ms)
		} else if len(ms) > 0 {
			ms = slices.Clone(ms)
			store.SortMutations(ms)
			err = st.Merge(ctx, ms)
		}
		if err != nil {
			return false, fmt.Errorf("anti-entropy: merge from %s: %w", peer, err)
		}
	}
	for refs := range slices.Chunk(push, refBatch) {
		ms, err := st.ReadRows(ctx, refs)
		if err != nil {
			return false, err
		}
		if err := r.mergeOn(ctx, peer, liveOrRecent(ms, cutoff)); err != nil {
			return false, fmt.Errorf("anti-entropy: merge into %s: %w", peer, err)
		}
	}
	if len(pull)+len(push) > 0 {
		r.log.DebugContext(ctx, "anti-entropy copied rows", "peer", peer, "space", sp, "pulled", len(pull), "pushed", len(push))
	}
	return proved, nil
}

// liveOrRecent drops the tombstones older than cutoff: the GC drops them
// on every member, so copying one would only bring it back for a while.
func liveOrRecent(ms []store.Mutation, cutoff hlc.Timestamp) []store.Mutation {
	return slices.DeleteFunc(ms, func(m store.Mutation) bool { return m.Deleted && m.HLC < cutoff })
}

// diffRows compares this member's row digests with a peer's: the rows to
// pull are newer, or only, on the peer; those to push newer, or only,
// here. A row at the same version with another hash (its set-once columns
// differ) goes both ways, as merging keeps the earliest of each.
func diffRows(ours, theirs []store.RowDigest) (pull, push []store.RowRef) {
	key := func(d store.RowDigest) string { return d.Table + "\x00" + fmt.Sprint([]any(d.Key)) }
	mine := make(map[string]store.RowDigest, len(ours))
	for _, d := range ours {
		mine[key(d)] = d
	}
	seen := map[string]bool{}
	for _, t := range theirs {
		k := key(t)
		seen[k] = true
		m, ok := mine[k]
		switch {
		case !ok || t.Newer(m):
			pull = append(pull, t.RowRef)
		case m.Newer(t):
			push = append(push, m.RowRef)
		case m.Hash != t.Hash:
			pull = append(pull, t.RowRef)
			push = append(push, m.RowRef)
		}
	}
	for _, m := range ours {
		if !seen[key(m)] {
			push = append(push, m.RowRef)
		}
	}
	return pull, push
}

// handleAntiEntropy answers the tree, leaves and rows requests.
func (r *Replicator) handleAntiEntropy(ctx context.Context, st *store.Store, req apRequest) apResponse {
	fail := func(err error) apResponse { return apResponse{Error: apWireError(err)} }
	switch req.Op {
	case opTree:
		if err := checkRanges(req.Space, req.Ranges); err != nil {
			return fail(err)
		}
		return apResponse{Hashes: chunkHashes(st, req.Space, chunks(req.Ranges))}
	case opLeaves:
		if err := checkRanges(req.Space, req.Ranges); err != nil {
			return fail(err)
		}
		return apResponse{Hashes: st.BucketDigests(req.Space, bucketsOf(req.Ranges))}
	default:
		buckets := slices.Sorted(slices.Values(req.Buckets))
		for _, b := range buckets {
			if b < 0 || b >= req.Space.Buckets() {
				return fail(fmt.Errorf("bucket %d out of space", b))
			}
		}
		in := func(b int) bool { _, ok := slices.BinarySearch(buckets, b); return ok }
		ds, err := st.BucketRows(ctx, req.Space, in)
		if err != nil {
			return fail(err)
		}
		return apResponse{Digests: ds}
	}
}

// WaitSynced runs anti-entropy rounds until one with every live peer
// succeeds, or ctx ends, or limit passes: a member that just started
// catches up on the global rows before it acts on them.
func (r *Replicator) WaitSynced(ctx context.Context, limit time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	for {
		v := r.view()
		ok, masterSynced := true, false
		for _, p := range v.everyone {
			if p == v.self || !v.live[p] {
				continue
			}
			proved, err := r.syncWith(ctx, p)
			if err != nil {
				ok = false
			}
			masterSynced = masterSynced || proved
		}
		if ok && !masterSynced {
			// The global rows come from masters only: a sync with storage
			// members alone does not catch up on them.
			if err := r.syncGlobalWithAMaster(ctx, v); err != nil {
				r.log.DebugContext(ctx, "wait to be in sync", "err", err)
				ok = false
			}
		}
		if ok {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
}
