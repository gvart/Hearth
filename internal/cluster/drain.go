// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"

	"github.com/gvart/hearth/internal/hlc"
	"github.com/gvart/hearth/internal/store"
)

// Draining a storage member before its demotion (docs/design/ap-cluster.md
// §6): every row it holds is copied to the members that will own it once it
// has left the ring, and checked there. The member keeps the role, and so
// its place on the ring, until every bucket it holds rows of has N copies on
// the others; a future owner that is down holds the drain up until it is
// back.

// ErrLastStorage refuses to demote or remove the last storage member: the
// cluster would hold no copy of its rows (N would fall below 1).
var ErrLastStorage = errors.New("the last storage member cannot be demoted or removed: no other member would hold the rows")

// DrainProgress is how far a drain is.
type DrainProgress struct {
	// Done of Total buckets holding rows here have every row on each of
	// their future owners.
	Done, Total int
	// Waiting names a future owner that is down, if one holds the drain up.
	Waiting string
}

// Complete reports whether every row has its copies.
func (p DrainProgress) Complete() bool { return p.Done == p.Total }

// Percent is the share of buckets done.
func (p DrainProgress) Percent() int {
	if p.Total == 0 {
		return 100
	}
	return p.Done * 100 / p.Total
}

// Drain runs one round of the drain of this member: it copies the rows of
// every bucket it holds to the owners the bucket will have on the ring
// without this member, and checks that each of them holds every row at
// least at this member's version. It fails with ErrLastStorage when no
// other storage member exists.
func (r *Replicator) Drain(ctx context.Context) (DrainProgress, error) {
	st := r.store()
	if st == nil {
		return DrainProgress{}, errors.New("replicator: no store bound")
	}
	v := r.view()
	others := slices.DeleteFunc(slices.Clone(v.ring.Members()), func(m string) bool { return m == v.self })
	if len(others) == 0 {
		return DrainProgress{}, ErrLastStorage
	}
	future := NewRing(others)
	n := r.cfg.Replicas
	if n == 0 {
		n = 2
	}
	n = max(1, min(n, future.Size()))

	all := make([]int, store.ShardBuckets)
	for i := range all {
		all[i] = i
	}
	digests := st.BucketDigests(store.SpaceShard, all)
	byOwner := map[string][]int{}
	var held []int
	for b, d := range digests {
		if d == 0 {
			continue
		}
		held = append(held, b)
		for _, o := range future.Owners(b, n) {
			byOwner[o] = append(byOwner[o], b)
		}
	}
	p := DrainProgress{Total: len(held)}
	failed := map[int]bool{}
	for _, o := range slices.Sorted(maps.Keys(byOwner)) {
		buckets := byOwner[o]
		if !v.live[o] {
			p.Waiting = o
			for _, b := range buckets {
				failed[b] = true
			}
			continue
		}
		short, err := r.handTo(ctx, st, o, buckets)
		if err != nil {
			r.log.DebugContext(ctx, "drain", "member", o, "err", err)
			for _, b := range buckets {
				failed[b] = true
			}
			continue
		}
		for _, b := range short {
			failed[b] = true
		}
	}
	p.Done = p.Total - len(failed)
	return p, ctx.Err()
}

// handTo copies the rows of buckets held here to member o, then reads o's
// versions of them back, and returns the buckets of which o still lacks a
// row or holds an older version.
func (r *Replicator) handTo(ctx context.Context, st *store.Store, o string, buckets []int) ([]int, error) {
	in := func(b int) bool { _, ok := slices.BinarySearch(buckets, b); return ok }
	ours, err := st.BucketRows(ctx, store.SpaceShard, in)
	if err != nil {
		return nil, err
	}
	cutoff := hlc.New(r.cfg.Now().Add(-store.TombstoneTTL))
	refs := make([]store.RowRef, len(ours))
	for i, d := range ours {
		refs[i] = d.RowRef
	}
	for chunk := range slices.Chunk(refs, refBatch) {
		ms, err := st.ReadRows(ctx, chunk)
		if err != nil {
			return nil, err
		}
		if err := r.mergeOn(ctx, o, liveOrRecent(ms, cutoff)); err != nil {
			return nil, err
		}
	}
	resp, err := r.call(ctx, o, apRequest{Op: opRows, Space: store.SpaceShard, Buckets: buckets})
	if err != nil {
		return nil, err
	}
	_, missing := diffRows(ours, resp.Digests)
	if len(missing) == 0 {
		return nil, nil
	}
	// Tombstones past the window were not sent: the GC drops them
	// everywhere, so they need no copy.
	ms, err := st.ReadRows(ctx, missing)
	if err != nil {
		return nil, err
	}
	var short []int
	for _, m := range liveOrRecent(ms, cutoff) {
		p, err := m.Placement()
		if err != nil {
			return nil, fmt.Errorf("drain: %w", err)
		}
		short = append(short, store.BucketOf(store.Token(p.Key)))
	}
	return short, nil
}
