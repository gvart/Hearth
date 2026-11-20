// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import (
	"slices"
	"strconv"
	"strings"

	"github.com/gvart/hearth/internal/store"
)

// The consistent-hash ring of a sharded (AP) cluster
// (docs/design/ap-cluster.md §5.1).
//
// Each storage member takes ringVnodes positions on the ring. A position is
// a shard bucket (store.ShardBuckets of them), so every row of one bucket
// has the same replicas: walking the ring clockwise from a row's bucket, its
// preference list is every member in the order first met, and its replicas
// are the first N. A member's positions depend only on its id, so adding or
// removing a member moves only the buckets next to its positions.

// ringVnodes is how many positions each member takes.
const ringVnodes = 64

// Ring places buckets on members.
type Ring struct {
	// pos are the positions, sorted by bucket then member.
	pos     []ringPos
	members []string
}

type ringPos struct {
	bucket int
	member string
}

// NewRing returns the ring of members (ids; duplicates ignored).
func NewRing(members []string) *Ring {
	ms := slices.Clone(members)
	slices.Sort(ms)
	ms = slices.Compact(ms)
	r := &Ring{members: ms}
	for _, m := range ms {
		for i := range ringVnodes {
			r.pos = append(r.pos, ringPos{bucket: store.BucketOf(store.Token(m + "#" + strconv.Itoa(i))), member: m})
		}
	}
	slices.SortFunc(r.pos, func(a, b ringPos) int {
		if a.bucket != b.bucket {
			return a.bucket - b.bucket
		}
		return strings.Compare(a.member, b.member)
	})
	return r
}

// Members returns the ring's members, sorted.
func (r *Ring) Members() []string { return r.members }

// Size is the number of members.
func (r *Ring) Size() int { return len(r.members) }

// Preference returns every member in the order the ring meets them walking
// clockwise from bucket: the first N are the bucket's replicas.
func (r *Ring) Preference(bucket int) []string {
	if len(r.pos) == 0 {
		return nil
	}
	i, _ := slices.BinarySearchFunc(r.pos, bucket, func(p ringPos, b int) int { return p.bucket - b })
	out := make([]string, 0, len(r.members))
	for k := 0; k < len(r.pos) && len(out) < len(r.members); k++ {
		m := r.pos[(i+k)%len(r.pos)].member
		if !slices.Contains(out, m) {
			out = append(out, m)
		}
	}
	return out
}

// Owners returns the first n members of bucket's preference list.
func (r *Ring) Owners(bucket, n int) []string {
	p := r.Preference(bucket)
	return p[:min(n, len(p))]
}

// Segment is a run of buckets [Start, End) whose preference list is the
// same.
type Segment struct {
	Start, End int
}

// Segments splits the bucket space into the runs between ring positions:
// every bucket of a segment has the same replicas.
func (r *Ring) Segments() []Segment {
	if len(r.pos) == 0 {
		return []Segment{{0, store.ShardBuckets}}
	}
	var starts []int
	for _, p := range r.pos {
		if len(starts) == 0 || starts[len(starts)-1] != p.bucket {
			starts = append(starts, p.bucket)
		}
	}
	// A bucket's preference starts at the first position at or after it,
	// so the buckets (prev, pos] share one: segments end just past each
	// position.
	var out []Segment
	prev := 0
	for _, s := range starts {
		if s+1 > prev {
			out = append(out, Segment{prev, s + 1})
		}
		prev = s + 1
	}
	if prev < store.ShardBuckets {
		out = append(out, Segment{prev, store.ShardBuckets})
	}
	return out
}
