// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Schema changes in an AP cluster (docs/design/ap-cluster.md §8).
//
// No log orders a schema change. A member migrates its own database when it
// opens, to the newest schema its binary supports, and says so on the
// gossip (memberMeta.Schema). A table or column a migration added is
// written only once every live member supports it: the write schema W is
// the oldest schema this member and the live members support
// (store.WithWriteSchema). The newest W a member has used is its written
// schema, kept in the data dir and gossiped (memberMeta.Written): rows of
// that schema may exist from then on, so a member whose binary supports
// less is refused, on the gossip and at its join, whichever members are
// live when it comes.

// schemaWrittenFile keeps the member's written schema, in DataDir/raft.
const schemaWrittenFile = "schema-written"

// schemaGate computes this member's write schema and keeps its written
// schema.
type schemaGate struct {
	self    string
	path    string
	members func() []MemberInfo
	// seeking reports whether this member is still looking for the cluster
	// it joins: until it has found it, it knows too few members to raise
	// the written schema.
	seeking func() bool
	log     *slog.Logger

	// supported is the schema this member's database is at, set once the
	// store is bound; zero before.
	supported atomic.Int64
	// write is the write schema of the latest refresh; zero before one.
	write atomic.Int64
	// written is the written schema: this member's and the newest any
	// member gossips.
	written atomic.Int64

	// mu serialises refreshes and guards warned.
	mu sync.Mutex
	// warned are the members already logged as having written a schema
	// this member does not support.
	warned map[string]bool
}

func newSchemaGate(self, path string, members func() []MemberInfo, seeking func() bool, log *slog.Logger) *schemaGate {
	g := &schemaGate{self: self, path: path, members: members, seeking: seeking, log: log, warned: map[string]bool{}}
	if b, err := os.ReadFile(path); err == nil {
		if v, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64); err == nil && v > 0 {
			g.written.Store(v)
		}
	}
	return g
}

// bind sets the schema this member's database is at.
func (g *schemaGate) bind(supported int64) {
	g.supported.Store(supported)
	g.refresh()
}

// WriteSchema is the schema this member's writes use (see
// store.WithWriteSchema).
func (g *schemaGate) WriteSchema() int64 {
	if v := g.write.Load(); v > 0 {
		return v
	}
	return g.refresh()
}

// Written is the cluster's written schema as this member knows it: a member
// supporting less is refused.
func (g *schemaGate) Written() int64 { return g.written.Load() }

// refresh computes the write schema from the members of the moment, and
// keeps a newer written schema. It returns the write schema; without a
// bound store it caps nothing.
func (g *schemaGate) refresh() int64 {
	g.mu.Lock()
	defer g.mu.Unlock()
	sup := g.supported.Load()
	if sup <= 0 {
		return math.MaxInt64
	}
	w, h := sup, g.written.Load()
	for _, m := range g.members() {
		if m.ID == g.self || (m.State != MemberAlive && m.State != MemberSuspect) {
			continue
		}
		if m.Schema > 0 {
			w = min(w, m.Schema)
		}
		h = max(h, m.Written)
		if m.Written > sup && !g.warned[m.ID] {
			g.warned[m.ID] = true
			g.log.Error("this member's hearth is too old for the cluster: upgrade it", "member", m.ID,
				"cluster_written_schema", m.Written, "supported_schema", sup)
		}
	}
	if !g.seeking() {
		// Writes may use w from now on: rows of it may exist.
		h = max(h, w)
	}
	if h > g.written.Load() {
		if err := writeFileSync(g.path, []byte(strconv.FormatInt(h, 10)+"\n"), 0o600); err != nil {
			// Not kept: the next refresh tries again, and writes stay at the
			// schema every live member supports.
			g.log.Warn("keep the cluster's written schema", "schema", h, "err", err)
		} else {
			g.written.Store(h)
		}
	}
	g.write.Store(w)
	return w
}

// errSchemaTooOld refuses a member whose binary does not support the
// cluster's written schema.
var errSchemaTooOld = errors.New("its hearth is too old for the cluster")

// checkSchema refuses member id, which supports schema supported, when the
// cluster has written a newer one; a member that says none is refused too.
func (g *schemaGate) checkSchema(id string, supported int64) error {
	if h := g.Written(); supported < h {
		return fmt.Errorf("member %s supports schema %d but the cluster has written %d: upgrade its hearth: %w",
			id, supported, h, errSchemaTooOld)
	}
	return nil
}

// WrittenSchema is the cluster's written schema as this member knows it: a
// hub whose binary supports less may not join (see schemaGate).
func (n *APNode) WrittenSchema() int64 {
	if n.schema == nil {
		return 0
	}
	return n.schema.Written()
}

// WriteSchema is the schema this member's writes use: the oldest a live
// member supports.
func (n *APNode) WriteSchema() int64 { return n.schema.WriteSchema() }

// runSchemaGate refreshes the write schema, and checks the members' host
// flags, whenever a member joins, leaves or changes, and every RolesEvery
// (a member stops seeking the cluster without a change), until ctx ends.
func (n *APNode) runSchemaGate(ctx context.Context, changes <-chan struct{}) {
	t := time.NewTicker(n.cfg.RolesEvery)
	defer t.Stop()
	var drift string
	for {
		n.schema.refresh()
		drift = n.warnHostFlagDrift(drift)
		select {
		case <-ctx.Done():
			return
		case <-changes:
		case <-t.C:
		}
	}
}

// warnHostFlagDrift logs a warning when the live members' host flags
// (HostFlagsSource) differ, once per set of differing digests: last is the
// set logged before, and the set of now is returned.
func (n *APNode) warnHostFlagDrift(last string) string {
	groups := HostFlagGroups(n.membership.Members())
	if len(groups) < 2 {
		return ""
	}
	key := fmt.Sprint(groups)
	if key != last {
		n.log.Warn("members run with different host flags (--allow-dangerous-automation): a dangerous "+
			"automation may run on one master and not another; give every master the same flags", "members", groups)
	}
	return key
}

// HostFlagGroups groups the live members gossiping a configuration digest
// by it: more than one group means their host flags differ. Each group is
// sorted, and the groups by their first member.
func HostFlagGroups(members []MemberInfo) [][]string {
	by := map[string][]string{}
	for _, m := range members {
		if m.ConfigDigest == "" || (m.State != MemberAlive && m.State != MemberSuspect) {
			continue
		}
		by[m.ConfigDigest] = append(by[m.ConfigDigest], m.ID)
	}
	out := make([][]string, 0, len(by))
	for _, ids := range by {
		slices.Sort(ids)
		out = append(out, ids)
	}
	slices.SortFunc(out, func(a, b []string) int { return strings.Compare(a[0], b[0]) })
	return out
}
