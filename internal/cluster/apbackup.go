// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"slices"
	"strings"

	"github.com/gvart/hearth/internal/store"
)

// Backups of an AP cluster. A member holds only the shards the ring gives
// it, so a copy of its database file is not the cluster's store. Snapshot
// copies it, then pulls into the copy every row it lacks from the live
// members: the global rows, the master tables' rows from the masters, and
// every shard bucket from every live storage member (stand-ins included).
// It refuses, rather than writing a partial
// copy, when some bucket has no replica that answered.

// ErrIncompleteSnapshot refuses a backup that would miss rows: no live
// replica of some shard buckets answered.
var ErrIncompleteSnapshot = errors.New("not every shard of the cluster could be copied")

// Snapshot writes a copy of the whole cluster store to path, a file that
// must not exist yet.
func (n *APNode) Snapshot(ctx context.Context, path string) error {
	if n.st == nil {
		return errors.New("snapshot: ap node not bound to a store")
	}
	if !n.rep.holdsKey() {
		// It would miss the rows only masters hold (sessions, tokens, panels).
		return errors.New("snapshot: this hub is no master: take the backup on a master")
	}
	if err := n.st.VacuumInto(ctx, path); err != nil {
		return err
	}
	dst, err := store.Open(ctx, path, store.WithDigest())
	if err != nil {
		return fmt.Errorf("snapshot: open the copy: %w", err)
	}
	err = n.rep.PullAll(ctx, dst)
	if cerr := dst.Close(); err == nil && cerr != nil {
		err = fmt.Errorf("snapshot: close the copy: %w", cerr)
	}
	return err
}

// PullAll merges into dst, a copy of this member's store, the rows of every
// live member: the global rows of each, and all shard buckets of each live
// storage member. It fails with ErrIncompleteSnapshot when some ring
// segment has no replica, this member's own copy included, that answered.
func (r *Replicator) PullAll(ctx context.Context, dst *store.Store) error {
	v := r.view()
	answered := map[string]bool{}
	if local := r.local.Load(); local.storage && !local.syncing {
		answered[v.self] = true
	}
	storage := v.ring.Members()
	var problems []string
	for _, p := range v.everyone {
		if p == v.self {
			continue
		}
		if !v.live[p] {
			problems = append(problems, p+" (down)")
			continue
		}
		if err := r.syncSpaceOf(ctx, dst, p, store.SpaceGlobal, []bucketRange{{0, store.GlobalBuckets}}, true); err != nil {
			problems = append(problems, fmt.Sprintf("%s (%v)", p, err))
			continue
		}
		// The master tables' rows, from masters only.
		if err := r.syncMasterRows(ctx, dst, p, true); err != nil {
			problems = append(problems, fmt.Sprintf("%s (%v)", p, err))
			continue
		}
		if !slices.Contains(storage, p) {
			continue
		}
		if err := r.syncSpaceOf(ctx, dst, p, store.SpaceShard, []bucketRange{{0, store.ShardBuckets}}, true); err != nil {
			problems = append(problems, fmt.Sprintf("%s (%v)", p, err))
			continue
		}
		if !v.syncing[p] {
			answered[p] = true
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	for _, seg := range v.ring.Segments() {
		owners := v.ring.Owners(seg.Start, v.n)
		if !slices.ContainsFunc(owners, func(m string) bool { return answered[m] }) {
			return fmt.Errorf("%w: no replica of shard buckets %d-%d (held by %s) answered; members not copied: %s. "+
				"Bring one of them back and back up again", ErrIncompleteSnapshot, seg.Start, seg.End-1,
				strings.Join(owners, ", "), strings.Join(problems, ", "))
		}
	}
	if len(problems) > 0 {
		r.log.WarnContext(ctx, "backup: members not copied; every shard was copied from another replica",
			"members", problems)
	}
	return nil
}

// snapshotRequest asks the hub for a complete copy of the store at Path, a
// new file inside its data dir.
type snapshotRequest struct {
	Path string `json:"path"`
}

type snapshotReply struct {
	Error string `json:"error,omitempty"`
}

// serveSnapshot serves POST /v1/snapshot on the control socket.
func (n *APNode) serveSnapshot(w http.ResponseWriter, r *http.Request) {
	var req snapshotRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var reply snapshotReply
	if err := n.snapshotInDataDir(r.Context(), req.Path); err != nil {
		reply.Error = err.Error()
	}
	writeJSON(w, reply)
}

// snapshotInDataDir is Snapshot to path, which must lie inside the data dir:
// the copy is as private as the database it comes from.
func (n *APNode) snapshotInDataDir(ctx context.Context, path string) error {
	dir, err := filepath.Abs(n.cfg.DataDir)
	if err != nil {
		return err
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	rel, err := filepath.Rel(dir, abs)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("snapshot: %s is not inside the data dir %s", path, dir)
	}
	return n.Snapshot(ctx, abs)
}

// Snapshot asks the running AP member to write a complete copy of the
// cluster store to path, a new file inside its data dir.
func (c *ControlClient) Snapshot(ctx context.Context, path string) error {
	// A copy of a large store takes a while: no client timeout.
	var reply snapshotReply
	if err := c.postWith(ctx, &http.Client{Transport: c.http.Transport}, "/v1/snapshot", snapshotRequest{Path: path}, &reply); err != nil {
		return err
	}
	if reply.Error != "" {
		return errors.New(reply.Error)
	}
	return nil
}
