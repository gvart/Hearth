// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// The seeds file (seedsFile) keeps the gossip address of each other member
// this one learnt, one "<node id> <address>" line each, so it finds the
// cluster again after a restart. A line of an address alone is one a join
// response named (writeJoinSeeds), its member not seen on the gossip yet.
//
// An entry goes only on positive news of its member: the gossip shows it at
// a new address (the entry is replaced), or it was removed from the cluster
// (its hub certificates are all revoked). A member down, or that left the
// gossip because its hub stopped, keeps its entry: after a whole-cluster
// power cut every hub still knows where the others were.

// seedEntry is a line of the seeds file; id is "" for an address alone.
type seedEntry struct{ id, addr string }

func (n *APNode) seedsPath() string { return filepath.Join(n.cfg.DataDir, StateDir, seedsFile) }

// readSeeds reads the seeds file at path; a missing one has no entries.
func readSeeds(path string) []seedEntry {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []seedEntry
	for line := range strings.Lines(string(b)) {
		switch f := strings.Fields(line); len(f) {
		case 1:
			out = append(out, seedEntry{addr: f[0]})
		case 2:
			out = append(out, seedEntry{id: f[0], addr: f[1]})
		}
	}
	return out
}

// seeds are the configured seeds and the members learnt before.
func (n *APNode) seeds() []string {
	out := slices.Clone(n.cfg.Seeds)
	for _, e := range readSeeds(n.seedsPath()) {
		out = append(out, e.addr)
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// updateSeeds brings the seeds file up to date with the gossip: each other
// member it lists, at its address now, and the entries it does not list
// kept but those of removed members.
func (n *APNode) updateSeeds() {
	path := n.seedsPath()
	byID := map[string]string{}
	var anon []string
	for _, e := range readSeeds(path) {
		if e.id == "" {
			anon = append(anon, e.addr)
		} else {
			byID[e.id] = e.addr
		}
	}
	listed := map[string]bool{}
	for _, mi := range n.membership.Members() {
		if mi.ID == n.cfg.NodeID || mi.Address == "" {
			continue
		}
		byID[mi.ID], listed[mi.ID] = mi.Address, true
		anon = slices.DeleteFunc(anon, func(a string) bool { return a == mi.Address })
	}
	delete(byID, n.cfg.NodeID)
	lines := make([]string, 0, len(byID)+len(anon))
	for id, addr := range byID {
		// Members leaves removed members out: so is one this hub has not
		// heard of since it restarted, once its revocation is here.
		if !listed[id] && n.removed(id) {
			continue
		}
		lines = append(lines, id+" "+addr)
	}
	slices.Sort(lines)
	slices.Sort(anon)
	lines = append(lines, slices.Compact(anon)...)
	var content string
	if len(lines) > 0 {
		content = strings.Join(lines, "\n") + "\n"
	}
	old, err := os.ReadFile(path)
	if (err != nil && content == "") || string(old) == content {
		return
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		n.log.Warn("save the gossip seeds", "err", err)
	}
}

// runSeeds keeps the seeds file up to date until ctx ends: at each change
// of the members, and every refresh for removals the gossip does not tell.
func (n *APNode) runSeeds(ctx context.Context, changes <-chan struct{}) {
	t := time.NewTicker(n.membership.cfg.RefreshEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-changes:
		case <-t.C:
		}
		n.updateSeeds()
	}
}
