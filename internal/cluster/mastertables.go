// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/gvart/hearth/internal/store"
)

// Where the master tables' rows live (#384, replauth.go): on masters only.
// A member that holds no hub CA key deletes them when it starts, and a
// master deletes them once it is demoted; a member promoted to master pulls
// them from a master that proves the key.

// masterTablesFile marks a data dir whose hints of the grant tables were
// dropped when it first ran a version that keeps them on masters only.
const masterTablesFile = "master-tables"

// grantTables are the master tables the store resets in a database that was
// a cluster's, as it first opens with this version (migration 00041): a copy
// kept from before may be stale, a revocation or a sign-out it missed held
// only by the storage members that were the row's replicas then. Their
// hints from before go too, once per data dir: they would bring them back.
var grantTables = []string{"sessions", "mcp_tokens", "dashboard_tokens", "panel_links"}

// placeMasterRows, when the store is bound, deletes the master tables'
// rows of a member that holds no hub CA key, and the hints of the grant
// tables kept from before this version.
func (n *APNode) placeMasterRows(ctx context.Context, st *store.Store) error {
	if !n.cfg.CA.HasKey() {
		k, err := st.DropMasterRows(ctx)
		if err != nil {
			return err
		}
		if k > 0 {
			n.log.InfoContext(ctx, "not a master: deleted the rows only masters hold (sessions, MCP and dashboard tokens, panels)", "rows", k)
		}
	}
	marker := filepath.Join(n.cfg.DataDir, StateDir, masterTablesFile)
	switch _, err := os.Stat(marker); {
	case err == nil:
		return nil
	case !errors.Is(err, fs.ErrNotExist):
		return fmt.Errorf("master tables: %w", err)
	}
	if n.hints != nil {
		if err := n.hints.DropTables(ctx, grantTables); err != nil {
			return err
		}
	}
	if err := writeFileSync(marker, []byte("1\n"), 0o600); err != nil {
		return fmt.Errorf("master tables: %w", err)
	}
	return nil
}

// dropMasterRows deletes the master tables' rows of a demoted master.
func (n *APNode) dropMasterRows(ctx context.Context) error {
	k, err := n.st.DropMasterRows(ctx)
	if err != nil {
		return err
	}
	n.log.InfoContext(ctx, "demoted from master: deleted the rows only masters hold", "rows", k)
	return nil
}

// pullMasterRowsFor bounds how long pullMasterRows retries; anti-entropy
// compares the rows later anyway.
const pullMasterRowsFor = 2 * time.Minute

// pullMasterRows compares, on a master that started or was just promoted,
// the master tables' rows with every other live master that proves the hub
// CA key, so it holds the newest of each before it reads its own
// (MasterRowsReady). It retries, backing off, while none answers: the
// others take a promoted member for a master only once their gossip says
// it is one.
func (r *Replicator) pullMasterRows(ctx context.Context) {
	start, wait := r.cfg.Now(), 250*time.Millisecond
	for {
		done, masters := r.compareMasterRows(ctx)
		if done {
			return
		}
		if r.cfg.Now().Sub(start) > pullMasterRowsFor {
			r.log.WarnContext(ctx, "the rows only masters hold not compared with another master yet; "+
				"sign-ins wait for anti-entropy", "masters", masters)
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		wait = min(2*wait, 5*time.Second)
	}
}

// compareMasterRows runs one round of pullMasterRows, one at a time. done
// reports that there is nothing left to wait for; masters are the ones it
// tried.
func (r *Replicator) compareMasterRows(ctx context.Context) (done bool, masters []string) {
	r.pullMu.Lock()
	defer r.pullMu.Unlock()
	if !r.holdsKey() || r.masterRowsSynced.Load() {
		return true, nil
	}
	masters = slices.DeleteFunc(r.view().otherLiveMasters(), r.unproved)
	if len(masters) == 0 {
		return true, nil // no other master live: nothing to wait for
	}
	var from []string
	for _, m := range masters {
		proved, err := r.syncGlobal(ctx, m)
		if err != nil || !proved {
			r.log.DebugContext(ctx, "compare the rows only masters hold", "member", m, "proved", proved, "err", err)
			continue
		}
		from = append(from, m)
	}
	if !r.masterRowsSynced.Load() {
		return false, masters
	}
	r.log.InfoContext(ctx, "compared the rows only masters hold with the other masters", "with", from)
	return true, masters
}

// askPullMaster asks Run to compare the master tables' rows with the
// other masters now; one ask already waiting covers this one.
func (r *Replicator) askPullMaster() {
	select {
	case r.pullMaster <- struct{}{}:
	default:
	}
}

// errMasterRowsSyncing refuses a read of the master tables' rows on a
// master that has not compared them with another since it started or was
// promoted: its copy may lack a sign-out or a reset (#384).
var errMasterRowsSyncing = errors.New("syncing: this master has not compared sessions and tokens with another master yet")

// MasterRowsReady implements store.MasterRowsGate: a master reads its copy
// of the master tables' rows once it compared them with another master,
// or while no other is live (one that answered without a proof is none),
// and not while it still seeks its cluster. A member without the hub CA
// key holds none.
func (r *Replicator) MasterRowsReady() error {
	if !r.holdsKey() || r.masterRowsSynced.Load() {
		return nil
	}
	v := r.view() // first: it notices the cluster found
	if r.seeking.Load() {
		return fmt.Errorf("%w: %w", errMasterRowsSyncing, store.ErrUnavailable)
	}
	if !slices.ContainsFunc(v.otherLiveMasters(), func(m string) bool { return !r.unproved(m) }) {
		return nil
	}
	// Once, here, for a quick timeout: the read waits for it rather than
	// fail.
	ctx, cancel := context.WithTimeout(*r.ctx.Load(), 2*r.cfg.QuickTimeout)
	defer cancel()
	if done, _ := r.compareMasterRows(ctx); done {
		return nil
	}
	r.askPullMaster()
	return fmt.Errorf("%w: %w", errMasterRowsSyncing, store.ErrUnavailable)
}
