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

// closeMasterRows closes the master tables' rows until they are compared
// again: at the start and on a promotion.
func (r *Replicator) closeMasterRows() {
	r.gateSince.Store(r.cfg.Now().UnixNano())
	r.masterRowsSynced.Store(false)
	r.lone.Store(false)
}

// Uncompared reports whether this master reads the master tables' rows
// without having compared them with another master since it started or
// was promoted: it found none live for LoneMasterWait. The web UI says so.
func (r *Replicator) Uncompared() bool { return r.holdsKey() && r.lone.Load() }

// pullMasterRows compares, on a master that started or was just promoted,
// the master tables' rows with every other live master that proves the hub
// CA key, so it holds the newest of each before it reads its own
// (MasterRowsReady). It retries, backing off, until it is done: the others
// take a promoted member for a master only once their gossip says it is
// one, and one that does not answer leaves the live set once the gossip
// suspects it.
func (r *Replicator) pullMasterRows(ctx context.Context) {
	wait := 250 * time.Millisecond
	for {
		r.pullMu.Lock()
		rctx, cancel := context.WithTimeout(ctx, r.cfg.RequestTimeout)
		done, _ := r.compareMasterRows(rctx)
		cancel()
		r.pullMu.Unlock()
		if done {
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

// compareMasterRows runs one round of pullMasterRows, under pullMu. It is
// done, and opens the rows, once it compared them with every other live
// master that proves the hub CA key (one that answered without a proof is
// no master), or once none was live for LoneMasterWait since the gate
// closed; masters are the ones it tried.
func (r *Replicator) compareMasterRows(ctx context.Context) (done bool, masters []string) {
	if !r.holdsKey() || r.masterRowsSynced.Load() {
		return true, nil
	}
	v := r.view() // first: it notices the cluster found
	if r.seeking.Load() {
		return false, nil
	}
	masters = slices.DeleteFunc(v.otherLiveMasters(), r.unproved)
	if len(masters) == 0 {
		clustered, err := r.store().Hubs().Clustered(ctx)
		if err != nil {
			r.log.WarnContext(ctx, "compare the rows only masters hold", "err", err)
			return false, nil
		}
		others := append(slices.Clone(v.masterSet), v.leftMasters...)
		knownMaster := slices.ContainsFunc(others, func(m string) bool { return m != v.self && !r.unproved(m) })
		if !clustered || (len(v.live) > 1 && !knownMaster) {
			// A hub alone, or one whose gossip found its cluster and no
			// other master in it: no other master holds a row it lacks.
			r.masterRowsSynced.Store(true)
			return true, nil
		}
		if r.cfg.Now().Sub(time.Unix(0, r.gateSince.Load())) < r.cfg.LoneMasterWait {
			return false, nil // the gossip may still find one
		}
		r.lone.Store(true)
		r.masterRowsSynced.Store(true)
		r.log.WarnContext(ctx, "no other master to compare sessions and tokens with: this hub reads its own copy, "+
			"which may lack a sign-out or a password reset made on a master it cannot reach", "waited", r.cfg.LoneMasterWait)
		return true, nil
	}
	for _, m := range masters {
		proved, err := r.syncGlobal(ctx, m)
		// syncGlobal compared the master tables' rows too if m is a
		// master that proved the key (syncMasterRows).
		proved = proved && r.saysMaster(m) && r.provedLast(m)
		if err != nil || !proved {
			r.log.DebugContext(ctx, "compare the rows only masters hold", "member", m, "proved", proved, "err", err)
			return false, masters
		}
	}
	r.masterRowsSynced.Store(true)
	r.log.InfoContext(ctx, "compared the rows only masters hold with the other masters", "with", masters)
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
	// Once, here, for a quick timeout: the read waits for it rather than
	// fail, unless a comparison runs already (it does not queue behind it).
	if !r.pullMu.TryLock() {
		return fmt.Errorf("%w: %w", errMasterRowsSyncing, store.ErrUnavailable)
	}
	ctx, cancel := context.WithTimeout(*r.ctx.Load(), 2*r.cfg.QuickTimeout)
	done, _ := r.compareMasterRows(ctx)
	cancel()
	r.pullMu.Unlock()
	if done {
		return nil
	}
	r.askPullMaster()
	return fmt.Errorf("%w: %w", errMasterRowsSyncing, store.ErrUnavailable)
}
