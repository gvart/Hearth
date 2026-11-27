// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/gvart/hearth/internal/store"
)

// Where the master tables' rows live (#384, replauth.go): on masters only.
// A member that holds no hub CA key deletes them when it starts, and a
// master deletes them once it is demoted; a member promoted to master pulls
// them from a master that proves the key.

// masterTablesFile marks a data dir whose master tables were reset when it
// first ran a version that keeps them on masters only.
const masterTablesFile = "master-tables"

// grantTables are the master tables reset at that first start: a copy kept
// from before may be stale, a revocation or a sign-out it missed held only
// by the storage members that were the row's replicas then.
var grantTables = []string{"sessions", "mcp_tokens", "dashboard_tokens", "panel_links"}

// placeMasterRows, when the store is bound, deletes the master tables'
// rows of a member that holds no hub CA key, and resets the grant tables
// of a member of a cluster at its first start with this version.
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
	if len(n.seeds()) > 0 {
		k, err := st.DropMasterRows(ctx, grantTables...)
		if err != nil {
			return err
		}
		n.log.InfoContext(ctx, "upgrade: sign-in sessions, MCP and dashboard tokens and panel links now live on masters only; "+
			"the ones from before are gone: sign in again and create them again", "rows", k)
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

// pullMasterRows copies, to a member just promoted to master, the master
// tables' rows from a live master that proves the hub CA key, retrying
// until ctx ends: the others take this member for a master only once their
// gossip says it is one. Anti-entropy does it too, later.
func (r *Replicator) pullMasterRows(ctx context.Context) {
	for {
		v := r.view()
		if len(v.otherLiveMasters()) == 0 {
			return
		}
		for _, m := range v.otherLiveMasters() {
			proved, err := r.syncGlobal(ctx, m)
			if err == nil && proved {
				r.log.InfoContext(ctx, "promoted to master: copied the rows only masters hold", "from", m)
				return
			}
		}
		select {
		case <-ctx.Done():
			r.log.WarnContext(ctx, "promoted to master: the rows only masters hold not copied yet; anti-entropy will")
			return
		case <-time.After(250 * time.Millisecond):
		}
	}
}
