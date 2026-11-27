// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"fmt"
	"slices"
)

// DropShardRows deletes from this member's own database, and from its
// digests, every row of the sharded tables, tombstones included, except the
// audit log, which is append-only. Nothing is replicated. A member promoted
// to storage again does it before it copies its buckets from the others:
// rows it kept from before its demotion are stale, and their tombstones
// elsewhere may be gone, so copying them back could revive deleted rows.
// It returns how many rows it deleted.
func (s *Store) DropShardRows(ctx context.Context) (n int, err error) {
	n, err = s.dropRows(ctx, func(table string) bool { return table != auditTable && !globalTables[table] })
	if err != nil {
		return 0, fmt.Errorf("drop shard rows: %w", err)
	}
	return n, nil
}

// DropMasterRows deletes from this member's own database, and from its
// digests, every row of the master tables named, of every master table if
// none is, tombstones included (#384). Nothing is replicated. A member that
// holds no hub CA key, a storage-only member or a demoted master, holds none
// of their rows. It returns how many rows it deleted.
func (s *Store) DropMasterRows(ctx context.Context, tables ...string) (n int, err error) {
	for _, t := range tables {
		if !masterTables[t] {
			return 0, fmt.Errorf("drop master rows: %s is no master table", t)
		}
	}
	n, err = s.dropRows(ctx, func(table string) bool {
		return masterTables[table] && (len(tables) == 0 || slices.Contains(tables, table))
	})
	if err != nil {
		return 0, fmt.Errorf("drop master rows: %w", err)
	}
	return n, nil
}

// dropRows deletes from this member's own database the rows of the tables
// drop accepts, tombstones included, and takes them out of the digests.
func (s *Store) dropRows(ctx context.Context, drop func(table string) bool) (n int, err error) {
	here, err := s.TablesHere(ctx)
	if err != nil {
		return 0, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	dt := s.newDigestTx()
	// Children before their parents.
	for _, table := range slices.Backward(here) {
		if !drop(table) {
			continue
		}
		var keys [][]any
		err := scanDigests(ctx, tx, table, func(key []any, _ Space, _ int, _ rowState) error {
			keys = append(keys, slices.Clone(key))
			return nil
		})
		if err != nil {
			return n, fmt.Errorf("%s: %w", table, err)
		}
		for _, key := range keys {
			m, ok, err := s.readRow(ctx, tx, RowRef{Table: table, Key: key})
			if err != nil {
				return n, fmt.Errorf("%s: %w", table, err)
			}
			if !ok {
				continue // deleted with its parent
			}
			st, _, err := dt.state(ctx, tx, table, key)
			if err != nil {
				return n, fmt.Errorf("%s: %w", table, err)
			}
			// Identifiers are constants of the tables spec.
			if _, err := tx.ExecContext(ctx, `DELETE FROM `+table+` WHERE `+pkWhere(keyCols(table)), key...); err != nil { //nolint:gosec // table and columns from the store's own list
				return n, fmt.Errorf("%s: %w", table, err)
			}
			if err := dt.dropped(table, key, st, m.Row); err != nil {
				return n, err
			}
			n++
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	dt.commit()
	return n, nil
}
