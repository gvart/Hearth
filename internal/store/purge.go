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
	here, err := s.TablesHere(ctx)
	if err != nil {
		return 0, fmt.Errorf("drop shard rows: %w", err)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("drop shard rows: %w", err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	dt := s.newDigestTx()
	// Children before their parents.
	for _, table := range slices.Backward(here) {
		if table == auditTable || globalTables[table] {
			continue
		}
		var keys [][]any
		err := scanDigests(ctx, tx, table, func(key []any, _ Space, _ int, _ rowState) error {
			keys = append(keys, slices.Clone(key))
			return nil
		})
		if err != nil {
			return n, fmt.Errorf("drop shard rows of %s: %w", table, err)
		}
		for _, key := range keys {
			m, ok, err := s.readRow(ctx, tx, RowRef{Table: table, Key: key})
			if err != nil {
				return n, fmt.Errorf("drop shard rows of %s: %w", table, err)
			}
			if !ok {
				continue // deleted with its parent
			}
			st, _, err := dt.state(ctx, tx, table, key)
			if err != nil {
				return n, fmt.Errorf("drop shard rows of %s: %w", table, err)
			}
			// Identifiers are constants of the tables spec.
			if _, err := tx.ExecContext(ctx, `DELETE FROM `+table+` WHERE `+pkWhere(keyCols(table)), key...); err != nil { //nolint:gosec // table and columns from the store's own list
				return n, fmt.Errorf("drop shard rows of %s: %w", table, err)
			}
			if err := dt.dropped(table, key, st, m.Row); err != nil {
				return n, err
			}
			n++
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("drop shard rows: %w", err)
	}
	dt.commit()
	return n, nil
}
