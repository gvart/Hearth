// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"crypto/rand"
	"fmt"
	"maps"
	"slices"
	"time"

	"github.com/gvart/hearth/internal/hlc"
)

// Merge merges mutations made on another member (see ApplyLocalMutations),
// in one transaction, last-writer-wins: a row takes a mutation only if its
// version is newer than the stored one, set-once columns keep their earliest
// value whatever the order, a tombstone is kept against older writes, and an
// audit entry is appended once, never changed. Merging the same mutations in
// any order, any number of times, leaves the same rows.
//
// Every version is first checked against this member's clock: a mutation
// stamped more than hlc.MaxSkew ahead of it refuses the whole batch with an
// error matching hlc.ErrSkew, before anything is written. Below
// VersionedSchema Merge fails with ErrSchemaTooOld.
func (s *Store) Merge(ctx context.Context, muts []Mutation) (err error) {
	for _, m := range muts {
		if err := checkMutation(m); err != nil {
			return fmt.Errorf("merge: %w", err)
		}
	}
	for _, m := range muts {
		if _, err := s.clock.Update(m.HLC); err != nil {
			return fmt.Errorf("merge %s: %w", m.Table, err)
		}
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("merge: %w", err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	if ok, err := isVersioned(ctx, tx); err != nil {
		return fmt.Errorf("merge: %w", err)
	} else if !ok {
		return fmt.Errorf("merge: %w: it needs %d", ErrSchemaTooOld, VersionedSchema)
	}
	for _, m := range muts {
		if m.Table == auditTable {
			err = mergeAudit(ctx, tx, m)
		} else {
			_, err = mergeRow(ctx, s, tx, m, true)
		}
		if err != nil {
			return fmt.Errorf("merge %s: %w", m.Table, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("merge: %w", err)
	}
	return nil
}

// checkMutation refuses a mutation no member makes.
func checkMutation(m Mutation) error {
	if m.Table == auditTable {
		if m.Deleted {
			return fmt.Errorf("%s: %w", auditTable, errAppendOnly)
		}
		return nil
	}
	spec, ok := tables[m.Table]
	if !ok {
		return fmt.Errorf("unknown table %q", m.Table)
	}
	if m.Deleted && !spec.deletable {
		return fmt.Errorf("%s: the table has no tombstones", m.Table)
	}
	for c := range m.Row {
		if c == colHLC || c == colOrigin || c == colDeleted || c == colSeq {
			return fmt.Errorf("%s: version column %s in the row", m.Table, c)
		}
	}
	return nil
}

// GCTombstones drops the tombstones older than TombstoneTTL at now, and
// returns how many. It writes the local database only: a tombstone is a
// member's own memory of a delete, and no read sees it. The hub calls it
// periodically.
func (s *Store) GCTombstones(ctx context.Context, now time.Time) (int, error) {
	if ok, err := isVersioned(ctx, s.db); err != nil || !ok {
		return 0, err
	}
	cutoff := int64(hlc.New(now.Add(-TombstoneTTL))) //nolint:gosec // an HLC fits in 63 bits
	n := 0
	for _, table := range slices.Sorted(maps.Keys(tables)) {
		if !tables[table].deletable {
			continue
		}
		// table is a key of the tables spec.
		res, err := s.db.ExecContext(ctx, `DELETE FROM `+table+` WHERE _deleted = 1 AND _hlc < ?`, cutoff) //nolint:gosec // see above
		if err != nil {
			return n, fmt.Errorf("gc tombstones of %s: %w", table, err)
		}
		k, err := res.RowsAffected()
		if err != nil {
			return n, fmt.Errorf("gc tombstones of %s: %w", table, err)
		}
		n += int(k)
	}
	return n, nil
}

// observeStored moves the clock past every version stored, so a hub whose
// wall clock went back (a Pi without an RTC) still stamps writes that
// supersede its own earlier ones.
func (s *Store) observeStored(ctx context.Context) error {
	if ok, err := isVersioned(ctx, s.db); err != nil || !ok {
		return err
	}
	for _, table := range append(slices.Sorted(maps.Keys(tables)), auditTable) {
		var h int64
		// table is a key of the tables spec.
		if err := s.db.QueryRowContext(ctx, `SELECT COALESCE(MAX(_hlc), 0) FROM `+table).Scan(&h); err != nil {
			return fmt.Errorf("read versions of %s: %w", table, err)
		}
		s.clock.Observe(hlc.Timestamp(h)) //nolint:gosec // _hlc is never negative
	}
	return nil
}

// randomOrigin is the member id of a store opened without WithOrigin.
func randomOrigin() string { return rand.Text()[:16] }
