// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/gvart/hearth/internal/store"
)

// Hinted handoff (docs/design/ap-cluster.md §5.2): the rows a coordinator
// could not copy to a replica wait in a small SQLite database of the
// member's own, outside the replicated store, until the replica is back.
// The queue is bounded: past MaxHints the oldest hints are dropped, and
// anti-entropy brings their rows over instead.

// HintsFile is the hints database in a hub data dir.
const HintsFile = "hints.db"

// MaxHints bounds the hints kept, all members together.
const MaxHints = 100_000

// hintBatch is how many hints one delivery sends.
const hintBatch = 200

// Hints is a persisted queue of writes per member.
type Hints struct {
	db  *sql.DB
	max int64
}

// OpenHints opens (creating if needed) the hints database at path, keeping
// at most limit hints (MaxHints when zero).
func OpenHints(ctx context.Context, path string, limit int) (*Hints, error) {
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_txlock=immediate")
	if err != nil {
		return nil, fmt.Errorf("open hints: %w", err)
	}
	if _, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS hints (
		id     INTEGER PRIMARY KEY AUTOINCREMENT,
		member TEXT NOT NULL,
		muts   BLOB NOT NULL
	) STRICT; CREATE INDEX IF NOT EXISTS hints_member ON hints (member, id)`); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("open hints: %w", err)
	}
	if limit <= 0 {
		limit = MaxHints
	}
	return &Hints{db: db, max: int64(limit)}, nil
}

// Close closes the database.
func (h *Hints) Close() error { return h.db.Close() }

// Add keeps muts for member, dropping the oldest hints past the bound.
func (h *Hints) Add(member string, muts []store.Mutation) error {
	b, err := json.Marshal(muts)
	if err != nil {
		return err
	}
	ctx := context.Background()
	res, err := h.db.ExecContext(ctx, `INSERT INTO hints (member, muts) VALUES (?, ?)`, member, b)
	if err != nil {
		return fmt.Errorf("add hint: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return fmt.Errorf("add hint: %w", err)
	}
	if id > h.max {
		if _, err := h.db.ExecContext(ctx, `DELETE FROM hints WHERE id <= ?`, id-h.max); err != nil {
			return fmt.Errorf("bound hints: %w", err)
		}
	}
	return nil
}

// Members lists the members with hints waiting.
func (h *Hints) Members(ctx context.Context) ([]string, error) {
	rows, err := h.db.QueryContext(ctx, `SELECT DISTINCT member FROM hints ORDER BY member`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var m string
		if err := rows.Scan(&m); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// Count is the number of hints waiting for member.
func (h *Hints) Count(ctx context.Context, member string) (int, error) {
	var n int
	err := h.db.QueryRowContext(ctx, `SELECT count(*) FROM hints WHERE member = ?`, member).Scan(&n)
	return n, err
}

// Usage is the number of hints waiting for member and their size in
// bytes.
func (h *Hints) Usage(ctx context.Context, member string) (n int, size int64, err error) {
	err = h.db.QueryRowContext(ctx, `SELECT count(*), coalesce(sum(length(muts)), 0) FROM hints WHERE member = ?`, member).Scan(&n, &size)
	return n, size, err
}

// Take returns up to limit of member's oldest hints, in order, without
// removing them: their ids, and their writes together.
func (h *Hints) Take(ctx context.Context, member string, limit int) ([]int64, []store.Mutation, error) {
	rows, err := h.db.QueryContext(ctx, `SELECT id, muts FROM hints WHERE member = ? ORDER BY id LIMIT ?`, member, limit)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	var (
		ids  []int64
		muts []store.Mutation
	)
	for rows.Next() {
		var (
			id int64
			b  []byte
		)
		if err := rows.Scan(&id, &b); err != nil {
			return nil, nil, err
		}
		var ms []store.Mutation
		if err := json.Unmarshal(b, &ms); err != nil {
			return nil, nil, fmt.Errorf("decode hint %d: %w", id, err)
		}
		ids = append(ids, id)
		muts = append(muts, ms...)
	}
	return ids, muts, rows.Err()
}

// DropTables removes the rows of tables from every hint, and the hints left
// with none.
func (h *Hints) DropTables(ctx context.Context, tables []string) error {
	rows, err := h.db.QueryContext(ctx, `SELECT id, muts FROM hints`)
	if err != nil {
		return fmt.Errorf("drop hints of %v: %w", tables, err)
	}
	kept := map[int64][]store.Mutation{}
	for rows.Next() {
		var (
			id int64
			b  []byte
		)
		if err := rows.Scan(&id, &b); err != nil {
			_ = rows.Close()
			return fmt.Errorf("drop hints of %v: %w", tables, err)
		}
		var ms []store.Mutation
		if err := json.Unmarshal(b, &ms); err != nil {
			_ = rows.Close()
			return fmt.Errorf("decode hint %d: %w", id, err)
		}
		out := slices.DeleteFunc(slices.Clone(ms), func(m store.Mutation) bool { return slices.Contains(tables, m.Table) })
		if len(out) != len(ms) {
			kept[id] = out
		}
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for id, ms := range kept {
		if len(ms) == 0 {
			_, err = h.db.ExecContext(ctx, `DELETE FROM hints WHERE id = ?`, id)
		} else {
			var b []byte
			if b, err = json.Marshal(ms); err == nil {
				_, err = h.db.ExecContext(ctx, `UPDATE hints SET muts = ? WHERE id = ?`, b, id)
			}
		}
		if err != nil {
			return fmt.Errorf("drop hints of %v: %w", tables, err)
		}
	}
	return nil
}

// Replace keeps ms in place of the hints ids, under the oldest's id: ms
// are what is left of them to deliver.
func (h *Hints) Replace(ctx context.Context, ids []int64, ms []store.Mutation) error {
	if len(ids) == 0 {
		return nil
	}
	if len(ms) == 0 {
		return h.Delete(ctx, ids)
	}
	b, err := json.Marshal(ms)
	if err != nil {
		return err
	}
	first := slices.Min(ids)
	if _, err := h.db.ExecContext(ctx, `UPDATE hints SET muts = ? WHERE id = ?`, b, first); err != nil {
		return fmt.Errorf("replace hints: %w", err)
	}
	return h.Delete(ctx, slices.DeleteFunc(slices.Clone(ids), func(id int64) bool { return id == first }))
}

// DropMember removes every hint for member: it was removed from the cluster.
func (h *Hints) DropMember(ctx context.Context, member string) error {
	_, err := h.db.ExecContext(ctx, `DELETE FROM hints WHERE member = ?`, member)
	return err
}

// Delete removes delivered hints.
func (h *Hints) Delete(ctx context.Context, ids []int64) error {
	if len(ids) == 0 {
		return nil
	}
	args := make([]any, len(ids))
	for i, id := range ids {
		args[i] = id
	}
	_, err := h.db.ExecContext(ctx, `DELETE FROM hints WHERE id IN (`+strings.TrimSuffix(strings.Repeat("?,", len(ids)), ",")+`)`, args...) //nolint:gosec // placeholders only
	return err
}
