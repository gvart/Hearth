// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
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
