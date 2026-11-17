// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// AuditEntry is one row of the append-only audit log.
type AuditEntry struct {
	ID        int64
	TS        time.Time
	ActorKind string
	ActorID   string
	Action    string
	Target    string
	Decision  string
	Result    string
	// Detail is an opaque JSON document; nil is stored as {}.
	Detail json.RawMessage
}

// Audit is the repository for the audit log. Append is the only write path:
// there is no update or delete, and the schema rejects both.
type Audit struct{ db *sql.DB }

// Audit returns the audit log repository.
func (s *Store) Audit() Audit { return Audit{db: s.db} }

// Append writes e and returns its ID. A zero TS is set to the current time.
func (r Audit) Append(ctx context.Context, e AuditEntry) (int64, error) {
	if e.ActorKind == "" || e.ActorID == "" || e.Action == "" || e.Decision == "" {
		return 0, errors.New("append audit: actor_kind, actor_id, action and decision are required")
	}
	detail := []byte(e.Detail)
	if len(detail) == 0 {
		detail = []byte("{}")
	}
	if !json.Valid(detail) {
		return 0, errors.New("append audit: detail is not valid JSON")
	}
	if e.TS.IsZero() {
		e.TS = time.Now()
	}
	res, err := r.db.ExecContext(ctx, `
		INSERT INTO audit_log (ts, actor_kind, actor_id, action, target, decision, result, detail)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		toMillis(e.TS), e.ActorKind, e.ActorID, e.Action, e.Target, e.Decision, e.Result, string(detail))
	if err != nil {
		return 0, fmt.Errorf("append audit %s: %w", e.Action, err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("append audit %s: %w", e.Action, err)
	}
	return id, nil
}

// List returns up to limit entries, newest first.
func (r Audit) List(ctx context.Context, limit int) ([]AuditEntry, error) {
	if limit <= 0 {
		return nil, errors.New("list audit: limit must be positive")
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, ts, actor_kind, actor_id, action, target, decision, result, detail
		FROM audit_log ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("list audit: %w", err)
	}
	defer rows.Close()
	var out []AuditEntry
	for rows.Next() {
		var (
			e      AuditEntry
			ts     int64
			detail string
		)
		if err := rows.Scan(&e.ID, &ts, &e.ActorKind, &e.ActorID, &e.Action, &e.Target,
			&e.Decision, &e.Result, &detail); err != nil {
			return nil, fmt.Errorf("list audit: %w", err)
		}
		e.TS = fromMillis(ts)
		e.Detail = json.RawMessage(detail)
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list audit: %w", err)
	}
	return out, nil
}
