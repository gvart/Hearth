// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
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
type Audit struct{ s *Store }

// Audit returns the audit log repository.
func (s *Store) Audit() Audit { return Audit{s: s} }

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
	res, err := r.s.apply(ctx, AppendAudit{
		TS: toMillis(e.TS), ActorKind: e.ActorKind, ActorID: e.ActorID, Action: e.Action,
		Target: e.Target, Decision: e.Decision, Result: e.Result, Detail: string(detail),
	})
	if err != nil {
		return 0, fmt.Errorf("append audit %s: %w", e.Action, err)
	}
	return res.ID, nil
}

// AuditFilter selects audit entries. Zero fields match everything.
type AuditFilter struct {
	ActorKind string
	// ActorID matches actor IDs that contain it.
	ActorID string
	// Actions match any of these actions.
	Actions []string
	// Targets match any of these targets.
	Targets  []string
	Decision string
	// Since and Until bound the timestamp: Since <= ts < Until.
	Since, Until time.Time
	// Before returns only entries older than the entry with this ID: the
	// cursor for the next page.
	Before int64
}

// List returns up to limit entries, newest first.
func (r Audit) List(ctx context.Context, limit int) ([]AuditEntry, error) {
	return r.Query(ctx, AuditFilter{}, limit)
}

// Query returns up to limit entries matching f, newest first.
func (r Audit) Query(ctx context.Context, f AuditFilter, limit int) ([]AuditEntry, error) {
	if limit <= 0 {
		return nil, errors.New("list audit: limit must be positive")
	}
	actions, err := json.Marshal(nonNilStrings(f.Actions))
	if err != nil {
		return nil, fmt.Errorf("list audit: %w", err)
	}
	targets, err := json.Marshal(nonNilStrings(f.Targets))
	if err != nil {
		return nil, fmt.Errorf("list audit: %w", err)
	}
	var since, until int64
	if !f.Since.IsZero() {
		since = toMillis(f.Since)
	}
	if !f.Until.IsZero() {
		until = toMillis(f.Until)
	}
	rows, err := r.s.db.QueryContext(ctx, `
		SELECT id, ts, actor_kind, actor_id, action, target, decision, result, detail
		FROM audit_log
		WHERE (?1 = '' OR actor_kind = ?1)
		  AND (?2 = '' OR instr(actor_id, ?2) > 0)
		  AND (?3 = '[]' OR action IN (SELECT value FROM json_each(?3)))
		  AND (?4 = '[]' OR target IN (SELECT value FROM json_each(?4)))
		  AND (?5 = '' OR decision = ?5)
		  AND (?6 = 0 OR ts >= ?6)
		  AND (?7 = 0 OR ts < ?7)
		  AND (?8 = 0 OR id < ?8)
		ORDER BY id DESC LIMIT ?9`,
		f.ActorKind, f.ActorID, string(actions), string(targets), f.Decision, since, until, f.Before, limit)
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

func nonNilStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
