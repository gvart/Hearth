// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
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
	// Key, when set, lands the entry once however often it is appended: an
	// append whose Key is in the log already adds nothing and returns the
	// ID of the entry there. It is for an entry retried after a write that
	// seemed to fail. Before auditKeySchema it is ignored. Query does not
	// return it.
	Key string
}

// Keys of an entry's Detail that tie the entry written before an action to
// the one reporting its outcome. Query folds the two into one and removes them.
const (
	// AuditOpKey is set on the entry written before the action, to an id
	// unique to the operation.
	AuditOpKey = "audit_op"
	// AuditOutcomeOfKey is set on the outcome entry, to the same id.
	AuditOutcomeOfKey = "audit_outcome_of"
)

// maxAuditDetailDepth is how deep an entry's Detail may nest. SQLite's JSON
// functions give up at 1000 levels; no entry comes close to this.
const maxAuditDetailDepth = 64

// auditOpSchema is the schema version whose migration (00018) added the
// indexed audit_op and audit_outcome_of columns.
const auditOpSchema = 18

// auditKeySchema is the schema version whose migration (00020) added the
// audit_key column.
const auditKeySchema = 20

// The operation an entry starts (audit_op) and the one it reports the outcome
// of (audit_outcome_of), if any, are read from the detail as
//
//	CASE WHEN json_valid(detail) THEN json_extract(detail, '$.audit_op') END
//
// and the same for audit_outcome_of: a detail SQLite cannot parse has none,
// instead of failing the whole query. A write sets the columns this way (see
// AppendAudit), and a database before auditOpSchema is read this way. The
// statements below are whole constants, one per schema, so none is built at
// run time.

// auditPageIndexedSQL and auditPageDetailSQL select a page of entries and the
// operation each starts. The + before the outcome column makes SQLite scan by
// id and stop at the limit, not walk the index, which holds nearly every row
// as NULL.
const auditPageIndexedSQL = `
	SELECT id, ts, actor_kind, actor_id, action, target, decision, result, detail,
	       coalesce(audit_op, '')
	FROM audit_log
	WHERE +audit_outcome_of IS NULL
	  AND (?1 = '' OR actor_kind = ?1)
	  AND (?2 = '' OR instr(actor_id, ?2) > 0)
	  AND (?3 = '[]' OR action IN (SELECT value FROM json_each(?3)))
	  AND (?4 = '[]' OR target IN (SELECT value FROM json_each(?4)))
	  AND (?5 = '' OR decision = ?5)
	  AND (?6 = 0 OR ts >= ?6)
	  AND (?7 = 0 OR ts < ?7)
	  AND (?8 = 0 OR id < ?8)
	ORDER BY id DESC LIMIT ?9`

const auditPageDetailSQL = `
	SELECT id, ts, actor_kind, actor_id, action, target, decision, result, detail,
	       coalesce(CASE WHEN json_valid(detail) THEN json_extract(detail, '$.audit_op') END, '')
	FROM audit_log
	WHERE +CASE WHEN json_valid(detail) THEN json_extract(detail, '$.audit_outcome_of') END IS NULL
	  AND (?1 = '' OR actor_kind = ?1)
	  AND (?2 = '' OR instr(actor_id, ?2) > 0)
	  AND (?3 = '[]' OR action IN (SELECT value FROM json_each(?3)))
	  AND (?4 = '[]' OR target IN (SELECT value FROM json_each(?4)))
	  AND (?5 = '' OR decision = ?5)
	  AND (?6 = 0 OR ts >= ?6)
	  AND (?7 = 0 OR ts < ?7)
	  AND (?8 = 0 OR id < ?8)
	ORDER BY id DESC LIMIT ?9`

// auditFoldIndexedSQL and auditFoldDetailSQL select the outcome entries newer
// than ?1 that report one of the operations in the JSON array ?2.
const auditFoldIndexedSQL = `
	SELECT audit_outcome_of, result, detail
	FROM audit_log
	WHERE id > ?1 AND audit_outcome_of IN (SELECT value FROM json_each(?2))`

const auditFoldDetailSQL = `
	SELECT CASE WHEN json_valid(detail) THEN json_extract(detail, '$.audit_outcome_of') END, result, detail
	FROM audit_log
	WHERE id > ?1 AND CASE WHEN json_valid(detail) THEN json_extract(detail, '$.audit_outcome_of') END IN (SELECT value FROM json_each(?2))`

// AuditDetailTooDeep reports whether the valid JSON document detail nests
// deeper than Audit.Append accepts.
func AuditDetailTooDeep(detail []byte) bool { return jsonDepth(detail) > maxAuditDetailDepth }

// jsonDepth returns how deep the valid JSON document b nests.
func jsonDepth(b []byte) int {
	depth, deepest, inString := 0, 0, false
	for i := 0; i < len(b); i++ {
		switch c := b[i]; {
		case inString && c == '\\':
			i++
		case inString:
			inString = c != '"'
		case c == '"':
			inString = true
		case c == '[' || c == '{':
			depth++
			deepest = max(deepest, depth)
		case c == ']' || c == '}':
			depth--
		}
	}
	return deepest
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
	if jsonDepth(detail) > maxAuditDetailDepth {
		return 0, fmt.Errorf("append audit: detail nests deeper than %d levels", maxAuditDetailDepth)
	}
	if e.TS.IsZero() {
		e.TS = time.Now()
	}
	appendCmd := AppendAudit{
		TS: toMillis(e.TS), ActorKind: e.ActorKind, ActorID: e.ActorID, Action: e.Action,
		Target: e.Target, Decision: e.Decision, Result: e.Result, Detail: string(detail),
	}
	var cmd Command = appendCmd
	if e.Key != "" {
		// A cluster not yet migrated cannot apply the keyed command: the
		// entry goes in without its key, and a retry may then add it twice.
		v, err := schemaVersion(ctx, r.s.db)
		if err != nil {
			return 0, fmt.Errorf("append audit %s: %w", e.Action, err)
		}
		if v >= auditKeySchema {
			cmd = AppendAuditOnce{AppendAudit: appendCmd, Key: e.Key}
		}
	}
	res, err := r.s.apply(ctx, cmd)
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

// Query returns up to limit entries matching f, newest first, one per action:
// an entry written before an action runs carries the result and detail of the
// entry reporting its outcome, and keeps its own place in the log, so an
// action stays ordered by when it started. Without an outcome entry it is
// returned as written.
func (r Audit) Query(ctx context.Context, f AuditFilter, limit int) ([]AuditEntry, error) {
	v, err := schemaVersion(ctx, r.s.db)
	if err != nil {
		return nil, fmt.Errorf("list audit: %w", err)
	}
	return r.query(ctx, f, limit, v >= auditOpSchema)
}

// query is Query reading operation ids from the indexed columns, or from the
// detail JSON when indexed is false.
func (r Audit) query(ctx context.Context, f AuditFilter, limit int, indexed bool) ([]AuditEntry, error) {
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
	page := auditPageDetailSQL
	if indexed {
		page = auditPageIndexedSQL
	}
	rows, err := r.s.db.QueryContext(ctx, page,
		f.ActorKind, f.ActorID, string(actions), string(targets), f.Decision, since, until, f.Before, limit)
	if err != nil {
		return nil, fmt.Errorf("list audit: %w", err)
	}
	defer rows.Close()
	var out []AuditEntry
	ops := map[string]int{} // operation id to its index in out
	var oldest int64
	for rows.Next() {
		var (
			e      AuditEntry
			ts     int64
			detail string
			op     string
		)
		if err := rows.Scan(&e.ID, &ts, &e.ActorKind, &e.ActorID, &e.Action, &e.Target,
			&e.Decision, &e.Result, &detail, &op); err != nil {
			return nil, fmt.Errorf("list audit: %w", err)
		}
		e.TS = fromMillis(ts)
		e.Detail = json.RawMessage(detail)
		if op != "" {
			ops[op] = len(out)
			oldest = e.ID
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list audit: %w", err)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("list audit: %w", err)
	}
	if len(ops) == 0 {
		return out, nil
	}
	if err := r.foldOutcomes(ctx, out, ops, oldest, indexed); err != nil {
		return nil, fmt.Errorf("list audit: %w", err)
	}
	return out, nil
}

// foldOutcomes gives the entries of out named by ops the result and detail of
// their outcome entries, all of them newer than the entry with ID oldest, and
// removes the keys that tie the two from every detail.
func (r Audit) foldOutcomes(ctx context.Context, out []AuditEntry, ops map[string]int, oldest int64, indexed bool) error {
	ids, err := json.Marshal(slices.Collect(maps.Keys(ops)))
	if err != nil {
		return err
	}
	fold := auditFoldDetailSQL
	if indexed {
		fold = auditFoldIndexedSQL
	}
	rows, err := r.s.db.QueryContext(ctx, fold, oldest, string(ids))
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var op, result, detail string
		if err := rows.Scan(&op, &result, &detail); err != nil {
			return err
		}
		out[ops[op]].Result, out[ops[op]].Detail = result, json.RawMessage(detail)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for _, i := range ops {
		out[i].Detail = withoutOpKeys(out[i].Detail)
	}
	return nil
}

// withoutOpKeys returns detail without the keys that tie an action's entries,
// or as it is if it cannot be read: one odd row must not hide the log.
func withoutOpKeys(detail json.RawMessage) json.RawMessage {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(detail, &m); err != nil {
		return detail
	}
	delete(m, AuditOpKey)
	delete(m, AuditOutcomeOfKey)
	out, err := json.Marshal(m)
	if err != nil {
		return detail
	}
	return out
}

func nonNilStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
