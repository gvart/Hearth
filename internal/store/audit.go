// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"time"

	"github.com/gvart/hearth/internal/hlc"
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

// auditMode is how a query reads the log, by schema: operation ids from the
// detail (before auditOpSchema) or from the indexed columns, and in the
// order of the local id or, from VersionedSchema, of the global id (_hlc,
// _origin, _seq).
type auditMode int

const (
	auditByDetail auditMode = iota
	auditByColumn
	auditByVersion
)

// auditModeAt is the mode of a database at schema v.
func auditModeAt(v int64) auditMode {
	switch {
	case v >= VersionedSchema:
		return auditByVersion
	case v >= auditOpSchema:
		return auditByColumn
	}
	return auditByDetail
}

// auditPageVersionSQL is auditPageIndexedSQL in the order of the global id:
// the cursor ?8 is the local id of the last entry of the page before.
const auditPageVersionSQL = `
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
	  AND (?8 = 0 OR (_hlc, _origin, _seq) < (SELECT _hlc, _origin, _seq FROM audit_log WHERE id = ?8))
	ORDER BY _hlc DESC, _origin DESC, _seq DESC LIMIT ?9`

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

// auditFoldVersionSQL is auditFoldIndexedSQL after the entry with local id ?1
// in the order of the global id.
const auditFoldVersionSQL = `
	SELECT audit_outcome_of, result, detail
	FROM audit_log
	WHERE audit_outcome_of IN (SELECT value FROM json_each(?2))
	  AND (_hlc, _origin, _seq) > (SELECT _hlc, _origin, _seq FROM audit_log WHERE id = ?1)`

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
	return r.query(ctx, f, limit, auditModeAt(v))
}

// query is Query reading the log in mode.
func (r Audit) query(ctx context.Context, f AuditFilter, limit int, mode auditMode) ([]AuditEntry, error) {
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
	page := map[auditMode]string{
		auditByDetail: auditPageDetailSQL, auditByColumn: auditPageIndexedSQL, auditByVersion: auditPageVersionSQL,
	}[mode]
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
	if err := r.foldOutcomes(ctx, out, ops, oldest, mode); err != nil {
		return nil, fmt.Errorf("list audit: %w", err)
	}
	return out, nil
}

// foldOutcomes gives the entries of out named by ops the result and detail of
// their outcome entries, all of them newer than the entry with ID oldest, and
// removes the keys that tie the two from every detail.
func (r Audit) foldOutcomes(ctx context.Context, out []AuditEntry, ops map[string]int, oldest int64, mode auditMode) error {
	ids, err := json.Marshal(slices.Collect(maps.Keys(ops)))
	if err != nil {
		return err
	}
	fold := map[auditMode]string{
		auditByDetail: auditFoldDetailSQL, auditByColumn: auditFoldIndexedSQL, auditByVersion: auditFoldVersionSQL,
	}[mode]
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

// errAppendOnly refuses a change to an audit entry.
var errAppendOnly = errors.New("audit_log is append-only")

// The statements that append an entry, by schema. The operation columns come
// from the detail (see above), selected from a one-row subquery to be read by
// both the column and the expressions: from auditOpSchema, and the key from
// auditKeySchema. Parameters: ts to result, then (auditInsertVersionSQL) the
// global id _hlc, _origin, _seq, then the detail, then the key.
const (
	auditInsertSQL = `
		INSERT INTO audit_log (ts, actor_kind, actor_id, action, target, decision, result, detail)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
	auditInsertIndexedSQL = `
		INSERT INTO audit_log (ts, actor_kind, actor_id, action, target, decision, result, detail, audit_op, audit_outcome_of)
		SELECT ?, ?, ?, ?, ?, ?, ?, detail,
		       CASE WHEN json_valid(detail) THEN json_extract(detail, '$.audit_op') END,
		       CASE WHEN json_valid(detail) THEN json_extract(detail, '$.audit_outcome_of') END
		FROM (SELECT ? AS detail)`
	auditInsertKeyedSQL = `
		INSERT INTO audit_log (ts, actor_kind, actor_id, action, target, decision, result, detail, audit_op, audit_outcome_of, audit_key)
		SELECT ?, ?, ?, ?, ?, ?, ?, detail,
		       CASE WHEN json_valid(detail) THEN json_extract(detail, '$.audit_op') END,
		       CASE WHEN json_valid(detail) THEN json_extract(detail, '$.audit_outcome_of') END,
		       nullif(k, '')
		FROM (SELECT ? AS detail, ? AS k)`
	auditInsertVersionSQL = `
		INSERT INTO audit_log (ts, actor_kind, actor_id, action, target, decision, result, _hlc, _origin, _seq,
		                       detail, audit_op, audit_outcome_of, audit_key)
		SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, detail,
		       CASE WHEN json_valid(detail) THEN json_extract(detail, '$.audit_op') END,
		       CASE WHEN json_valid(detail) THEN json_extract(detail, '$.audit_outcome_of') END,
		       nullif(k, '')
		FROM (SELECT ? AS detail, ? AS k)`
)

// appendAudit appends entry c with key (none if empty) and returns its local
// id. From VersionedSchema its global id is the command's stamp, or the
// newest entry's HLC plus one if that is not newer: the log lists in the
// order entries were applied, as it did by id.
func (w *writer) appendAudit(ctx context.Context, c AppendAudit, key string) (int64, error) {
	cols := []any{c.TS, c.ActorKind, c.ActorID, c.Action, c.Target, c.Decision, c.Result}
	if !w.versioned {
		q, args := auditInsertSQL, append(cols, c.Detail)
		switch {
		case key != "":
			q, args = auditInsertKeyedSQL, append(args, key)
		case w.schema >= auditOpSchema:
			q = auditInsertIndexedSQL
		}
		res, err := w.tx.ExecContext(ctx, q, args...)
		if err != nil {
			return 0, err
		}
		return res.LastInsertId()
	}
	var top int64
	if err := w.tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(_hlc), 0) FROM audit_log`).Scan(&top); err != nil {
		return 0, err
	}
	m := Mutation{
		Table: auditTable, HLC: max(w.stamp.HLC, hlc.Timestamp(top)+1), Origin: w.stamp.Origin, //nolint:gosec // _hlc is never negative
		Row: map[string]any{
			"ts": c.TS, "actor_kind": c.ActorKind, "actor_id": c.ActorID, "action": c.Action, "target": c.Target,
			"decision": c.Decision, "result": c.Result, "detail": c.Detail, "audit_key": optString(key),
		},
	}
	var id int64
	if err := w.dt.merge(ctx, w.tx, m, func() (err error) {
		id, err = insertAudit(ctx, w.tx, m)
		return err
	}); err != nil {
		return 0, err
	}
	w.muts = append(w.muts, m)
	return id, nil
}

// insertAudit appends the entry of m and returns its local id.
func insertAudit(ctx context.Context, tx *sql.Tx, m Mutation) (int64, error) {
	r := row(m.Row)
	key := ""
	if !r.isNull("audit_key") {
		key = r.str("audit_key")
	}
	res, err := tx.ExecContext(ctx, auditInsertVersionSQL,
		r["ts"], r["actor_kind"], r["actor_id"], r["action"], r["target"], r["decision"], r["result"],
		int64(m.HLC), m.Origin, m.Seq, r["detail"], key) //nolint:gosec // an HLC fits in 63 bits
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// mergeAudit appends the entry of m unless the log has it: an entry with its
// global id, or with its key. An entry is never changed or removed.
func mergeAudit(ctx context.Context, tx *sql.Tx, m Mutation) error {
	var exists bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM audit_log WHERE _hlc = ? AND _origin = ? AND _seq = ?)
		OR EXISTS (SELECT 1 FROM audit_log WHERE audit_key = ?)`,
		int64(m.HLC), m.Origin, m.Seq, m.Row["audit_key"]).Scan(&exists); err != nil { //nolint:gosec // an HLC fits in 63 bits
		return err
	}
	if exists {
		return nil
	}
	_, err := insertAudit(ctx, tx, m)
	return err
}
