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
	"strconv"
	"strings"
	"time"

	"github.com/gvart/hearth/internal/hlc"
)

// AuditEntry is one row of the append-only audit log.
type AuditEntry struct {
	ID int64
	// Cursor, filled by Query in a sharded cluster, is the entry's place in
	// the log, for AuditFilter.BeforeCursor.
	Cursor    string
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
	// Verification, filled by Query, is whether the entry's seal checks
	// (#387): AuditVerified, AuditUnverified, AuditLegacy or AuditUnchecked;
	// for an entry folded with its outcome, the worse of the two.
	Verification string
	// SealOrigin and SealSeq, filled by Query for a sealed entry, are its
	// place in the chain of the master that sealed it.
	SealOrigin string
	SealSeq    int64
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
	// auditByChain is auditByVersion with the entries' seals (#387).
	auditByChain
)

// auditModeAt is the mode of a database at schema v.
func auditModeAt(v int64) auditMode {
	switch {
	case v >= auditChainSchema:
		return auditByChain
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

// auditPageChainLocalSQL is auditPageVersionSQL with the columns an entry's
// seal covers (#387).
const auditPageChainLocalSQL = `
	SELECT id, ts, actor_kind, actor_id, action, target, decision, result, detail,
	       coalesce(audit_op, ''), coalesce(audit_key, ''), coalesce(chain_origin, ''), coalesce(chain_seq, 0),
	       coalesce(chain_prev, ''), coalesce(chain_kid, ''), coalesce(chain_mac, '')
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

// auditFoldChainSQL is auditFoldVersionSQL with the columns the outcome's
// seal covers.
const auditFoldChainSQL = `
	SELECT audit_outcome_of, result, detail, ts, actor_kind, actor_id, action, target, decision,
	       coalesce(audit_key, ''), coalesce(chain_origin, ''), coalesce(chain_seq, 0),
	       coalesce(chain_prev, ''), coalesce(chain_kid, ''), coalesce(chain_mac, '')
	FROM audit_log
	WHERE audit_outcome_of IN (SELECT value FROM json_each(?2))
	  AND (_hlc, _origin, _seq) > (SELECT _hlc, _origin, _seq FROM audit_log WHERE id = ?1)`

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
	key := ""
	if e.Key != "" {
		// A cluster not yet migrated cannot apply the keyed command: the
		// entry goes in without its key, and a retry may then add it twice.
		v, err := schemaVersion(ctx, r.s.db)
		if err != nil {
			return 0, fmt.Errorf("append audit %s: %w", e.Action, err)
		}
		if v >= auditKeySchema {
			key = e.Key
		}
	}
	sealer, err := r.s.sealsAudit(ctx)
	if err != nil {
		return 0, fmt.Errorf("append audit %s: %w", e.Action, err)
	}
	if sealer != nil {
		return r.appendSealed(ctx, appendCmd, key, sealer)
	}
	res, err := r.s.apply(ctx, auditCommand(appendCmd, key))
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
	// BeforeCursor is Before in a sharded cluster, where an ID (the HLC) is
	// not unique: the Cursor of the last entry of the page before.
	BeforeCursor string
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
	if r.s.shards != nil {
		sealed, err := r.s.writesAt(ctx, auditChainSchema)
		if err != nil {
			return nil, fmt.Errorf("list audit: %w", err)
		}
		if sealed {
			return r.queryChain(ctx, f, string(actions), string(targets), since, until, limit)
		}
		return r.queryShards(ctx, f, string(actions), string(targets), since, until, limit)
	}
	page := map[auditMode]string{
		auditByDetail: auditPageDetailSQL, auditByColumn: auditPageIndexedSQL, auditByVersion: auditPageVersionSQL,
		auditByChain: auditPageChainLocalSQL,
	}[mode]
	rows, err := r.s.db.QueryContext(ctx, page,
		f.ActorKind, f.ActorID, string(actions), string(targets), f.Decision, since, until, f.Before, limit)
	if err != nil {
		return nil, fmt.Errorf("list audit: %w", err)
	}
	defer rows.Close()
	ck, err := r.checker(ctx, mode)
	if err != nil {
		return nil, fmt.Errorf("list audit: %w", err)
	}
	var out []AuditEntry
	ops := map[string]int{} // operation id to its index in out
	var oldest int64
	for rows.Next() {
		var (
			e   AuditEntry
			raw auditRaw
			op  string
		)
		dest := []any{&e.ID, &raw.TS, &raw.ActorKind, &raw.ActorID, &raw.Action, &raw.Target,
			&raw.Decision, &raw.Result, &raw.Detail, &op}
		if mode == auditByChain {
			dest = append(dest, &raw.Key, &raw.Origin, &raw.Seq, &raw.Prev, &raw.KID, &raw.MAC)
		}
		if err := rows.Scan(dest...); err != nil {
			return nil, fmt.Errorf("list audit: %w", err)
		}
		e.TS, e.ActorKind, e.ActorID, e.Action, e.Target = fromMillis(raw.TS), raw.ActorKind, raw.ActorID, raw.Action, raw.Target
		e.Decision, e.Result, e.Detail = raw.Decision, raw.Result, json.RawMessage(raw.Detail)
		e.Verification = ck(raw)
		if raw.MAC != "" {
			e.SealOrigin, e.SealSeq = raw.Origin, raw.Seq
		}
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
	if err := r.foldOutcomes(ctx, out, ops, oldest, mode, ck); err != nil {
		return nil, fmt.Errorf("list audit: %w", err)
	}
	return out, nil
}

// checker returns the verification of an entry a query in mode reads: below
// auditChainSchema every entry is legacy.
func (r Audit) checker(ctx context.Context, mode auditMode) (func(auditRaw) string, error) {
	if mode != auditByChain {
		return func(auditRaw) string { return AuditLegacy }, nil
	}
	since, err := r.s.auditSince(ctx)
	if err != nil {
		return nil, err
	}
	sealer := r.s.auditSealer()
	return func(raw auditRaw) string { return raw.verify(since, sealer) }, nil
}

// foldOutcomes gives the entries of out named by ops the result and detail of
// their outcome entries, all of them newer than the entry with ID oldest, and
// removes the keys that tie the two from every detail. An entry's
// verification becomes the worse of its own and its outcome's (ck).
func (r Audit) foldOutcomes(ctx context.Context, out []AuditEntry, ops map[string]int, oldest int64, mode auditMode, ck func(auditRaw) string) error {
	ids, err := json.Marshal(slices.Collect(maps.Keys(ops)))
	if err != nil {
		return err
	}
	fold := map[auditMode]string{
		auditByDetail: auditFoldDetailSQL, auditByColumn: auditFoldIndexedSQL, auditByVersion: auditFoldVersionSQL,
		auditByChain: auditFoldChainSQL,
	}[mode]
	rows, err := r.s.db.QueryContext(ctx, fold, oldest, string(ids))
	if err != nil {
		return err
	}
	defer rows.Close()
	outcome := map[string]auditRaw{}
	for rows.Next() {
		var op string
		var raw auditRaw
		dest := []any{&op, &raw.Result, &raw.Detail}
		if mode == auditByChain {
			dest = append(dest, &raw.TS, &raw.ActorKind, &raw.ActorID, &raw.Action, &raw.Target, &raw.Decision,
				&raw.Key, &raw.Origin, &raw.Seq, &raw.Prev, &raw.KID, &raw.MAC)
		}
		if err := rows.Scan(dest...); err != nil {
			return err
		}
		outcome[op] = raw
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for op, raw := range outcome {
		e := &out[ops[op]]
		e.Result, e.Detail = raw.Result, json.RawMessage(raw.Detail)
		e.Verification = worseVerification(e.Verification, ck(raw))
	}
	for _, i := range ops {
		out[i].Detail = withoutOpKeys(out[i].Detail)
	}
	return nil
}

// auditPageShardSQL is the audit page of a member of a sharded cluster, in
// the strict order of the global id (_hlc, _origin, _seq), newest first: the
// cursor ?8, ?10, ?11 is the global id of the last entry of the page before
// (?8 = 0: none), and the page holds only entries before it in that order,
// so entries with the same HLC from two members are neither skipped nor
// repeated. The outcome folds in on the member itself, which holds an
// action's entries together (auditPartition). After its own columns it
// selects the hidden ones queryAll merges by.
const auditPageShardSQL = `
	SELECT _hlc, _origin, _seq, ts, actor_kind, actor_id, action, target, decision,
	       coalesce((SELECT o.result FROM audit_log o WHERE a.audit_op IS NOT NULL AND o.audit_outcome_of = a.audit_op
	                 ORDER BY o._hlc DESC, o._origin DESC, o._seq DESC LIMIT 1), result),
	       coalesce((SELECT o.detail FROM audit_log o WHERE a.audit_op IS NOT NULL AND o.audit_outcome_of = a.audit_op
	                 ORDER BY o._hlc DESC, o._origin DESC, o._seq DESC LIMIT 1), detail),
	       coalesce(audit_op, ''),
	       _hlc, _origin, _seq, _hlc, _origin
	FROM audit_log a
	WHERE +audit_outcome_of IS NULL
	  AND (?1 = '' OR actor_kind = ?1)
	  AND (?2 = '' OR instr(actor_id, ?2) > 0)
	  AND (?3 = '[]' OR action IN (SELECT value FROM json_each(?3)))
	  AND (?4 = '[]' OR target IN (SELECT value FROM json_each(?4)))
	  AND (?5 = '' OR decision = ?5)
	  AND (?6 = 0 OR ts >= ?6)
	  AND (?7 = 0 OR ts < ?7)
	  AND (?8 = 0 OR (_hlc, _origin, _seq) < (?8, ?10, ?11))
	ORDER BY _hlc DESC, _origin DESC, _seq DESC LIMIT ?9`

// queryShards is query in a sharded cluster: every member pages its own
// entries, outcomes folded in, and the pages merge newest first (a k-way
// merge in the strict order of the global id). An entry's ID is its HLC, its
// Cursor its global id, and f.BeforeCursor the cursor of the page before.
func (r Audit) queryShards(ctx context.Context, f AuditFilter, actions, targets string, since, until int64, limit int) ([]AuditEntry, error) {
	var before auditCursor
	if f.BeforeCursor != "" {
		var err error
		if before, err = parseAuditCursor(f.BeforeCursor); err != nil {
			return nil, fmt.Errorf("list audit: %w", err)
		}
	}
	order := desc(then(byInt(0), byText(1), byInt(2)))
	rows, err := r.s.queryAll(ctx, gather{table: auditTable, order: order, limit: limit}, auditPageShardSQL,
		f.ActorKind, f.ActorID, actions, targets, f.Decision, since, until, before.hlc, limit, before.origin, before.seq)
	if err != nil {
		return nil, fmt.Errorf("list audit: %w", err)
	}
	defer rows.Close()
	var out []AuditEntry
	for rows.Next() {
		var (
			e          AuditEntry
			c          auditCursor
			ts         int64
			detail, op string
		)
		if err := rows.Scan(&c.hlc, &c.origin, &c.seq, &ts, &e.ActorKind, &e.ActorID, &e.Action, &e.Target,
			&e.Decision, &e.Result, &detail, &op); err != nil {
			return nil, fmt.Errorf("list audit: %w", err)
		}
		e.ID, e.Cursor = c.hlc, c.String()
		e.TS = fromMillis(ts)
		e.Detail = json.RawMessage(detail)
		e.Verification = AuditLegacy
		if op != "" {
			e.Detail = withoutOpKeys(e.Detail)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ErrBadCursor refuses an audit cursor that is not one Query returned.
var ErrBadCursor = errors.New("bad audit cursor")

// auditCursor is an audit entry's global id: the position of the entry in a
// sharded cluster's log, which orders by it.
type auditCursor struct {
	hlc    int64
	origin string
	seq    int64
}

// String encodes c as "<hlc>.<seq>.<origin>"; the origin, a node id, goes
// last so it may hold anything.
func (c auditCursor) String() string {
	return strconv.FormatInt(c.hlc, 10) + "." + strconv.FormatInt(c.seq, 10) + "." + c.origin
}

// CheckAuditCursor checks that s is an AuditEntry.Cursor, to pass as
// AuditFilter.BeforeCursor: ErrBadCursor if not.
func CheckAuditCursor(s string) error {
	_, err := parseAuditCursor(s)
	return err
}

// parseAuditCursor decodes an AuditEntry.Cursor, to pass as
// AuditFilter.BeforeCursor.
func parseAuditCursor(s string) (auditCursor, error) {
	parts := strings.SplitN(s, ".", 3)
	if len(parts) != 3 || parts[2] == "" {
		return auditCursor{}, fmt.Errorf("%w %q", ErrBadCursor, s)
	}
	h, err1 := strconv.ParseInt(parts[0], 10, 64)
	seq, err2 := strconv.ParseInt(parts[1], 10, 64)
	if err1 != nil || err2 != nil || h <= 0 || seq < 0 {
		return auditCursor{}, fmt.Errorf("%w %q", ErrBadCursor, s)
	}
	return auditCursor{hlc: h, origin: parts[2], seq: seq}, nil
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
	// auditInsertSealedSQL is auditInsertVersionSQL with the seal (#387).
	auditInsertSealedSQL = `
		INSERT INTO audit_log (ts, actor_kind, actor_id, action, target, decision, result, _hlc, _origin, _seq,
		                       detail, audit_op, audit_outcome_of, audit_key,
		                       chain_origin, chain_seq, chain_prev, chain_kid, chain_mac)
		SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, detail,
		       CASE WHEN json_valid(detail) THEN json_extract(detail, '$.audit_op') END,
		       CASE WHEN json_valid(detail) THEN json_extract(detail, '$.audit_outcome_of') END,
		       nullif(k, ''), co, cs, cp, ck, cm
		FROM (SELECT ? AS detail, ? AS k, ? AS co, ? AS cs, ? AS cp, ? AS ck, ? AS cm)`
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
	if s := c.Seal; s != nil {
		m.Row["chain_origin"], m.Row["chain_seq"], m.Row["chain_prev"] = s.Origin, s.Seq, s.Prev
		m.Row["chain_kid"], m.Row["chain_mac"] = s.KID, s.MAC
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
	q, args := auditInsertVersionSQL, []any{
		r["ts"], r["actor_kind"], r["actor_id"], r["action"], r["target"], r["decision"], r["result"],
		int64(m.HLC), m.Origin, m.Seq, r["detail"], key, //nolint:gosec // an HLC fits in 63 bits
	}
	if _, sealed := r["chain_mac"]; sealed {
		// The seal columns, which a member below auditChainSchema does not
		// have: its merge drops them (knownColumns).
		q, args = auditInsertSealedSQL, append(args, r["chain_origin"], r["chain_seq"], r["chain_prev"], r["chain_kid"], r["chain_mac"])
	}
	res, err := tx.ExecContext(ctx, q, args...)
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
