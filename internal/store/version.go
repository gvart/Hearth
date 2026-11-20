// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/gvart/hearth/internal/hlc"
)

// Versioned rows (docs/design/ap-cluster.md §4).
//
// From VersionedSchema every replicated row carries the version of the write
// that made it, (_hlc, _origin), and a tombstone flag, _deleted. A command's
// apply no longer writes rows with SQL of its own: it reads the rows it
// needs, and hands the full new row to the writer, which turns it into a
// Mutation and merges it with the one function every write goes through,
// mergeRow: last-writer-wins on (_hlc, _origin), set-once columns
// (revocations) keeping the earliest time any version had, never cleared.
//
// The version of a command's mutations comes from the Stamp it carries: the
// HLC reading and member id of the hub that accepted the write, set by
// Store.apply before the command reaches the Applier, so a replicated log
// carries it and every member applies the same bytes. apply never reads a
// clock. A write supersedes the row it read: its version is the stamp, or
// the stored version plus one if that is not newer. Log order, not clock
// order, thus decides between two commands, as it did before versions, and a
// command whose apply succeeded is never undone by an older stamp. Only
// Store.Merge, the entry point for mutations made elsewhere, decides by
// version alone.
//
// A command without a stamp (one encoded before VersionedSchema, or applied
// with ApplyLocal directly) has the zero stamp: its version is the stored
// version plus one, with an empty origin. That is the same on every member
// applying the same log, since each holds the same rows at the same entry.
//
// Below VersionedSchema (a cluster member not migrated yet) the same code
// writes rows without versions: a plain upsert, and a delete removes the row.

// VersionedSchema is the schema version whose migration (00027) added the
// row versions.
const VersionedSchema = 27

// TombstoneTTL is how long a tombstone is kept: a member offline for longer
// must rejoin empty (docs/design/ap-cluster.md §4.3).
const TombstoneTTL = 7 * 24 * time.Hour

// Stamp is the version a command's writes carry: the HLC reading and member
// id of the hub that accepted the write. Every command embeds one.
type Stamp struct {
	HLC    hlc.Timestamp `json:"_hlc,omitempty"`
	Origin string        `json:"_origin,omitempty"`
}

func (s Stamp) stamp() Stamp { return s }

// stamper is implemented by every command but MigrateSchema, through its
// embedded Stamp.
type stamper interface{ stamp() Stamp }

// stampOf returns cmd's stamp, the zero one for a command without.
func stampOf(cmd Command) Stamp {
	if s, ok := cmd.(stamper); ok {
		return s.stamp()
	}
	return Stamp{}
}

// withStamp returns a copy of cmd carrying st; cmd as it is if it has no
// Stamp field.
func withStamp(cmd Command, st Stamp) Command {
	v := reflect.New(reflect.TypeOf(cmd)).Elem()
	v.Set(reflect.ValueOf(cmd))
	f := v.FieldByName("Stamp")
	if !f.IsValid() || f.Type() != reflect.TypeFor[Stamp]() {
		return cmd
	}
	f.Set(reflect.ValueOf(st))
	out, _ := v.Interface().(Command)
	return out
}

// Mutation is one row write: the full row of Table at version (HLC,
// Origin), or its tombstone when Deleted. Row holds every column of the row
// at the schema it was made at, its primary key included, by name, and not
// the version columns. Values are int64, float64, string, []byte or nil.
//
// An audit_log mutation is an append: Seq completes its global id (HLC,
// Origin, Seq), and Row holds the entry's columns (ts to detail, and
// audit_key) without the local id.
type Mutation struct {
	Table   string
	Row     map[string]any
	HLC     hlc.Timestamp
	Origin  string
	Deleted bool
	Seq     int64
}

// tableSpec describes how the rows of a replicated table merge.
type tableSpec struct {
	// pk are the primary key columns.
	pk []string
	// setOnce are the columns that, once set, are never cleared: the merged
	// row keeps the earliest value any version had (deny wins).
	setOnce []string
	// deletable tables have tombstones; their reads skip rows with
	// _deleted. A tombstone for any other table is refused.
	deletable bool
	// tombstone, if set, blanks the columns a tombstone must not keep
	// (secrets) or hold (values of a UNIQUE column, so a deleted row does
	// not keep a name taken).
	tombstone func(r row)
	// since is the schema version whose migration added the table, for a
	// table newer than VersionedSchema: below it the table does not exist.
	since int64
}

// existsAt reports whether the table is in a database at schema v.
func (t tableSpec) existsAt(v int64) bool { return v >= max(t.since, VersionedSchema) }

// auditTable is the append-only audit log, merged by mergeAudit.
const auditTable = "audit_log"

// tables are the replicated tables, but the audit log.
var tables = map[string]tableSpec{
	"devices":         {pk: []string{"id"}},
	"tokens":          {pk: []string{"hash"}, setOnce: []string{"used_at"}},
	"certs":           {pk: []string{"serial"}, setOnce: []string{"revoked_at", "pin_mismatch_at"}},
	"admin":           {pk: []string{"id"}},
	"sessions":        {pk: []string{"hash"}, deletable: true},
	"join_tokens":     {pk: []string{"hash"}, setOnce: []string{"used_at"}},
	"cluster_hubs":    {pk: []string{"node_id"}},
	"hub_certs":       {pk: []string{"serial"}, setOnce: []string{"revoked_at"}},
	"automation_runs": {pk: []string{"id"}, deletable: true},
	"kube_clusters": {pk: []string{"id"}, deletable: true, tombstone: func(r row) {
		r["kubeconfig"], r["name"] = []byte{}, deletedName(r["id"])
	}},
	"approvals":      {pk: []string{"id"}},
	"approval_links": {pk: []string{"hash"}, setOnce: []string{"used_at"}},
	"mcp_tokens":     {pk: []string{"name"}, setOnce: []string{"revoked_at"}},
	"network_hosts":  {pk: []string{"mac"}},
	"proxmox_servers": {pk: []string{"id"}, deletable: true, tombstone: func(r row) {
		r["connection"], r["name"] = []byte{}, deletedName(r["id"])
	}},
	"runbook_runs": {pk: []string{"id"}, deletable: true, tombstone: func(r row) {
		r["source"] = []byte{}
	}},
	"telemetry":        {pk: []string{"id"}},
	"panels":           {pk: []string{"id"}, deletable: true},
	"panel_links":      {pk: []string{"id"}, deletable: true, setOnce: []string{"revoked_at"}},
	"dashboard_tokens": {pk: []string{"id"}, setOnce: []string{"revoked_at"}},
	"ca_rotations":     {pk: []string{"new_ca_fp"}},
	"config_docs": {pk: []string{"id"}, deletable: true, since: configDocsSchema, tombstone: func(r row) {
		r["content"], r["digest"] = []byte{}, ""
	}},
}

// deletedName is the name a tombstone of a table with a UNIQUE name holds:
// its id behind a NUL, which no valid name contains, so it never takes the
// name of a live row.
func deletedName(id any) string { return fmt.Sprintf("\x00%v", id) }

// Version columns.
const (
	colHLC     = "_hlc"
	colOrigin  = "_origin"
	colDeleted = "_deleted"
	colSeq     = "_seq"
)

// row is one row of a replicated table, by column name, as SELECT * reads
// it: at VersionedSchema with its version columns.
type row map[string]any

// version returns the stored version of r: zero for a row read before
// VersionedSchema or not stored.
func (r row) version() (hlc.Timestamp, string) {
	h, _ := r[colHLC].(int64)
	o, _ := r[colOrigin].(string)
	return hlc.Timestamp(h), o //nolint:gosec // _hlc is never negative
}

func (r row) deleted() bool {
	d, _ := r[colDeleted].(int64)
	return d != 0
}

// data returns r without its version columns.
func (r row) data() map[string]any {
	out := make(map[string]any, len(r))
	for k, v := range r {
		if k != colHLC && k != colOrigin && k != colDeleted {
			out[k] = v
		}
	}
	return out
}

func (r row) str(col string) string {
	s, _ := r[col].(string)
	return s
}

func (r row) int(col string) int64 {
	n, _ := r[col].(int64)
	return n
}

// isNull reports whether col is NULL (or missing) in r.
func (r row) isNull(col string) bool { return r[col] == nil }

// scanner returns a Scan for the columns cols of r, so a row read through
// the writer is decoded by the same function as a query's.
func (r row) scanner(cols ...string) rowScan {
	return rowScan{r: r, cols: cols}
}

type rowScan struct {
	r    row
	cols []string
}

// Scan assigns the columns to dest like sql.Rows.Scan, for the destination
// types the store's scanners use.
func (s rowScan) Scan(dest ...any) error {
	if len(dest) != len(s.cols) {
		return fmt.Errorf("scan row: %d destinations for %d columns", len(dest), len(s.cols))
	}
	for i, d := range dest {
		if err := scanValue(s.r[s.cols[i]], d); err != nil {
			return fmt.Errorf("scan column %s: %w", s.cols[i], err)
		}
	}
	return nil
}

// scanValue assigns v, a value SQLite returned, to d like sql.Rows.Scan,
// for the destination types the store's scanners use.
func scanValue(v any, d any) error {
	var err error
	switch d := d.(type) {
	case *string:
		*d, err = asString(v)
	case *int64:
		n, ok := v.(int64)
		if !ok {
			err = fmt.Errorf("not an integer: %T", v)
		}
		*d = n
	case *int:
		n, ok := v.(int64)
		if !ok {
			err = fmt.Errorf("not an integer: %T", v)
		}
		*d = int(n)
	case *bool:
		n, ok := v.(int64)
		if !ok {
			err = fmt.Errorf("not an integer: %T", v)
		}
		*d = n != 0
	case *float64:
		switch v := v.(type) {
		case float64:
			*d = v
		case int64:
			*d = float64(v)
		default:
			err = fmt.Errorf("not a number: %T", v)
		}
	case *[]byte:
		switch v := v.(type) {
		case []byte:
			*d = slices.Clone(v)
		case string:
			*d = []byte(v)
		case nil:
			*d = nil
		default:
			err = fmt.Errorf("not a blob: %T", v)
		}
	case *any:
		*d = v
	case sql.Scanner:
		err = d.Scan(v)
	default:
		err = fmt.Errorf("unsupported destination %T", d)
	}
	return err
}

func asString(v any) (string, error) {
	switch v := v.(type) {
	case string:
		return v, nil
	case []byte:
		return string(v), nil
	default:
		return "", fmt.Errorf("not text: %T", v)
	}
}

// ErrExists refuses a command that creates a row whose key is taken.
var ErrExists = errors.New("already exists")

// writer is what a command's apply writes through: it reads rows in the
// command's transaction and merges the rows the command writes, stamped
// with the command's version.
type writer struct {
	s     *Store
	tx    *sql.Tx
	stamp Stamp
	// schema is the database's schema version; versioned is schema >=
	// VersionedSchema.
	schema    int64
	versioned bool
	// muts are the mutations merged so far, in order.
	muts []Mutation
	// dt collects the digest changes (nil without digests).
	dt *digestTx
}

// get returns the live row of table with primary key pk (in the order of
// the table's pk columns), or nil if there is none or it is a tombstone.
func (w *writer) get(ctx context.Context, table string, pk ...any) (row, error) {
	r, err := w.getAny(ctx, table, pk...)
	if err != nil || r == nil || r.deleted() {
		return nil, err
	}
	return r, nil
}

// getAny is get, tombstones included.
func (w *writer) getAny(ctx context.Context, table string, pk ...any) (row, error) {
	spec, ok := tables[table]
	if !ok {
		return nil, fmt.Errorf("unknown table %q", table)
	}
	st, err := w.s.stmtFor(ctx, w.tx, selectKey{table}, func() string {
		return `SELECT * FROM ` + table + ` WHERE ` + pkWhere(spec.pk)
	})
	if err != nil {
		return nil, err
	}
	rows, err := st.QueryContext(ctx, pk...)
	if err != nil {
		return nil, err
	}
	out, err := scanRows(rows)
	if err != nil || len(out) == 0 {
		return nil, err
	}
	return out[0], nil
}

// query returns the live rows of table matching where (a condition on its
// columns, with args), ordered by orderBy.
func (w *writer) query(ctx context.Context, table, where, orderBy string, args ...any) ([]row, error) {
	if w.versioned && tables[table].deletable {
		where = `(` + where + `) AND _deleted = 0`
	}
	// table and where are constants of the callers; values are bound.
	q := `SELECT * FROM ` + table + ` WHERE ` + where //nolint:gosec // see above
	if orderBy != "" {
		q += ` ORDER BY ` + orderBy
	}
	rows, err := w.tx.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	return scanRows(rows)
}

// scanRows reads every row of rows by column name, and closes it.
func scanRows(rows *sql.Rows) ([]row, error) {
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	var out []row
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}
		r := make(row, len(cols))
		for i, c := range cols {
			r[c] = vals[i]
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// insert writes r, a new row of table. It fails with ErrExists if a live
// row has its key; a tombstone is replaced.
func (w *writer) insert(ctx context.Context, table string, r row) error {
	spec, ok := tables[table]
	if !ok {
		return fmt.Errorf("unknown table %q", table)
	}
	old, err := w.getAny(ctx, table, pkOf(spec, r)...)
	if err != nil {
		return err
	}
	if old != nil && !old.deleted() {
		return fmt.Errorf("%s %v: %w", table, pkOf(spec, r), ErrExists)
	}
	return w.write(ctx, table, r, old, false)
}

// put writes r, a row of table: a new one, or the new version of the row
// get returned (r is that row, changed: its version columns say what it
// supersedes).
func (w *writer) put(ctx context.Context, table string, r row) error {
	if _, known := r[colHLC]; !known && w.versioned {
		old, err := w.getAny(ctx, table, pkOf(tables[table], r)...)
		if err != nil {
			return err
		}
		return w.write(ctx, table, r, old, false)
	}
	return w.write(ctx, table, r, r, false)
}

// delete writes a tombstone for r, a live row get or query returned.
func (w *writer) delete(ctx context.Context, table string, r row) error {
	return w.write(ctx, table, r, r, true)
}

// write merges r as the version of its row after old, the stored row (nil
// if none).
func (w *writer) write(ctx context.Context, table string, r, old row, deleted bool) error {
	spec, ok := tables[table]
	if !ok {
		return fmt.Errorf("unknown table %q", table)
	}
	data := row(r.data())
	if deleted {
		if !spec.deletable {
			return fmt.Errorf("delete from %s: the table has no tombstones", table)
		}
		if spec.tombstone != nil && w.versioned {
			spec.tombstone(data)
		}
	}
	var stored hlc.Timestamp
	if old != nil {
		stored, _ = old.version()
	}
	m := Mutation{
		Table: table, Row: data, Deleted: deleted,
		HLC: max(w.stamp.HLC, stored+1), Origin: w.stamp.Origin,
	}
	if err := w.dt.merge(ctx, w.tx, m, func() error {
		_, err := mergeRow(ctx, w.s, w.tx, m, w.versioned)
		return err
	}); err != nil {
		return err
	}
	if w.versioned {
		w.muts = append(w.muts, m)
	}
	return nil
}

// pkOf returns the primary key values of r.
func pkOf(spec tableSpec, r map[string]any) []any {
	out := make([]any, len(spec.pk))
	for i, c := range spec.pk {
		out[i] = r[c]
	}
	return out
}

func pkWhere(pk []string) string {
	conds := make([]string, len(pk))
	for i, c := range pk {
		conds[i] = c + ` = ?`
	}
	return strings.Join(conds, ` AND `)
}

// mergeRow merges m into its table: the one write path of every replicated
// row but the audit log's. Versioned, it is an upsert that takes m's columns
// only if m's version (HLC, Origin) is newer than the stored row's, and
// merges set-once columns either way, keeping the earliest non-NULL value.
// Below VersionedSchema it is a plain upsert, set-once columns kept, or a
// delete. It reports whether the stored row changed.
func mergeRow(ctx context.Context, s *Store, tx *sql.Tx, m Mutation, versioned bool) (bool, error) {
	spec, ok := tables[m.Table]
	if !ok {
		return false, fmt.Errorf("merge: unknown table %q", m.Table)
	}
	cols := slices.Sorted(maps.Keys(m.Row))
	for _, c := range spec.pk {
		if m.Row[c] == nil {
			return false, fmt.Errorf("merge %s: no primary key column %s", m.Table, c)
		}
	}
	if m.Deleted && !versioned {
		st, err := s.stmtFor(ctx, tx, deleteKey{m.Table}, func() string {
			return `DELETE FROM ` + m.Table + ` WHERE ` + pkWhere(spec.pk)
		})
		if err != nil {
			return false, err
		}
		res, err := st.ExecContext(ctx, pkOf(spec, m.Row)...)
		if err != nil {
			return false, err
		}
		n, err := res.RowsAffected()
		return n > 0, err
	}
	st, err := s.stmtFor(ctx, tx, upsertKey{table: m.Table, cols: strings.Join(cols, ","), versioned: versioned}, func() string {
		return upsertSQL(m.Table, spec, cols, versioned)
	})
	if err != nil {
		return false, err
	}
	args := make([]any, 0, len(cols)+3)
	for _, c := range cols {
		args = append(args, m.Row[c])
	}
	if versioned {
		deleted := int64(0)
		if m.Deleted {
			deleted = 1
		}
		args = append(args, int64(m.HLC), m.Origin, deleted) //nolint:gosec // an HLC fits in 63 bits
	}
	res, err := st.ExecContext(ctx, args...)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// upsertSQL builds the merge statement of table for a row with columns cols.
// Identifiers come from the tables spec and from column names SELECT *
// returned, never from input.
func upsertSQL(table string, spec tableSpec, cols []string, versioned bool) string {
	insertCols := slices.Clone(cols)
	if versioned {
		insertCols = append(insertCols, colHLC, colOrigin, colDeleted)
	}
	marks := strings.TrimSuffix(strings.Repeat("?, ", len(insertCols)), ", ")
	newer := `TRUE`
	if versioned {
		newer = `(excluded._hlc > ` + table + `._hlc OR (excluded._hlc = ` + table + `._hlc AND excluded._origin > ` + table + `._origin))`
	}
	var sets, improves []string
	for _, c := range cols {
		switch {
		case slices.Contains(spec.pk, c):
		case slices.Contains(spec.setOnce, c):
			old, in := table+`.`+c, `excluded.`+c
			sets = append(sets, c+` = CASE WHEN `+old+` IS NULL THEN `+in+` WHEN `+in+` IS NULL THEN `+old+
				` ELSE MIN(`+old+`, `+in+`) END`)
			improves = append(improves, `(`+in+` IS NOT NULL AND (`+old+` IS NULL OR `+in+` < `+old+`))`)
		case versioned:
			sets = append(sets, c+` = CASE WHEN `+newer+` THEN excluded.`+c+` ELSE `+table+`.`+c+` END`)
		default:
			sets = append(sets, c+` = excluded.`+c)
		}
	}
	where := ``
	if versioned {
		for _, c := range []string{colHLC, colOrigin, colDeleted} {
			sets = append(sets, c+` = CASE WHEN `+newer+` THEN excluded.`+c+` ELSE `+table+`.`+c+` END`)
		}
		where = ` WHERE ` + strings.Join(append([]string{newer}, improves...), ` OR `)
	}
	return `INSERT INTO ` + table + ` (` + strings.Join(insertCols, `, `) + `) VALUES (` + marks + `)` +
		` ON CONFLICT (` + strings.Join(spec.pk, `, `) + `) DO UPDATE SET ` + strings.Join(sets, `, `) + where
}

// Statement cache keys.
type (
	selectKey struct{ table string }
	deleteKey struct{ table string }
	upsertKey struct {
		table, cols string
		versioned   bool
	}
)

// stmtFor returns the statement cached under key, prepared the first time,
// bound to tx. database/sql keeps it prepared on each connection that ran
// it, so a write does not parse its statements again; SQLite prepares it
// again by itself after a schema change.
func (s *Store) stmtFor(ctx context.Context, tx *sql.Tx, key any, build func() string) (*sql.Stmt, error) {
	cached, ok := s.stmts.Load(key)
	if !ok {
		st, err := s.db.PrepareContext(ctx, build())
		if err != nil {
			return nil, err
		}
		if cached, ok = s.stmts.LoadOrStore(key, st); ok {
			_ = st.Close()
		} else {
			cached = st
		}
	}
	return tx.StmtContext(ctx, cached.(*sql.Stmt)), nil //nolint:forcetypeassert // the cache holds statements only
}

// liveOnly is the condition, ANDed into a read of a table with tombstones,
// that skips them: empty below VersionedSchema, which has none.
func liveOnly(versioned bool) string {
	if versioned {
		return ` AND _deleted = 0`
	}
	return ``
}

// deleteRow deletes the live row of table with key pk, or fails with
// ErrNotFound. Result: Count, 1.
func deleteRow(ctx context.Context, w *writer, table string, pk ...any) (Result, error) {
	r, err := w.get(ctx, table, pk...)
	if err != nil {
		return Result{}, err
	}
	if r == nil {
		return Result{}, ErrNotFound
	}
	return Result{Count: 1}, w.delete(ctx, table, r)
}

// revokeOne sets revoked_at to now on the one live, unrevoked row of table
// matching where, or fails with ErrNotFound. Result: Count, 1.
func revokeOne(ctx context.Context, w *writer, table, where string, now int64, args ...any) (Result, error) {
	n, err := revokeWhere(ctx, w, table, where, now, args...)
	if err != nil {
		return Result{}, err
	}
	if n == 0 {
		return Result{}, ErrNotFound
	}
	return Result{Count: n}, nil
}

// pruneRuns deletes the live rows of table matching where but the newest
// keep, newest by started_at, then by rowid: the order the rows were
// inserted in, the same on every member applying the same log. A negative
// keep keeps every row.
func pruneRuns(ctx context.Context, w *writer, table, where string, keep int, args ...any) error {
	if keep < 0 {
		return nil
	}
	rows, err := w.query(ctx, table, where, `started_at DESC, rowid DESC`, args...)
	if err != nil {
		return err
	}
	for i, r := range rows {
		if i < keep {
			continue
		}
		if err := w.delete(ctx, table, r); err != nil {
			return err
		}
	}
	return nil
}

// sortRows sorts rows by the text column col.
func sortRows(rows []row, col string) {
	slices.SortFunc(rows, func(a, b row) int { return strings.Compare(a.str(col), b.str(col)) })
}

// isVersioned reports whether the database behind q is at VersionedSchema.
func isVersioned(ctx context.Context, q querier) (bool, error) {
	return atSchema(ctx, q, VersionedSchema)
}
