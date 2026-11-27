// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"database/sql"
	"fmt"
	"slices"
	"strings"
)

// Reads in a sharded cluster (docs/design/ap-cluster.md §5.2, §5.3).
//
// A member of a sharded (AP) cluster holds only the partitions the hash
// ring gives it. The repositories keep their API; under it, every read goes
// through one of three seams:
//
//   - a read of global tables, or of one partition this member holds, runs
//     on the local database, as on a standalone hub;
//   - a read of one partition this member does not hold runs on a live
//     replica of it (queryKey: R = 1); a point read a false not-found must
//     not come from asks every replica when the first has no row of it
//     (queryRowLive);
//   - a list not keyed by one partition fans out to live storage members
//     that together hold every partition, and the rows they return merge
//     here (queryAll): each row once, at its newest version, then sorted
//     and limited as the query was. A row seen at different versions on two
//     members is handed to Shards.Repair (read repair).
//
// A query that fans out selects, after its own columns, the key and version
// columns of its table (hidden), which the merge reads and drops.

// Shards is a sharded cluster as the store reads it.
type Shards interface {
	// Holds reports whether this member holds the rows of partition key.
	Holds(key string) bool
	// ReadKey runs the read-only query on a live replica of partition key
	// and returns its rows.
	ReadKey(ctx context.Context, key, query string, args Values) (Rows, error)
	// ReadReplicas runs the read-only query on every live replica of
	// partition key (stand-ins and members catching up included) and
	// returns the rows of each that answered. It fails with ErrUnavailable
	// when none did.
	ReadReplicas(ctx context.Context, key, query string, args Values) ([]Rows, error)
	// ReadAll runs the read-only query on live storage members that
	// together hold every partition, this one included, and returns the
	// rows of each. It fails with ErrUnavailable when no live member holds
	// some partition.
	ReadAll(ctx context.Context, query string, args Values) ([]Rows, error)
	// Repair is told of rows seen at different versions on different
	// members; it brings their replicas to the newest, in the background.
	Repair(refs []RowRef)
}

// MasterRowsGate is implemented by a Shards whose master may hold a stale
// copy of the master tables' rows (#384): until it compared them with
// another master since it started or was promoted, MasterRowsReady fails
// with ErrUnavailable, and the store reads none of them.
type MasterRowsGate interface {
	MasterRowsReady() error
}

// masterRowsReady is nil when this member may read its copy of the master
// tables' rows (MasterRowsGate).
func (s *Store) masterRowsReady() error {
	if g, ok := s.shards.(MasterRowsGate); ok {
		return g.MasterRowsReady()
	}
	return nil
}

// Rows are the rows a read returned on one member.
type Rows struct {
	Member string   `json:"member"`
	Vals   []Values `json:"vals"`
}

// WithShards makes the store read the partitions it does not hold from
// the cluster (see Shards). It implies WithDigest.
func WithShards(sh Shards) Option {
	return func(c *openConfig) { c.shards, c.digest = sh, true }
}

// Sharded reports whether the store is a member of a sharded cluster.
func (s *Store) Sharded() bool { return s.shards != nil }

// openSharded prepares a store opened WithDigest or WithShards: the bucket
// digests, and a read-only pool for the reads other members send.
func (s *Store) openSharded(ctx context.Context, cfg openConfig) error {
	if ok, err := isVersioned(ctx, s.db); err != nil {
		return err
	} else if !ok {
		return fmt.Errorf("%w: a sharded store needs schema %d", ErrSchemaTooOld, VersionedSchema)
	}
	ro, err := sql.Open("sqlite", "file:"+s.path+"?_pragma=busy_timeout(5000)&_pragma=query_only(1)")
	if err != nil {
		return err
	}
	s.ro = ro
	s.shards = cfg.shards
	if cfg.digest {
		return s.buildDigest(ctx)
	}
	return nil
}

// ReadLocal runs a read another member sent (Shards.ReadKey, ReadAll) on
// this member's database, on a connection that refuses any write.
func (s *Store) ReadLocal(ctx context.Context, query string, args Values) (Rows, error) {
	if s.ro == nil {
		return Rows{}, fmt.Errorf("read: %w", ErrNoRoute)
	}
	rows, err := s.ro.QueryContext(ctx, query, args...)
	if err != nil {
		return Rows{}, fmt.Errorf("read: %w", err)
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		return Rows{}, fmt.Errorf("read: %w", err)
	}
	out := Rows{Member: s.origin}
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return Rows{}, fmt.Errorf("read: %w", err)
		}
		out.Vals = append(out.Vals, vals)
	}
	if err := rows.Err(); err != nil {
		return Rows{}, fmt.Errorf("read: %w", err)
	}
	return out, nil
}

// rowIter is what *sql.Rows and memRows have in common.
type rowIter interface {
	Next() bool
	Scan(dest ...any) error
	Err() error
	Close() error
}

// rowScanner is what *sql.Row and memRow have in common.
type rowScanner interface {
	Scan(dest ...any) error
}

// memRows iterates rows read on other members.
type memRows struct {
	rows [][]any
	i    int
}

func (m *memRows) Next() bool {
	if m.i < len(m.rows) {
		m.i++
		return true
	}
	return false
}

func (m *memRows) Scan(dest ...any) error {
	if m.i == 0 || m.i > len(m.rows) {
		return sql.ErrNoRows
	}
	return scanVals(m.rows[m.i-1], dest)
}

func (m *memRows) Err() error   { return nil }
func (m *memRows) Close() error { return nil }

// memRow is the first of rows read on another member, like *sql.Row.
type memRow struct {
	rows [][]any
	err  error
}

func (m memRow) Scan(dest ...any) error {
	if m.err != nil {
		return m.err
	}
	if len(m.rows) == 0 {
		return sql.ErrNoRows
	}
	return scanVals(m.rows[0], dest)
}

func scanVals(vals []any, dest []any) error {
	if len(dest) != len(vals) {
		return fmt.Errorf("scan: %d destinations for %d columns", len(dest), len(vals))
	}
	for i, d := range dest {
		if err := scanValue(vals[i], d); err != nil {
			return fmt.Errorf("scan column %d: %w", i, err)
		}
	}
	return nil
}

// wireArgs converts query arguments for the wire.
func wireArgs(args []any) (Values, error) {
	out := make(Values, len(args))
	for i, a := range args {
		v, err := WireArg(a)
		if err != nil {
			return nil, err
		}
		out[i] = v
	}
	return out, nil
}

// holds reports whether this member reads partition key locally.
func (s *Store) holds(key string) bool { return s.shards == nil || s.shards.Holds(key) }

// queryKey runs query, whose rows all have partition key key, here if this
// member holds it, else on a replica of it.
func (s *Store) queryKey(ctx context.Context, key, query string, args ...any) (rowIter, error) {
	if s.holds(key) {
		return s.db.QueryContext(ctx, query, args...)
	}
	wargs, err := wireArgs(args)
	if err != nil {
		return nil, err
	}
	rs, err := s.shards.ReadKey(ctx, key, query, wargs)
	if err != nil {
		return nil, err
	}
	return &memRows{rows: valuesRows(rs.Vals)}, nil
}

// queryRowNewest reads the row of table that query (selecting
// s.hidden(table) after its own columns, tombstones included) finds in
// partition key, at its newest version. The replica asked first (this
// member, if it holds key) answers, unless it has no row of it at all, live
// or deleted: a replica that missed the row's write (hinted to it while it
// was, or seemed, down) has none, so every live replica is asked then, and
// the newest version among them wins: a deleted row's tombstone counts, so
// a replica that missed the delete does not bring the row back. ok is false
// if no replica has a row. Only for a store with shards.
func (s *Store) queryRowNewest(ctx context.Context, table, key, query string, args ...any) (vals []any, ok bool, err error) {
	wargs, err := wireArgs(args)
	if err != nil {
		return nil, false, err
	}
	var first Rows
	if s.holds(key) {
		first, err = s.ReadLocal(ctx, query, wargs)
	} else {
		first, err = s.shards.ReadKey(ctx, key, query, wargs)
	}
	if err != nil {
		return nil, false, err
	}
	parts := []Rows{first}
	if len(first.Vals) == 0 {
		if parts, err = s.shards.ReadReplicas(ctx, key, query, wargs); err != nil {
			return nil, false, err
		}
	}
	rows, repair := mergeRows(gather{table: table}, parts)
	if len(repair) > 0 {
		s.shards.Repair(repair)
	}
	if len(rows) == 0 {
		return nil, false, nil
	}
	return rows[0], true, nil
}

// queryRowLive reads one row of table, sel + rest (sel the SELECT list,
// rest from FROM on, ending in its WHERE clause), in partition key, like QueryRowContext, for a
// read a false not-found must not come from: in a sharded cluster through
// queryRowNewest, so a replica that missed the row's write does not answer
// "no row" for it, and the newest version among the replicas, a tombstone
// included, decides. The row scans as sql.ErrNoRows unless that version is
// live. On a store that holds every row, and for a global table, which every
// member holds, it is the plain read, live rows of a deletable table only.
func (s *Store) queryRowLive(ctx context.Context, table, key, sel, rest string, args ...any) rowScanner {
	if masterTables[table] {
		if err := s.masterRowsReady(); err != nil {
			return memRow{err: err}
		}
	}
	if s.shards == nil || globalTables[table] {
		if tables[table].deletable {
			versioned, err := isVersioned(ctx, s.db)
			if err != nil {
				return memRow{err: err}
			}
			rest += liveOnly(versioned)
		}
		return s.db.QueryRowContext(ctx, sel+rest, args...)
	}
	vals, ok, err := s.queryRowNewest(ctx, table, key, sel+`, _deleted`+s.hidden(table)+rest, args...)
	switch {
	case err != nil:
		return memRow{err: err}
	case !ok || len(vals) == 0 || vals[len(vals)-1] != int64(0):
		return memRow{}
	}
	return memRow{rows: [][]any{vals[:len(vals)-1]}}
}

func valuesRows(vs []Values) [][]any {
	out := make([][]any, len(vs))
	for i, v := range vs {
		out[i] = v
	}
	return out
}

// hidden returns the columns a query that fans out (queryAll) over table
// selects after its own: the table's key columns, then its version. On a
// store that holds every row it is empty and the query runs as written.
func (s *Store) hidden(table string) string {
	if s.shards == nil {
		return ""
	}
	return `, ` + strings.Join(keyCols(table), `, `) + `, _hlc, _origin`
}

// gather says how the rows of a query that fans out merge.
type gather struct {
	// table is the table whose rows the query returns, one per row.
	table string
	// order sorts the merged rows (their own columns) as the query's ORDER
	// BY did; nil leaves them in no particular order.
	order func(a, b []any) int
	// limit keeps the first rows of the merge; zero keeps all.
	limit int
}

// queryAll runs query, which selects s.hidden(g.table) after its own
// columns, here on a store that holds every row; in a sharded cluster on
// members that together hold every partition, merging their rows by g.
func (s *Store) queryAll(ctx context.Context, g gather, query string, args ...any) (rowIter, error) {
	if s.shards == nil {
		return s.db.QueryContext(ctx, query, args...)
	}
	wargs, err := wireArgs(args)
	if err != nil {
		return nil, err
	}
	parts, err := s.shards.ReadAll(ctx, query, wargs)
	if err != nil {
		return nil, err
	}
	rows, repair := mergeRows(g, parts)
	if len(repair) > 0 {
		s.shards.Repair(repair)
	}
	return &memRows{rows: rows}, nil
}

// list runs `sel + rest`, a query of g.table's rows (sel the SELECT list,
// rest from FROM on): with key set, all of partition key, as queryKey;
// without, as queryAll, merged by g. A global table, which this member
// holds whole, is read here: a master table's rows are never read on
// another member (#384).
func (s *Store) list(ctx context.Context, key string, g gather, sel, rest string, args ...any) (rowIter, error) {
	if masterTables[g.table] {
		if err := s.masterRowsReady(); err != nil {
			return nil, err
		}
	}
	if globalTables[g.table] {
		return s.db.QueryContext(ctx, sel+rest, args...)
	}
	if key != "" {
		return s.queryKey(ctx, key, sel+rest, args...)
	}
	return s.queryAll(ctx, g, sel+s.hidden(g.table)+rest, args...)
}

// mergeRows merges the rows members returned for a query that fans out:
// each row once, at its newest version (last-writer-wins, as the store
// merges), sorted and limited by g. It also returns the rows seen at more
// than one version.
func mergeRows(g gather, parts []Rows) ([][]any, []RowRef) {
	type seen struct {
		vals   []any
		hlc    int64
		origin string
	}
	nk := len(keyCols(g.table))
	byKey := map[string]*seen{}
	var keys []string
	var repair []RowRef
	differs := map[string]bool{}
	for _, p := range parts {
		for _, vals := range p.Vals {
			n := len(vals) - nk - 2
			if n < 0 {
				continue
			}
			key := vals[n : n+nk]
			h, _ := vals[n+nk].(int64)
			o, _ := vals[n+nk+1].(string)
			k := pkString(key)
			b, ok := byKey[k]
			if !ok {
				byKey[k] = &seen{vals: vals[:n], hlc: h, origin: o}
				keys = append(keys, k)
				continue
			}
			if (b.hlc != h || b.origin != o) && !differs[k] {
				differs[k] = true
				repair = append(repair, RowRef{Table: g.table, Key: slices.Clone(key)})
			}
			if h > b.hlc || (h == b.hlc && o > b.origin) {
				*b = seen{vals: vals[:n], hlc: h, origin: o}
			}
		}
	}
	out := make([][]any, 0, len(keys))
	for _, k := range keys {
		out = append(out, byKey[k].vals)
	}
	if g.order != nil {
		slices.SortStableFunc(out, g.order)
	}
	if g.limit > 0 && len(out) > g.limit {
		out = out[:g.limit]
	}
	return out, repair
}

// shardedOnly returns v in a sharded cluster, "" elsewhere: for command
// fields only a sharded cluster routes by.
func (s *Store) shardedOnly(v string) string {
	if s.shards == nil {
		return ""
	}
	return v
}

// Ordering helpers for gather.order, over the merged rows' own columns.

// byText orders by the text column i, ascending.
func byText(i int) func(a, b []any) int {
	return func(a, b []any) int { return strings.Compare(textOf(a[i]), textOf(b[i])) }
}

// then orders by fs in turn.
func then(fs ...func(a, b []any) int) func(a, b []any) int {
	return func(a, b []any) int {
		for _, f := range fs {
			if c := f(a, b); c != 0 {
				return c
			}
		}
		return 0
	}
}

// byInt orders by the integer column i, ascending.
func byInt(i int) func(a, b []any) int {
	return func(a, b []any) int {
		x, _ := a[i].(int64)
		y, _ := b[i].(int64)
		switch {
		case x < y:
			return -1
		case x > y:
			return 1
		}
		return 0
	}
}

// desc reverses f.
func desc(f func(a, b []any) int) func(a, b []any) int {
	return func(a, b []any) int { return -f(a, b) }
}

func textOf(v any) string {
	s, _ := asString(v)
	return s
}
