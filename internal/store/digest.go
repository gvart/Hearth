// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"database/sql"
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"maps"
	"slices"
	"strings"
	"sync"

	"github.com/gvart/hearth/internal/hlc"
)

// Row digests for anti-entropy (docs/design/ap-cluster.md §5.2).
//
// A store opened WithDigest keeps, in memory, one 64-bit digest per bucket:
// the XOR of the hashes of the rows in it, tombstones included. A row's hash
// covers its table, key, version and set-once columns, so two replicas agree
// on a bucket's digest when they hold the same versions of its rows. The
// digests are built by one scan when the store opens and then kept up to
// date on every write, by XORing out a row's old hash and in its new one:
// an anti-entropy round reads no rows unless a bucket differs.
//
// Sharded rows fall in ShardBuckets buckets by the token of their partition
// key, the unit the hash ring places; global rows in GlobalBuckets buckets
// by the token of their table and key.

// Space is a digest space: the sharded rows or the global ones.
type Space int

// The digest spaces.
const (
	SpaceShard Space = iota
	SpaceGlobal
)

// Buckets is the number of buckets of sp.
func (sp Space) Buckets() int {
	if sp == SpaceGlobal {
		return GlobalBuckets
	}
	return ShardBuckets
}

// digest holds the bucket digests.
type digest struct {
	mu    sync.Mutex
	space [2][]uint64
}

func newDigest() *digest {
	return &digest{space: [2][]uint64{make([]uint64, ShardBuckets), make([]uint64, GlobalBuckets)}}
}

// rowState is what a row's hash covers besides its table and key.
type rowState struct {
	hlc     int64
	origin  string
	deleted int64
	setOnce string
}

// rowAt is one row's place and hash.
type rowAt struct {
	space  Space
	bucket int
	hash   uint64
}

// rowHash hashes a row of table with key pk (rendered by pkString) at st.
func rowHash(table, pk string, st rowState) uint64 {
	h := fnv.New64a()
	var b [8]byte
	_, _ = h.Write([]byte(table))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(pk))
	_, _ = h.Write([]byte{0})
	binary.BigEndian.PutUint64(b[:], uint64(st.hlc)) //nolint:gosec // a bit pattern
	_, _ = h.Write(b[:])
	_, _ = h.Write([]byte(st.origin))
	del := byte(0)
	if st.deleted != 0 {
		del = 1
	}
	_, _ = h.Write([]byte{0, del})
	_, _ = h.Write([]byte(st.setOnce))
	return h.Sum64()
}

// pkString renders primary key values as one string.
func pkString(vals []any) string {
	parts := make([]string, len(vals))
	for i, v := range vals {
		parts[i] = keyString(v)
	}
	return strings.Join(parts, "\x00")
}

// placeRow returns where the row of table with key pk and columns r lies
// in the digests.
func placeRow(table, pk string, r map[string]any) (Space, int, error) {
	p, err := PlacementOf(table, r)
	if err != nil {
		return 0, 0, err
	}
	if p.Global {
		return SpaceGlobal, int(Token(table+"\x00"+pk) >> 56), nil
	}
	return SpaceShard, BucketOf(Token(p.Key)), nil
}

// xor applies row hash changes.
func (d *digest) xor(changes []rowAt) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, c := range changes {
		d.space[c.space][c.bucket] ^= c.hash
	}
}

// BucketDigests returns the digests of buckets of sp, in their order. It is
// nil for a store opened without WithDigest.
func (s *Store) BucketDigests(sp Space, buckets []int) []uint64 {
	if s.digest == nil {
		return nil
	}
	s.digest.mu.Lock()
	defer s.digest.mu.Unlock()
	out := make([]uint64, len(buckets))
	for i, b := range buckets {
		out[i] = s.digest.space[sp][b]
	}
	return out
}

// WithDigest makes the store keep the bucket digests anti-entropy compares
// (see BucketDigests). It needs the versioned schema.
func WithDigest() Option {
	return func(c *openConfig) { c.digest = true }
}

// stateCols are the columns of a table's row state, in rowState order:
// the version columns, then the set-once columns.
func stateCols(table string) string {
	cols := []string{colHLC, colOrigin, colDeleted}
	if table == auditTable {
		return colHLC + `, ` + colOrigin + `, 0`
	}
	cols = append(cols, tables[table].setOnce...)
	return strings.Join(cols, `, `)
}

// scanState reads a row state from vals, laid out as stateCols.
func scanState(vals []any) rowState {
	var st rowState
	st.hlc, _ = vals[0].(int64)
	st.origin, _ = vals[1].(string)
	st.deleted, _ = vals[2].(int64)
	var once []string
	for _, v := range vals[3:] {
		if v == nil {
			once = append(once, "-")
		} else {
			once = append(once, keyString(v))
		}
	}
	st.setOnce = strings.Join(once, ",")
	return st
}

// placeCols are the columns placeRow needs of a row of table, besides its
// primary key.
func placeCols(table string) []string {
	switch {
	case table == auditTable:
		return []string{"detail", "audit_key", "ts", "actor_kind", "actor_id", "action", "target"}
	case globalTables[table]:
		return nil
	default:
		return []string{partitionCols[table]}
	}
}

// keyCols are the columns that identify a row of table.
func keyCols(table string) []string {
	if table == auditTable {
		return []string{colHLC, colOrigin, colSeq}
	}
	return tables[table].pk
}

// RowRef identifies one replicated row, the audit log's included, by the
// values of its key columns (for an audit entry its global id: _hlc,
// _origin, _seq).
type RowRef struct {
	Table string `json:"table"`
	Key   Values `json:"key"`
}

// RowDigest is a row's reference, version and hash.
type RowDigest struct {
	RowRef
	HLC    hlc.Timestamp `json:"hlc"`
	Origin string        `json:"origin"`
	Hash   uint64        `json:"hash"`
}

// Newer reports whether d's version is newer than o's.
func (d RowDigest) Newer(o RowDigest) bool {
	return d.HLC > o.HLC || (d.HLC == o.HLC && d.Origin > o.Origin)
}

// scanDigests runs fn for every row of table, tombstones included, with its
// key values, place and state. Each table is one scan of the columns the
// digest needs.
func scanDigests(ctx context.Context, q interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}, table string, fn func(key []any, sp Space, bucket int, st rowState) error,
) error {
	kc, pc := keyCols(table), placeCols(table)
	// Identifiers are constants of the tables spec.
	query := `SELECT ` + strings.Join(kc, `, `) + `, ` + stateCols(table)
	if len(pc) > 0 {
		query += `, ` + strings.Join(pc, `, `)
	}
	query += ` FROM ` + table
	rows, err := q.QueryContext(ctx, query)
	if err != nil {
		return fmt.Errorf("scan %s: %w", table, err)
	}
	defer rows.Close()
	nState := 3 + len(tables[table].setOnce)
	n := len(kc) + nState + len(pc)
	for rows.Next() {
		vals := make([]any, n)
		ptrs := make([]any, n)
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return fmt.Errorf("scan %s: %w", table, err)
		}
		key := vals[:len(kc)]
		st := scanState(vals[len(kc) : len(kc)+nState])
		r := map[string]any{}
		for i, c := range kc {
			r[c] = key[i]
		}
		for i, c := range pc {
			r[c] = vals[len(kc)+nState+i]
		}
		sp, b, err := placeRow(table, pkString(key), r)
		if err != nil {
			return err
		}
		if err := fn(key, sp, b, st); err != nil {
			return err
		}
	}
	return rows.Err()
}

// buildDigest computes every bucket digest from the rows: one scan of each
// table, when the store opens.
func (s *Store) buildDigest(ctx context.Context) error {
	d := newDigest()
	for _, table := range ReplicatedTables() {
		err := scanDigests(ctx, s.db, table, func(key []any, sp Space, b int, st rowState) error {
			d.space[sp][b] ^= rowHash(table, pkString(key), st)
			return nil
		})
		if err != nil {
			return fmt.Errorf("build digests: %w", err)
		}
	}
	s.digest = d
	return nil
}

// BucketRows returns the digest of every row of the buckets of sp that want
// accepts, tombstones included. It reads every table: anti-entropy calls it
// only for the buckets whose digests differ.
func (s *Store) BucketRows(ctx context.Context, sp Space, want func(bucket int) bool) ([]RowDigest, error) {
	var out []RowDigest
	for _, table := range ReplicatedTables() {
		if (sp == SpaceGlobal) != globalTables[table] {
			continue
		}
		err := scanDigests(ctx, s.db, table, func(key []any, rsp Space, b int, st rowState) error {
			if rsp != sp || !want(b) {
				return nil
			}
			out = append(out, RowDigest{
				RowRef: RowRef{Table: table, Key: slices.Clone(key)},
				HLC:    hlc.Timestamp(st.hlc), Origin: st.origin, //nolint:gosec // _hlc is never negative
				Hash: rowHash(table, pkString(key), st),
			})
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

// ReadRows returns the rows refs name as mutations, in dependency order
// (ReplicatedTables), tombstones included; a row this store does not hold
// is left out.
func (s *Store) ReadRows(ctx context.Context, refs []RowRef) ([]Mutation, error) {
	var out []Mutation
	for _, ref := range refs {
		m, ok, err := s.readRow(ctx, s.db, ref)
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, m)
		}
	}
	SortMutations(out)
	return out, nil
}

// SortMutations sorts muts in dependency order (parents first), keeping the
// order of each table's.
func SortMutations(muts []Mutation) {
	slices.SortStableFunc(muts, func(a, b Mutation) int { return TableRank(a.Table) - TableRank(b.Table) })
}

// readRow reads the row ref names as a mutation.
func (s *Store) readRow(ctx context.Context, q interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}, ref RowRef,
) (Mutation, bool, error) {
	kc := keyCols(ref.Table)
	if _, ok := tables[ref.Table]; !ok && ref.Table != auditTable {
		return Mutation{}, false, fmt.Errorf("read row: unknown table %q", ref.Table)
	}
	if len(ref.Key) != len(kc) {
		return Mutation{}, false, fmt.Errorf("read row of %s: %d key values for %d columns", ref.Table, len(ref.Key), len(kc))
	}
	// Identifiers are constants of the tables spec.
	rows, err := q.QueryContext(ctx, `SELECT * FROM `+ref.Table+` WHERE `+pkWhere(kc), ref.Key...)
	if err != nil {
		return Mutation{}, false, fmt.Errorf("read row of %s: %w", ref.Table, err)
	}
	rs, err := scanRows(rows)
	if err != nil || len(rs) == 0 {
		return Mutation{}, false, err
	}
	r := rs[0]
	h, origin := r.version()
	if ref.Table == auditTable {
		seq, _ := r[colSeq].(int64)
		m := Mutation{Table: auditTable, HLC: h, Origin: origin, Seq: seq, Row: map[string]any{}}
		for _, c := range []string{"ts", "actor_kind", "actor_id", "action", "target", "decision", "result", "detail", "audit_key"} {
			m.Row[c] = r[c]
		}
		return m, true, nil
	}
	return Mutation{Table: ref.Table, Row: r.data(), HLC: h, Origin: origin, Deleted: r.deleted()}, true, nil
}

// digestTx collects the digest changes of one transaction, applied once it
// commits.
type digestTx struct {
	s       *Store
	changes []rowAt
}

// newDigestTx returns a collector for a transaction of s; nil if s keeps no
// digests.
func (s *Store) newDigestTx() *digestTx {
	if s.digest == nil {
		return nil
	}
	return &digestTx{s: s}
}

// state reads the state of the row of table with key values key in tx;
// ok is false if there is none.
func (d *digestTx) state(ctx context.Context, tx *sql.Tx, table string, key []any) (rowState, bool, error) {
	n := 3 + len(tables[table].setOnce)
	// Identifiers are constants of the tables spec.
	row := tx.QueryRowContext(ctx, `SELECT `+stateCols(table)+` FROM `+table+` WHERE `+pkWhere(keyCols(table)), key...) //nolint:gosec // table and columns from the store's own list
	vals := make([]any, n)
	ptrs := make([]any, n)
	for i := range vals {
		ptrs[i] = &vals[i]
	}
	if err := row.Scan(ptrs...); err != nil {
		if err == sql.ErrNoRows {
			return rowState{}, false, nil
		}
		return rowState{}, false, err
	}
	return scanState(vals), true, nil
}

// merge runs write, which merges m into its table in tx, and records the
// change of the row's hash.
func (d *digestTx) merge(ctx context.Context, tx *sql.Tx, m Mutation, write func() error) error {
	if d == nil {
		return write()
	}
	var key []any
	if m.Table == auditTable {
		key = []any{int64(m.HLC), m.Origin, m.Seq} //nolint:gosec // an HLC fits in 63 bits
	} else {
		key = pkOf(tables[m.Table], m.Row)
	}
	pk := pkString(key)
	sp, b, err := placeRow(m.Table, pk, m.Row)
	if err != nil {
		return err
	}
	before, had, err := d.state(ctx, tx, m.Table, key)
	if err != nil {
		return err
	}
	if err := write(); err != nil {
		return err
	}
	after, has, err := d.state(ctx, tx, m.Table, key)
	if err != nil {
		return err
	}
	if had == has && before == after {
		return nil
	}
	if had {
		d.changes = append(d.changes, rowAt{space: sp, bucket: b, hash: rowHash(m.Table, pk, before)})
	}
	if has {
		d.changes = append(d.changes, rowAt{space: sp, bucket: b, hash: rowHash(m.Table, pk, after)})
	}
	return nil
}

// commit applies the collected changes; call it after the transaction
// committed.
func (d *digestTx) commit() {
	if d != nil && len(d.changes) > 0 {
		d.s.digest.xor(d.changes)
	}
}

// dropped records rows removed from table in a transaction (tombstones the
// GC drops): their hashes leave the digests.
func (d *digestTx) dropped(table string, key []any, st rowState, r map[string]any) error {
	if d == nil {
		return nil
	}
	pk := pkString(key)
	sp, b, err := placeRow(table, pk, r)
	if err != nil {
		return err
	}
	d.changes = append(d.changes, rowAt{space: sp, bucket: b, hash: rowHash(table, pk, st)})
	return nil
}

// gcTombstonesDigested is GCTombstones for a store keeping digests: the
// tombstones dropped leave the digests too.
func (s *Store) gcTombstonesDigested(ctx context.Context, cutoff int64) (n int, err error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("gc tombstones: %w", err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	dt := s.newDigestTx()
	for _, table := range sortedTables() {
		if !tables[table].deletable {
			continue
		}
		var gone [][]any
		err := scanDigests(ctx, tx, table, func(key []any, _ Space, _ int, st rowState) error {
			if st.deleted == 1 && st.hlc < cutoff {
				gone = append(gone, slices.Clone(key))
			}
			return nil
		})
		if err != nil {
			return n, fmt.Errorf("gc tombstones of %s: %w", table, err)
		}
		for _, key := range gone {
			m, ok, err := s.readRow(ctx, tx, RowRef{Table: table, Key: key})
			if err != nil || !ok {
				return n, fmt.Errorf("gc tombstones of %s: %w", table, err)
			}
			st, _, err := dt.state(ctx, tx, table, key)
			if err != nil {
				return n, fmt.Errorf("gc tombstones of %s: %w", table, err)
			}
			// Identifiers are constants of the tables spec.
			if _, err := tx.ExecContext(ctx, `DELETE FROM `+table+` WHERE `+pkWhere(keyCols(table)), key...); err != nil { //nolint:gosec // table and columns from the store's own list
				return n, fmt.Errorf("gc tombstones of %s: %w", table, err)
			}
			if err := dt.dropped(table, key, st, m.Row); err != nil {
				return n, err
			}
			n++
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("gc tombstones: %w", err)
	}
	dt.commit()
	return n, nil
}

// sortedTables are the names of the replicated tables but the audit log, sorted.
func sortedTables() []string { return slices.Sorted(maps.Keys(tables)) }

// sortDevices sorts devices by id.
func sortDevices(ds []Device) {
	slices.SortFunc(ds, func(a, b Device) int { return strings.Compare(a.ID, b.ID) })
}

// auditRef renders an audit entry's global id as a key string, for logs.
