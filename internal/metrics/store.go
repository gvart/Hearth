// SPDX-License-Identifier: AGPL-3.0-only

// Package metrics stores the host metrics agents send (CPU, memory, disk,
// network, temperature) in a SQLite database of the hub's own.
//
// The database is hub-local: it is not part of the replicated store and never
// goes through Raft. Only the cluster leader serves agents, so the leader
// records the samples; a hub keeps what it recorded while it led. Raw samples
// are kept for RawRetention, and rollups for RollupRetention: one-minute
// rollups, and ten-minute and hourly ones so that a day's or a week's chart
// reads a few hundred rows. All are written along with each sample.
package metrics

import (
	"cmp"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	_ "modernc.org/sqlite" // registers the pure-Go "sqlite" database/sql driver
)

const (
	// RawRetention is how long raw samples are kept.
	RawRetention = 24 * time.Hour
	// RollupRetention is how long rollups are kept.
	RollupRetention = 7 * 24 * time.Hour
	// pruneEvery is how often Run deletes expired data.
	pruneEvery = 10 * time.Minute
	// schemaVersion is the PRAGMA user_version of this schema.
	schemaVersion = 1
	// tenMinuteRollup is the rollup period that keeps a day's chart to a few
	// hundred rows, which a Pi reads in milliseconds.
	tenMinuteRollup = 10 * time.Minute
)

// resolutions are the rollup periods, finest first.
var resolutions = []time.Duration{time.Minute, tenMinuteRollup, time.Hour}

// Series is a metric agents send, and how a chart shows it.
type Series struct {
	Key  string // the MetricSample name
	Name string
	Unit string // percent, celsius or bytes_per_second
}

// Known are the metrics the hub records, in chart order. Samples of any other
// name are dropped, so an agent cannot grow the database with series of its
// choosing.
var Known = []Series{
	{"cpu", "CPU", "percent"},
	{"memory", "Memory", "percent"},
	{"disk", "Disk /", "percent"},
	{"temperature", "Temperature", "celsius"},
	{"net_rx", "Network in", "bytes_per_second"},
	{"net_tx", "Network out", "bytes_per_second"},
}

// IsKnown reports whether name is one of Known.
func IsKnown(name string) bool {
	for _, s := range Known {
		if s.Key == name {
			return true
		}
	}
	return false
}

// Sample is one value of a metric.
type Sample struct {
	Name  string
	Value float64
}

// Point is a value at a time.
type Point struct {
	T time.Time
	V float64
}

// ErrNoData means a metric has no recent sample.
var ErrNoData = errors.New("no recent sample")

const schema = `
CREATE TABLE samples (
	device_id TEXT NOT NULL,
	name      TEXT NOT NULL,
	ts        INTEGER NOT NULL, -- unix milliseconds
	value     REAL NOT NULL,
	PRIMARY KEY (device_id, name, ts)
) WITHOUT ROWID;
CREATE INDEX samples_ts ON samples (ts);
CREATE TABLE rollups (
	device_id TEXT NOT NULL,
	res       INTEGER NOT NULL, -- period in milliseconds: a minute, ten minutes or an hour
	name      TEXT NOT NULL,
	ts        INTEGER NOT NULL, -- unix milliseconds, start of the period
	sum       REAL NOT NULL,
	count     INTEGER NOT NULL,
	PRIMARY KEY (device_id, res, name, ts)
) WITHOUT ROWID;
CREATE INDEX rollups_ts ON rollups (ts);
`

// Store is the metrics database. It is safe for concurrent use.
type Store struct {
	db  *sql.DB
	now func() time.Time
	log *slog.Logger
}

// Open opens (creating if needed) the metrics database at path. now is the
// clock retention is measured against; nil means time.Now.
func Open(ctx context.Context, path string, now func() time.Time, log *slog.Logger) (*Store, error) {
	// Metrics are disposable: synchronous(NORMAL) spares an SD card an fsync
	// per batch, and incremental auto_vacuum lets Prune give space back.
	dsn := "file:" + path +
		"?_pragma=auto_vacuum(INCREMENTAL)" +
		"&_pragma=journal_mode(WAL)" +
		"&_pragma=synchronous(NORMAL)" +
		"&_pragma=busy_timeout(5000)" +
		"&_txlock=immediate"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open metrics %s: %w", path, err)
	}
	if now == nil {
		now = time.Now
	}
	s := &Store{db: db, now: now, log: log}
	if err := s.init(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("open metrics %s: %w", path, err)
	}
	return s, nil
}

func (s *Store) init(ctx context.Context) error {
	var v int
	if err := s.db.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&v); err != nil {
		return err
	}
	switch {
	case v == schemaVersion:
		return nil
	case v > schemaVersion:
		return fmt.Errorf("schema %d is newer than this binary supports (%d)", v, schemaVersion)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, schema); err != nil {
		return fmt.Errorf("create schema: %w", err)
	}
	if _, err := tx.ExecContext(ctx, fmt.Sprintf(`PRAGMA user_version = %d`, schemaVersion)); err != nil {
		return err
	}
	return tx.Commit()
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

// Write records samples of a device taken at at, and adds them to their
// rollups. A second sample of a metric at the same millisecond is dropped.
func (s *Store) Write(ctx context.Context, deviceID string, at time.Time, samples []Sample) error {
	if len(samples) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("write metrics of %s: %w", deviceID, err)
	}
	defer func() { _ = tx.Rollback() }()
	for _, smp := range samples {
		res, err := tx.ExecContext(ctx,
			`INSERT OR IGNORE INTO samples (device_id, name, ts, value) VALUES (?, ?, ?, ?)`,
			deviceID, smp.Name, at.UnixMilli(), smp.Value)
		if err != nil {
			return fmt.Errorf("write metrics of %s: %w", deviceID, err)
		}
		if n, _ := res.RowsAffected(); n == 0 {
			continue
		}
		for _, r := range resolutions {
			if _, err := tx.ExecContext(ctx,
				`INSERT INTO rollups (device_id, res, name, ts, sum, count) VALUES (?, ?, ?, ?, ?, 1)
				 ON CONFLICT (device_id, res, name, ts) DO UPDATE SET sum = sum + excluded.sum, count = count + 1`,
				deviceID, r.Milliseconds(), smp.Name, at.Truncate(r).UnixMilli(), smp.Value); err != nil {
				return fmt.Errorf("write metrics of %s: %w", deviceID, err)
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("write metrics of %s: %w", deviceID, err)
	}
	return nil
}

// Query returns the series of a device from start to end, averaged over
// buckets of step, by metric name. Names limits the metrics; empty means all.
// It reads the coarsest data no coarser than step: hourly or one-minute
// rollups, or raw samples when step is under a minute and start is within
// RawRetention. Buckets are never finer than the data read.
func (s *Store) Query(ctx context.Context, deviceID string, names []string, start, end time.Time, step time.Duration) (map[string][]Point, error) {
	// Always naming the metrics lets SQLite seek each series through the
	// primary key, rather than scan all of the device's data for the range.
	if len(names) == 0 {
		for _, k := range Known {
			names = append(names, k.Key)
		}
	}
	res := resolution(step, start.Before(s.now().Add(-RawRetention)))
	b := newBuckets(max(step, res))
	var err error
	switch res {
	case 0:
		q := `SELECT name, ts, value, 1 FROM samples WHERE device_id = ? AND ts >= ? AND ts <= ?` + nameFilter(names) + ` ORDER BY name, ts`
		args := append([]any{deviceID, start.UnixMilli(), end.UnixMilli()}, nameArgs(names)...)
		err = s.readRows(ctx, q, args, b.add)
	case tenMinuteRollup:
		err = s.readTenMinutes(ctx, deviceID, names, start.UnixMilli(), end.UnixMilli(), b.add)
	default:
		err = s.readRollups(ctx, deviceID, res, names, start.UnixMilli(), end.UnixMilli(), b.add)
	}
	if err != nil {
		return nil, fmt.Errorf("query metrics of %s: %w", deviceID, err)
	}
	return b.finish(), nil
}

// nameFilter is the SQL condition limiting rows to names.
func nameFilter(names []string) string {
	return ` AND name IN (?` + strings.Repeat(`, ?`, len(names)-1) + `)`
}

func nameArgs(names []string) []any {
	args := make([]any, 0, len(names))
	for _, n := range names {
		args = append(args, n)
	}
	return args
}

// readRows calls add for each row of q, which selects name, ts, sum and count.
func (s *Store) readRows(ctx context.Context, q string, args []any, add func(name string, ts int64, sum float64, count int64)) error {
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var (
			name  string
			ts, c int64
			v     float64
		)
		if err := rows.Scan(&name, &ts, &v, &c); err != nil {
			return err
		}
		add(name, ts, v, c)
	}
	return rows.Err()
}

// readRollups calls add for the rollups of period res from from to to
// (unix milliseconds), in primary key order: by name, then time.
func (s *Store) readRollups(ctx context.Context, deviceID string, res time.Duration, names []string, from, to int64, add func(name string, ts int64, sum float64, count int64)) error {
	q := `SELECT name, ts, sum, count FROM rollups WHERE device_id = ? AND res = ? AND ts >= ? AND ts <= ?` + nameFilter(names) + ` ORDER BY name, ts`
	args := append([]any{deviceID, res.Milliseconds(), from, to}, nameArgs(names)...)
	return s.readRows(ctx, q, args, add)
}

// seriesHour is one hour of one metric.
type seriesHour struct {
	name string
	hour int64 // unix milliseconds
}

// readTenMinutes calls add for start..end at ten-minute detail, in order of
// name and time. An hour's ten-minute rollups are used only when they hold every
// sample of its hourly rollup. They may not: a hub that upgraded mid-hour or
// ran an older binary for a while wrote hourly and one-minute rollups alone,
// so such an hour is read from its one-minute rollups instead. An hour with no
// data at all stays a gap.
func (s *Store) readTenMinutes(ctx context.Context, deviceID string, names []string, start, end int64, add func(name string, ts int64, sum float64, count int64)) error {
	hourMS := time.Hour.Milliseconds()
	first := start / hourMS * hourMS
	hourly, tens := map[seriesHour]int64{}, map[seriesHour]int64{}
	err := s.readRollups(ctx, deviceID, time.Hour, names, first, end, func(name string, ts int64, _ float64, c int64) {
		hourly[seriesHour{name, ts}] = c
	})
	if err != nil {
		return err
	}
	type row struct {
		seriesHour
		ts  int64
		sum float64
		n   int64
	}
	var rows []row
	err = s.readRollups(ctx, deviceID, tenMinuteRollup, names, first, end, func(name string, ts int64, sum float64, c int64) {
		k := seriesHour{name, ts / hourMS * hourMS}
		tens[k] += c
		rows = append(rows, row{k, ts, sum, c})
	})
	if err != nil {
		return err
	}
	// Pruning can take the hourly rollup of the oldest hour and leave part
	// of that hour's data, so an unaccounted first hour is checked too.
	incomplete := func(k seriesHour) bool {
		return tens[k] != hourly[k] || (hourly[k] == 0 && k.hour == first)
	}
	from, to := int64(-1), int64(-1)
	for _, name := range names {
		for h := first; h <= end; h += hourMS {
			if incomplete(seriesHour{name, h}) {
				if from < 0 {
					from = h
				}
				from, to = min(from, h), max(to, h+hourMS-1)
			}
		}
	}
	rows = slices.DeleteFunc(rows, func(r row) bool { return r.ts < start || incomplete(r.seriesHour) })
	if from >= 0 {
		err = s.readRollups(ctx, deviceID, time.Minute, names, max(from, start), min(to, end), func(name string, ts int64, sum float64, c int64) {
			if k := (seriesHour{name, ts / hourMS * hourMS}); incomplete(k) {
				rows = append(rows, row{k, ts, sum, c})
			}
		})
		if err != nil {
			return err
		}
	}
	slices.SortFunc(rows, func(a, b row) int {
		return cmp.Or(strings.Compare(a.name, b.name), cmp.Compare(a.ts, b.ts))
	})
	for _, r := range rows {
		add(r.name, r.ts, r.sum, r.n)
	}
	return nil
}

// buckets averages rows that arrive by name then time into points of a step,
// summing as they stream; a GROUP BY would sort them all again.
type buckets struct {
	stepMS int64
	out    map[string][]Point
	cur    string
	bucket int64
	sum    float64
	n      int64
}

func newBuckets(step time.Duration) *buckets {
	return &buckets{stepMS: max(step.Milliseconds(), 1), out: map[string][]Point{}}
}

func (b *buckets) add(name string, ts int64, sum float64, count int64) {
	if at := ts / b.stepMS * b.stepMS; b.n == 0 || name != b.cur || at != b.bucket {
		b.flush()
		b.cur, b.bucket = name, at
	}
	b.sum += sum
	b.n += count
}

func (b *buckets) flush() {
	if b.n > 0 {
		b.out[b.cur] = append(b.out[b.cur], Point{T: time.UnixMilli(b.bucket).UTC(), V: b.sum / float64(b.n)})
	}
	b.sum, b.n = 0, 0
}

// finish returns the points of all rows added.
func (b *buckets) finish() map[string][]Point {
	b.flush()
	return b.out
}

// resolution is the rollup period a query of step reads: the coarsest no
// coarser than step, or 0 for raw samples. A query that reaches past
// RawRetention (old) reads rollups at least.
func resolution(step time.Duration, old bool) time.Duration {
	var res time.Duration
	for _, r := range resolutions {
		if r <= step {
			res = r
		}
	}
	if res == 0 && old {
		res = resolutions[0]
	}
	return res
}

// Latest returns the newest sample of a device's metric, or ErrNoData if
// there is none younger than maxAge.
func (s *Store) Latest(ctx context.Context, deviceID, name string, maxAge time.Duration) (float64, error) {
	var (
		ts int64
		v  float64
	)
	err := s.db.QueryRowContext(ctx,
		`SELECT ts, value FROM samples WHERE device_id = ? AND name = ? ORDER BY ts DESC LIMIT 1`,
		deviceID, name).Scan(&ts, &v)
	if errors.Is(err, sql.ErrNoRows) || err == nil && time.UnixMilli(ts).Before(s.now().Add(-maxAge)) {
		return 0, fmt.Errorf("%s of %s: %w", name, deviceID, ErrNoData)
	}
	if err != nil {
		return 0, fmt.Errorf("%s of %s: %w", name, deviceID, err)
	}
	return v, nil
}

// Prune deletes raw samples older than RawRetention and rollups older than
// RollupRetention, then returns the freed pages to the file system.
func (s *Store) Prune(ctx context.Context) error {
	now := s.now()
	if _, err := s.db.ExecContext(ctx, `DELETE FROM samples WHERE ts < ?`, now.Add(-RawRetention).UnixMilli()); err != nil {
		return fmt.Errorf("prune samples: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM rollups WHERE ts < ?`, now.Add(-RollupRetention).UnixMilli()); err != nil {
		return fmt.Errorf("prune rollups: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, `PRAGMA incremental_vacuum`); err != nil {
		return fmt.Errorf("vacuum metrics: %w", err)
	}
	return nil
}

// Run prunes expired data at start and then every pruneEvery, until ctx is
// canceled. A failed prune is logged and retried at the next tick.
func (s *Store) Run(ctx context.Context) error {
	t := time.NewTicker(pruneEvery)
	defer t.Stop()
	for {
		if err := s.Prune(ctx); err != nil && ctx.Err() == nil {
			s.log.WarnContext(ctx, "prune metrics", "err", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}
