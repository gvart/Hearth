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
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
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
	schemaVersion = 2
)

// resolutions are the rollup periods, finest first. Ten minutes keeps a day's
// chart to a few hundred rows, which a Pi reads in milliseconds.
var resolutions = []time.Duration{time.Minute, 10 * time.Minute, time.Hour}

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
	res       INTEGER NOT NULL, -- period in milliseconds: a minute or an hour
	name      TEXT NOT NULL,
	ts        INTEGER NOT NULL, -- unix milliseconds, start of the period
	sum       REAL NOT NULL,
	count     INTEGER NOT NULL,
	PRIMARY KEY (device_id, res, name, ts)
) WITHOUT ROWID;
CREATE INDEX rollups_ts ON rollups (ts);
`

// tenMinuteRollups derives the ten-minute rollups schema 2 adds from the
// one-minute ones a schema 1 database holds.
const tenMinuteRollups = `
INSERT OR IGNORE INTO rollups (device_id, res, name, ts, sum, count)
SELECT device_id, 600000, name, ts / 600000 * 600000, SUM(sum), SUM(count)
FROM rollups WHERE res = 60000
GROUP BY device_id, name, ts / 600000
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
	if v == 0 {
		if _, err := tx.ExecContext(ctx, schema); err != nil {
			return fmt.Errorf("create schema: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx, tenMinuteRollups); err != nil {
		return fmt.Errorf("add ten-minute rollups: %w", err)
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
	q := `SELECT name, ts, value, 1 FROM samples WHERE device_id = ?`
	args := []any{deviceID}
	if res := resolution(step, start.Before(s.now().Add(-RawRetention))); res > 0 {
		q = `SELECT name, ts, sum, count FROM rollups WHERE device_id = ? AND res = ?`
		args = append(args, res.Milliseconds())
		step = max(step, res)
	}
	q += ` AND ts >= ? AND ts <= ?`
	args = append(args, start.UnixMilli(), end.UnixMilli())
	// Always naming the metrics lets SQLite seek each series through the
	// primary key, rather than scan all of the device's data for the range.
	if len(names) == 0 {
		for _, k := range Known {
			names = append(names, k.Key)
		}
	}
	q += ` AND name IN (?` + strings.Repeat(`, ?`, len(names)-1) + `)` //nolint:gosec // only placeholders are added
	for _, n := range names {
		args = append(args, n)
	}
	// Rows come in primary key order, by name then time, so buckets are
	// summed as they stream; a GROUP BY would sort them all again.
	q += ` ORDER BY name, ts`
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("query metrics of %s: %w", deviceID, err)
	}
	defer func() { _ = rows.Close() }()

	stepMS := max(step.Milliseconds(), 1)
	out := map[string][]Point{}
	var (
		cur    string
		bucket int64
		sum    float64
		n      int64
	)
	flush := func() {
		if n > 0 {
			out[cur] = append(out[cur], Point{T: time.UnixMilli(bucket).UTC(), V: sum / float64(n)})
		}
		sum, n = 0, 0
	}
	for rows.Next() {
		var (
			name  string
			ts, c int64
			v     float64
		)
		if err := rows.Scan(&name, &ts, &v, &c); err != nil {
			return nil, fmt.Errorf("query metrics of %s: %w", deviceID, err)
		}
		if b := ts / stepMS * stepMS; n == 0 || name != cur || b != bucket {
			flush()
			cur, bucket = name, b
		}
		sum += v
		n += c
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("query metrics of %s: %w", deviceID, err)
	}
	flush()
	return out, nil
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
