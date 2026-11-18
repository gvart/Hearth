// SPDX-License-Identifier: AGPL-3.0-only

package metrics

import (
	"errors"
	"log/slog"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

// fakeClock is a settable clock.
type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time { return c.t }

var t0 = time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)

func openTest(t testing.TB, clock *fakeClock) *Store {
	t.Helper()
	s, err := Open(t.Context(), filepath.Join(t.TempDir(), "metrics.db"), clock.now, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func write(t *testing.T, s *Store, device string, at time.Time, name string, v float64) {
	t.Helper()
	if err := s.Write(t.Context(), device, at, []Sample{{Name: name, Value: v}}); err != nil {
		t.Fatal(err)
	}
}

func count(t *testing.T, s *Store, table string) int {
	t.Helper()
	var n int
	if err := s.db.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM `+table).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestRollups(t *testing.T) {
	clock := &fakeClock{t0}
	s := openTest(t, clock)
	// Four samples a minute at 15 s, for two minutes: 10, 20, 30, 40 and
	// 100, 100, 100, 100. Another device and metric must not mix in.
	for i, v := range []float64{10, 20, 30, 40, 100, 100, 100, 100} {
		at := t0.Add(time.Duration(i) * 15 * time.Second)
		write(t, s, "pi", at, "cpu", v)
		write(t, s, "pi", at, "memory", 50)
		write(t, s, "nas", at, "cpu", 99)
	}
	// A duplicate (same device, metric and millisecond) is dropped.
	write(t, s, "pi", t0, "cpu", 1000)

	var sum float64
	var n int
	if err := s.db.QueryRowContext(t.Context(),
		`SELECT sum, count FROM rollups WHERE device_id = 'pi' AND res = 60000 AND name = 'cpu' AND ts = ?`, t0.UnixMilli()).Scan(&sum, &n); err != nil {
		t.Fatal(err)
	}
	if sum != 100 || n != 4 {
		t.Errorf("first minute rollup = sum %v count %d, want 100 and 4", sum, n)
	}

	// Older than RawRetention: read from the rollups, one point a minute.
	clock.t = t0.Add(RawRetention + time.Hour)
	got, err := s.Query(t.Context(), "pi", []string{"cpu"}, t0.Add(-time.Minute), t0.Add(5*time.Minute), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	want := []Point{{t0, 25}, {t0.Add(time.Minute), 100}}
	if len(got) != 1 || !equal(got["cpu"], want) {
		t.Errorf("rollup query = %v, want cpu %v", got, want)
	}

	// A step of an hour or more reads the hourly rollups: one point for
	// the eight samples.
	got, err = s.Query(t.Context(), "pi", []string{"cpu"}, t0.Add(-time.Hour), t0.Add(time.Hour), 2*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	want = []Point{{t0.Truncate(2 * time.Hour), 62.5}}
	if !equal(got["cpu"], want) {
		t.Errorf("hourly query = %v, want cpu %v", got, want)
	}

	// Recent: read from raw samples, in buckets of the step.
	clock.t = t0.Add(time.Hour)
	got, err = s.Query(t.Context(), "pi", nil, t0, t0.Add(5*time.Minute), 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	want = []Point{{t0, 15}, {t0.Add(30 * time.Second), 35}, {t0.Add(time.Minute), 100}, {t0.Add(90 * time.Second), 100}}
	if !equal(got["cpu"], want) {
		t.Errorf("raw query cpu = %v, want %v", got["cpu"], want)
	}
	if len(got) != 2 || len(got["memory"]) != 4 {
		t.Errorf("raw query = %v, want cpu and memory", got)
	}
}

func equal(a, b []Point) bool {
	return slices.EqualFunc(a, b, func(p, q Point) bool { return p.T.Equal(q.T) && p.V == q.V })
}

func TestPrune(t *testing.T) {
	clock := &fakeClock{t0}
	s := openTest(t, clock)
	tests := []struct {
		age        time.Duration
		wantRaw    bool
		wantRollup bool
	}{
		{time.Minute, true, true},
		{RawRetention - time.Minute, true, true},
		{RawRetention + time.Minute, false, true},
		{RollupRetention - 2*time.Minute, false, true},
		{RollupRetention + 2*time.Minute, false, false},
	}
	for i, tt := range tests {
		write(t, s, "pi", t0.Add(-tt.age), "cpu", float64(i))
	}
	if err := s.Prune(t.Context()); err != nil {
		t.Fatal(err)
	}
	for i, tt := range tests {
		at := t0.Add(-tt.age)
		var raw, rollup int
		if err := s.db.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM samples WHERE ts = ?`, at.UnixMilli()).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		if err := s.db.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM rollups WHERE res = 60000 AND ts = ?`,
			at.Truncate(time.Minute).UnixMilli()).Scan(&rollup); err != nil {
			t.Fatal(err)
		}
		if (raw == 1) != tt.wantRaw || (rollup == 1) != tt.wantRollup {
			t.Errorf("sample %d (age %v): raw kept %v, rollup kept %v; want %v, %v", i, tt.age, raw == 1, rollup == 1, tt.wantRaw, tt.wantRollup)
		}
	}

	// A week later everything is gone.
	clock.t = t0.Add(RollupRetention + time.Hour)
	if err := s.Prune(t.Context()); err != nil {
		t.Fatal(err)
	}
	if r, u := count(t, s, "samples"), count(t, s, "rollups"); r != 0 || u != 0 {
		t.Errorf("after a week: %d samples, %d rollups, want none", r, u)
	}
}

func TestLatest(t *testing.T) {
	clock := &fakeClock{t0}
	s := openTest(t, clock)
	if _, err := s.Latest(t.Context(), "pi", "cpu", time.Minute); !errors.Is(err, ErrNoData) {
		t.Errorf("no samples: err = %v, want ErrNoData", err)
	}
	write(t, s, "pi", t0.Add(-30*time.Second), "cpu", 10)
	write(t, s, "pi", t0.Add(-15*time.Second), "cpu", 42)
	if v, err := s.Latest(t.Context(), "pi", "cpu", time.Minute); err != nil || v != 42 {
		t.Errorf("Latest = %v, %v; want 42", v, err)
	}
	clock.t = t0.Add(2 * time.Minute)
	if _, err := s.Latest(t.Context(), "pi", "cpu", time.Minute); !errors.Is(err, ErrNoData) {
		t.Errorf("stale sample: err = %v, want ErrNoData", err)
	}
}

func TestReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "metrics.db")
	clock := &fakeClock{t0}
	for range 2 {
		s, err := Open(t.Context(), path, clock.now, slog.New(slog.DiscardHandler))
		if err != nil {
			t.Fatal(err)
		}
		write(t, s, "pi", clock.t, "cpu", 1)
		clock.t = clock.t.Add(time.Second)
		_ = s.Close()
	}
}

// TestSchemaVersionUnchanged guards rollbacks: an older binary refuses a
// database with a newer user_version.
func TestSchemaVersionUnchanged(t *testing.T) {
	s := openTest(t, &fakeClock{t0})
	write(t, s, "pi", t0, "cpu", 1)
	var v int
	if err := s.db.QueryRowContext(t.Context(), `PRAGMA user_version`).Scan(&v); err != nil {
		t.Fatal(err)
	}
	if v != 1 {
		t.Errorf("user_version = %d, want 1", v)
	}
}

// writeMinutes writes one cpu sample a minute for n minutes from the given
// minute after t0. With older set, it leaves the database as a binary without
// ten-minute rollups would: only the one-minute and hourly rollups grow.
func writeMinutes(t *testing.T, s *Store, from, n int, v float64, older bool) {
	t.Helper()
	for i := from; i < from+n; i++ {
		at := t0.Add(time.Duration(i) * time.Minute)
		write(t, s, "pi", at, "cpu", v)
		if !older {
			continue
		}
		bucket := at.Truncate(tenMinuteRollup).UnixMilli()
		for _, q := range []string{
			`UPDATE rollups SET sum = sum - ?1, count = count - 1 WHERE res = 600000 AND ts = ?2`,
			`DELETE FROM rollups WHERE res = 600000 AND ts = ?2 AND count = 0 AND ?1 = ?1`,
		} {
			if _, err := s.db.ExecContext(t.Context(), q, v, bucket); err != nil {
				t.Fatal(err)
			}
		}
	}
}

// markTenMinutes doubles the ten-minute rollups, so a point read from them
// can be told from one read from the one-minute rollups.
func markTenMinutes(t *testing.T, s *Store) {
	t.Helper()
	if _, err := s.db.ExecContext(t.Context(), `UPDATE rollups SET sum = sum * 2 WHERE res = 600000`); err != nil {
		t.Fatal(err)
	}
}

// points is n ten-minute points of v, from the given minute after t0.
func points(from, n int, v float64) []Point {
	out := make([]Point, 0, n)
	for i := range n {
		out = append(out, Point{t0.Add(time.Duration(from+i*10) * time.Minute), v})
	}
	return out
}

func TestQueryTenMinutes(t *testing.T) {
	tests := []struct {
		name  string
		write func(t *testing.T, s *Store)
		want  []Point
	}{
		{
			name:  "complete hour reads ten-minute rollups",
			write: func(t *testing.T, s *Store) { writeMinutes(t, s, 0, 60, 10, false) },
			want:  points(0, 6, 20),
		},
		{
			name: "upgrade inside a bucket falls back for that hour",
			write: func(t *testing.T, s *Store) {
				writeMinutes(t, s, 0, 3, 100, true)
				writeMinutes(t, s, 3, 57, 10, false)
			},
			want: append([]Point{{t0, 37}}, points(10, 5, 10)...),
		},
		{
			name: "upgrade, rollback and upgrade leave no hole",
			write: func(t *testing.T, s *Store) {
				writeMinutes(t, s, 0, 60, 10, false)
				writeMinutes(t, s, 60, 60, 50, true)
				writeMinutes(t, s, 120, 60, 10, false)
			},
			want: slices.Concat(points(0, 6, 20), points(60, 6, 50), points(120, 6, 20)),
		},
		{
			name: "rollback for part of an hour",
			write: func(t *testing.T, s *Store) {
				writeMinutes(t, s, 0, 30, 10, false)
				writeMinutes(t, s, 30, 30, 50, true)
			},
			want: slices.Concat(points(0, 3, 10), points(30, 3, 50)),
		},
		{
			name: "older binary only",
			write: func(t *testing.T, s *Store) {
				writeMinutes(t, s, 0, 60, 50, true)
			},
			want: points(0, 6, 50),
		},
		{
			name: "offline hour stays a gap",
			write: func(t *testing.T, s *Store) {
				writeMinutes(t, s, 0, 60, 10, false)
				writeMinutes(t, s, 120, 60, 10, false)
			},
			want: slices.Concat(points(0, 6, 20), points(120, 6, 20)),
		},
		{
			name: "offline inside an hour stays a gap",
			write: func(t *testing.T, s *Store) {
				writeMinutes(t, s, 0, 20, 10, false)
				writeMinutes(t, s, 40, 20, 10, false)
			},
			want: slices.Concat(points(0, 2, 20), points(40, 2, 20)),
		},
		{
			name: "offline after a rollback stays a gap",
			write: func(t *testing.T, s *Store) {
				writeMinutes(t, s, 0, 20, 50, true)
				writeMinutes(t, s, 40, 20, 10, false)
			},
			want: slices.Concat(points(0, 2, 50), points(40, 2, 10)),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clock := &fakeClock{t0.Add(3 * time.Hour)}
			s := openTest(t, clock)
			tt.write(t, s)
			markTenMinutes(t, s)
			got, err := s.Query(t.Context(), "pi", []string{"cpu"}, t0, t0.Add(3*time.Hour), tenMinuteRollup)
			if err != nil {
				t.Fatal(err)
			}
			if !equal(got["cpu"], tt.want) {
				t.Errorf("cpu = %v\nwant  %v", got["cpu"], tt.want)
			}
		})
	}
}

// A range starting inside a complete hour must still see that hour as complete.
func TestQueryTenMinutesStartsInsideHour(t *testing.T) {
	clock := &fakeClock{t0.Add(2 * time.Hour)}
	s := openTest(t, clock)
	writeMinutes(t, s, 0, 60, 10, false)
	markTenMinutes(t, s)
	got, err := s.Query(t.Context(), "pi", []string{"cpu"}, t0.Add(30*time.Minute), t0.Add(time.Hour), tenMinuteRollup)
	if err != nil {
		t.Fatal(err)
	}
	if want := points(30, 3, 20); !equal(got["cpu"], want) {
		t.Errorf("cpu = %v, want %v", got["cpu"], want)
	}
}

// Pruning cuts the oldest hour in two: it takes that hour's hourly rollup and
// part of its finer ones. What remains must still read correctly, and the next
// hour must stay covered.
func TestPruneTenMinuteRollups(t *testing.T) {
	tests := []struct {
		name     string
		keepTens bool
	}{
		{"oldest hour keeps ten-minute rollups", true},
		{"oldest hour has only one-minute rollups", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clock := &fakeClock{t0}
			s := openTest(t, clock)
			writeMinutes(t, s, 0, 120, 10, false)
			cutoff := t0.Add(30 * time.Minute)
			clock.t = cutoff.Add(RollupRetention)
			if err := s.Prune(t.Context()); err != nil {
				t.Fatal(err)
			}
			for _, res := range []time.Duration{time.Minute, tenMinuteRollup, time.Hour} {
				var old int
				err := s.db.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM rollups WHERE res = ? AND ts < ?`,
					res.Milliseconds(), cutoff.UnixMilli()).Scan(&old)
				if err != nil {
					t.Fatal(err)
				}
				if old != 0 {
					t.Errorf("%d rollups of period %v outlived retention", old, res)
				}
			}
			if !tt.keepTens {
				if _, err := s.db.ExecContext(t.Context(), `DELETE FROM rollups WHERE res = 600000 AND ts < ?`, t0.Add(time.Hour).UnixMilli()); err != nil {
					t.Fatal(err)
				}
			}
			markTenMinutes(t, s)
			got, err := s.Query(t.Context(), "pi", []string{"cpu"}, cutoff, t0.Add(2*time.Hour), tenMinuteRollup)
			if err != nil {
				t.Fatal(err)
			}
			if want := slices.Concat(points(30, 3, 10), points(60, 6, 20)); !equal(got["cpu"], want) {
				t.Errorf("cpu = %v\nwant  %v", got["cpu"], want)
			}
		})
	}
}

// fill writes a week of one device's metrics as an agent sends them, every
// 15 s: raw samples for the last RawRetention, rollups for the whole week.
func fill(b testing.TB, s *Store, device string, end time.Time) {
	b.Helper()
	ctx := b.Context()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		b.Fatal(err)
	}
	start := end.Add(-RollupRetention)
	for m := start; m.Before(end); m = m.Add(time.Minute) {
		for _, k := range Known {
			if _, err := tx.ExecContext(ctx, `INSERT INTO rollups VALUES (?, 60000, ?, ?, 200, 4)`, device, k.Key, m.UnixMilli()); err != nil {
				b.Fatal(err)
			}
			if m.Equal(m.Truncate(10 * time.Minute)) {
				if _, err := tx.ExecContext(ctx, `INSERT INTO rollups VALUES (?, 600000, ?, ?, 2000, 40)`, device, k.Key, m.UnixMilli()); err != nil {
					b.Fatal(err)
				}
			}
			if m.Equal(m.Truncate(time.Hour)) {
				if _, err := tx.ExecContext(ctx, `INSERT INTO rollups VALUES (?, 3600000, ?, ?, 12000, 240)`, device, k.Key, m.UnixMilli()); err != nil {
					b.Fatal(err)
				}
			}
			if m.Before(end.Add(-RawRetention)) {
				continue
			}
			for i := range 4 {
				ts := m.Add(time.Duration(i) * 15 * time.Second).UnixMilli()
				if _, err := tx.ExecContext(ctx, `INSERT INTO samples VALUES (?, ?, ?, 50)`, device, k.Key, ts); err != nil {
					b.Fatal(err)
				}
			}
		}
	}
	if err := tx.Commit(); err != nil {
		b.Fatal(err)
	}
}

// BenchmarkQuery is a chart query of one device among ten holding a week of
// data, for each range the UI offers, at the API's 120-point resolution.
func BenchmarkQuery(b *testing.B) {
	clock := &fakeClock{t0}
	s := openTest(b, clock)
	for _, d := range []string{"d0", "d1", "d2", "d3", "d4", "d5", "d6", "d7", "d8", "d9"} {
		fill(b, s, d, t0)
	}
	ranges := []struct {
		name   string
		window time.Duration
	}{
		{"1h", time.Hour},
		{"24h", RawRetention},
		{"7d", RollupRetention},
	}
	run := func(prefix string) {
		for _, tt := range ranges {
			b.Run(prefix+tt.name, func(b *testing.B) {
				for b.Loop() {
					got, err := s.Query(b.Context(), "d3", nil, t0.Add(-tt.window), t0, tt.window/120)
					if err != nil {
						b.Fatal(err)
					}
					if len(got) != len(Known) {
						b.Fatalf("got %d series", len(got))
					}
				}
			})
		}
	}
	run("covered-")
	// Right after an upgrade no ten-minute rollups exist yet.
	if _, err := s.db.ExecContext(b.Context(), `DELETE FROM rollups WHERE res = 600000`); err != nil {
		b.Fatal(err)
	}
	run("uncovered-")
}
