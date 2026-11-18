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

// BenchmarkQuery7d is a 7-day chart query of one device among ten, at the
// API's 120-point resolution.
func BenchmarkQuery7d(b *testing.B) {
	clock := &fakeClock{t0}
	s := openTest(b, clock)
	for _, d := range []string{"d0", "d1", "d2", "d3", "d4", "d5", "d6", "d7", "d8", "d9"} {
		fill(b, s, d, t0)
	}
	start := t0.Add(-RollupRetention)
	for b.Loop() {
		got, err := s.Query(b.Context(), "d3", nil, start, t0, RollupRetention/120)
		if err != nil {
			b.Fatal(err)
		}
		if len(got) != len(Known) {
			b.Fatalf("got %d series", len(got))
		}
	}
}
