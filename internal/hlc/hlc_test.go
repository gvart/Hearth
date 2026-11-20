// SPDX-License-Identifier: AGPL-3.0-only

package hlc

import (
	"errors"
	"sync"
	"testing"
	"time"
)

var t0 = time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)

// fakeWall is a settable wall clock.
type fakeWall struct {
	mu sync.Mutex
	t  time.Time
}

func (f *fakeWall) now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.t
}

func (f *fakeWall) set(t time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.t = t
}

func TestTimestampParts(t *testing.T) {
	ts := New(t0) + 7
	if !ts.Time().Equal(t0) || ts.Logical() != 7 {
		t.Fatalf("parts of %d = %s, %d", ts, ts.Time(), ts.Logical())
	}
	if New(time.UnixMilli(-1)) != 0 {
		t.Fatal("a time before the epoch is not zero")
	}
	if New(t0) <= New(t0.Add(-time.Millisecond))+0xffff {
		t.Fatal("a later millisecond does not order after every logical tick of the one before")
	}
}

func TestNow(t *testing.T) {
	tests := []struct {
		name string
		// walls are the wall clock readings before each Now.
		walls []time.Time
		want  []Timestamp
	}{
		{"wall moves", []time.Time{t0, t0.Add(time.Millisecond)}, []Timestamp{New(t0), New(t0.Add(time.Millisecond))}},
		{"same millisecond", []time.Time{t0, t0, t0}, []Timestamp{New(t0), New(t0) + 1, New(t0) + 2}},
		{"wall steps back", []time.Time{t0, t0.Add(-time.Hour)}, []Timestamp{New(t0), New(t0) + 1}},
		{"wall catches up", []time.Time{t0, t0.Add(-time.Hour), t0.Add(time.Second)}, []Timestamp{New(t0), New(t0) + 1, New(t0.Add(time.Second))}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := &fakeWall{}
			c := NewClock(w.now)
			for i, wall := range tt.walls {
				w.set(wall)
				if got := c.Now(); got != tt.want[i] {
					t.Fatalf("Now #%d = %s, want %s", i, got, tt.want[i])
				}
			}
		})
	}
}

func TestLogicalOverflowCarries(t *testing.T) {
	w := &fakeWall{t: t0}
	c := NewClock(w.now)
	c.Observe(New(t0) + 0xffff)
	if got := c.Now(); got != New(t0.Add(time.Millisecond)) {
		t.Fatalf("Now after the last logical tick = %s, want the next millisecond", got)
	}
}

func TestUpdate(t *testing.T) {
	tests := []struct {
		name    string
		remote  Timestamp
		want    Timestamp // the clock's reading after Update
		wantErr bool
	}{
		{"behind", New(t0.Add(-time.Minute)), New(t0), false},
		{"same", New(t0), New(t0) + 1, false},
		{"ahead within the bound", New(t0.Add(30 * time.Second)), New(t0.Add(30*time.Second)) + 1, false},
		{"exactly at the bound", New(t0.Add(MaxSkew)), New(t0.Add(MaxSkew)) + 1, false},
		{"past the bound", New(t0.Add(MaxSkew + time.Millisecond)), 0, true},
		{"far future", New(t0.Add(24 * time.Hour * 365)), 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := &fakeWall{t: t0}
			c := NewClock(w.now)
			got, err := c.Update(tt.remote)
			if tt.wantErr {
				var se *SkewError
				if !errors.As(err, &se) || !errors.Is(err, ErrSkew) || se.Remote != tt.remote || se.Max != MaxSkew {
					t.Fatalf("Update(%s) err = %v, want a *SkewError", tt.remote, err)
				}
				if c.Last() != 0 {
					t.Fatalf("a refused Update moved the clock to %s", c.Last())
				}
				// The clock goes on from the wall clock, not the refused future.
				if now := c.Now(); now != New(t0) {
					t.Fatalf("Now after a refused Update = %s, want %s", now, New(t0))
				}
				return
			}
			if err != nil || got != tt.want {
				t.Fatalf("Update(%s) = %s, %v, want %s", tt.remote, got, err, tt.want)
			}
			if now := c.Now(); now <= tt.remote || now <= got {
				t.Fatalf("Now after Update = %s, want past %s and %s", now, tt.remote, got)
			}
		})
	}
}

func TestObserveSkipsTheSkewCheck(t *testing.T) {
	w := &fakeWall{t: t0}
	c := NewClock(w.now)
	future := New(t0.Add(time.Hour))
	c.Observe(future)
	if now := c.Now(); now != future+1 {
		t.Fatalf("Now after Observe = %s, want %s", now, future+1)
	}
	c.Observe(New(t0)) // an older one does not move it back
	if c.Last() != future+1 {
		t.Fatalf("Last = %s, want %s", c.Last(), future+1)
	}
}

func TestNowIsUniqueUnderConcurrency(t *testing.T) {
	c := NewClock(func() time.Time { return t0 })
	const workers, each = 8, 500
	var (
		mu   sync.Mutex
		seen = map[Timestamp]bool{}
		wg   sync.WaitGroup
	)
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range each {
				ts := c.Now()
				mu.Lock()
				seen[ts] = true
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if len(seen) != workers*each {
		t.Fatalf("%d distinct timestamps, want %d", len(seen), workers*each)
	}
}
