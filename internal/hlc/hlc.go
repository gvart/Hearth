// SPDX-License-Identifier: AGPL-3.0-only

// Package hlc is a hybrid logical clock: a 64-bit timestamp that follows
// physical time (unix milliseconds in the high 48 bits) and orders events the
// physical clock cannot (a 16-bit logical counter in the low bits). A clock's
// timestamps only ever grow, also when the wall clock steps back, and a clock
// that has seen a timestamp issues larger ones from then on.
//
// A remote timestamp more than MaxSkew ahead of the local wall clock is
// refused (see Clock.Update), so a member with a wrong clock cannot drag
// every other clock, and win every conflict, into its future.
package hlc

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

// logicalBits is the width of the logical counter.
const logicalBits = 16

// MaxSkew is how far ahead of the local wall clock a remote timestamp may be.
const MaxSkew = 60 * time.Second

// Timestamp is a hybrid logical clock reading: unix milliseconds << 16 | a
// logical counter. Zero is "no timestamp", before every reading. A counter
// that overflows carries into the milliseconds.
type Timestamp uint64

// New returns the timestamp of physical time t with logical counter 0.
func New(t time.Time) Timestamp {
	ms := t.UnixMilli()
	if ms < 0 {
		return 0
	}
	return Timestamp(ms) << logicalBits
}

// Time is the physical part of ts.
func (ts Timestamp) Time() time.Time {
	return time.UnixMilli(int64(ts >> logicalBits)).UTC()
}

// Logical is the logical counter of ts.
func (ts Timestamp) Logical() uint16 { return uint16(ts) }

// String formats ts as its physical time and logical counter.
func (ts Timestamp) String() string {
	return fmt.Sprintf("%s+%d", ts.Time().Format(time.RFC3339Nano), ts.Logical())
}

// ErrSkew is matched (errors.Is) by every *SkewError.
var ErrSkew = errors.New("hlc: remote timestamp too far ahead of the local clock")

// SkewError refuses a remote timestamp more than MaxSkew ahead of the local
// wall clock.
type SkewError struct {
	Remote Timestamp
	Local  time.Time
	Max    time.Duration
}

func (e *SkewError) Error() string {
	return fmt.Sprintf("hlc: remote timestamp %s is %s ahead of the local clock %s (at most %s)",
		e.Remote, e.Remote.Time().Sub(e.Local).Round(time.Millisecond), e.Local.UTC().Format(time.RFC3339Nano), e.Max)
}

// Is makes errors.Is(err, ErrSkew) true.
func (e *SkewError) Is(target error) bool { return target == ErrSkew }

// Clock issues hybrid logical timestamps. It is safe for concurrent use.
type Clock struct {
	now     func() time.Time
	maxSkew time.Duration

	mu   sync.Mutex
	last Timestamp
}

// NewClock returns a clock reading the wall clock now (time.Now if nil) and
// refusing remote timestamps more than MaxSkew ahead of it.
func NewClock(now func() time.Time) *Clock {
	if now == nil {
		now = time.Now
	}
	return &Clock{now: now, maxSkew: MaxSkew}
}

// Now returns a timestamp larger than every one this clock issued or saw.
func (c *Clock) Now() Timestamp {
	wall := New(c.now())
	c.mu.Lock()
	defer c.mu.Unlock()
	c.last = max(wall, c.last+1)
	return c.last
}

// Update records a remote timestamp, so the next Now is larger, and returns
// the clock's new reading. It refuses, with a *SkewError and without
// changing the clock, a timestamp more than MaxSkew ahead of the wall clock.
func (c *Clock) Update(remote Timestamp) (Timestamp, error) {
	wallTime := c.now()
	if remote.Time().Sub(wallTime) > c.maxSkew {
		return 0, &SkewError{Remote: remote, Local: wallTime, Max: c.maxSkew}
	}
	wall := New(wallTime)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.last = max(wall, c.last+1, remote+1)
	return c.last, nil
}

// Observe records a timestamp the clock must stay ahead of without the skew
// check: one it has no choice about, such as a version already stored in the
// local database or one applied by a replicated log every member applies
// alike. Remote timestamps from another member go through Update.
func (c *Clock) Observe(ts Timestamp) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.last = max(c.last, ts)
}

// Last returns the largest timestamp the clock issued or saw.
func (c *Clock) Last() Timestamp {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.last
}
