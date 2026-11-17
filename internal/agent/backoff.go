// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"math/rand/v2"
	"time"
)

// Reconnect delays.
const (
	minBackoff = time.Second
	maxBackoff = time.Minute
	// quickRetry is the first delay after an established session ended: the
	// hub most likely restarted, so try again almost at once. It is drawn
	// from [quickRetry, 2.5·quickRetry].
	quickRetry = 100 * time.Millisecond
)

// backoff yields exponentially growing reconnect delays with jitter. The n-th
// delay (from 0) is drawn uniformly from [base/2, base], where base is
// min·2ⁿ capped at max, so agents that lost the hub together spread out.
// After reset(true) one quick delay comes first.
type backoff struct {
	min, max time.Duration
	rand     func() float64 // in [0, 1)
	attempt  int
	quick    bool
}

func newBackoff() *backoff {
	return &backoff{min: minBackoff, max: maxBackoff, rand: rand.Float64}
}

// next returns the delay before the next attempt and advances the sequence.
func (b *backoff) next() time.Duration {
	if b.quick {
		b.quick = false
		return quickRetry + time.Duration(b.rand()*float64(quickRetry*3/2))
	}
	base := b.max
	if b.attempt < 32 { // past that the shift overflows; we are long capped anyway
		if d := b.min << b.attempt; d > 0 && d < b.max {
			base = d
		}
	}
	b.attempt++
	return base/2 + time.Duration(b.rand()*float64(base/2))
}

// reset starts the sequence over, after a successful session; quick makes
// the next delay a quick retry.
func (b *backoff) reset(quick bool) {
	b.attempt = 0
	b.quick = quick
}
