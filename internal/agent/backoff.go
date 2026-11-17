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
)

// backoff yields exponentially growing reconnect delays with jitter. The n-th
// delay (from 0) is drawn uniformly from [base/2, base], where base is
// min·2ⁿ capped at max, so agents that lost the hub together spread out.
type backoff struct {
	min, max time.Duration
	rand     func() float64 // in [0, 1)
	attempt  int
}

func newBackoff() *backoff {
	return &backoff{min: minBackoff, max: maxBackoff, rand: rand.Float64}
}

// next returns the delay before the next attempt and advances the sequence.
func (b *backoff) next() time.Duration {
	base := b.max
	if b.attempt < 32 { // past that the shift overflows; we are long capped anyway
		if d := b.min << b.attempt; d > 0 && d < b.max {
			base = d
		}
	}
	b.attempt++
	return base/2 + time.Duration(b.rand()*float64(base/2))
}

// reset starts the sequence over, after a successful session.
func (b *backoff) reset() { b.attempt = 0 }
