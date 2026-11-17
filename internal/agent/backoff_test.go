// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/durationpb"
)

func TestBackoff(t *testing.T) {
	tests := []struct {
		name   string
		jitter float64      // fixed value returned by the random source
		resets map[int]bool // reset(quick) before delay i
		want   []time.Duration
	}{
		{
			name:   "no jitter doubles up to the cap",
			jitter: 1,
			want:   []time.Duration{1 * time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second, 32 * time.Second, 60 * time.Second, 60 * time.Second},
		},
		{
			name:   "full jitter halves every step",
			jitter: 0,
			want:   []time.Duration{500 * time.Millisecond, time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second, 30 * time.Second, 30 * time.Second},
		},
		{
			name:   "jitter in between",
			jitter: 0.5,
			want:   []time.Duration{750 * time.Millisecond, 1500 * time.Millisecond, 3 * time.Second},
		},
		{
			name:   "reset after a brief session starts over",
			jitter: 1,
			resets: map[int]bool{3: false},
			want:   []time.Duration{1 * time.Second, 2 * time.Second, 4 * time.Second, 1 * time.Second, 2 * time.Second},
		},
		{
			name:   "reset after an established session retries quickly first",
			jitter: 1,
			resets: map[int]bool{3: true},
			want:   []time.Duration{1 * time.Second, 2 * time.Second, 4 * time.Second, 250 * time.Millisecond, 1 * time.Second, 2 * time.Second},
		},
		{
			name:   "quick retry with full jitter",
			jitter: 0,
			resets: map[int]bool{0: true},
			want:   []time.Duration{100 * time.Millisecond, 500 * time.Millisecond, time.Second},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := newBackoff()
			b.rand = func() float64 { return tt.jitter }
			for i, want := range tt.want {
				if quick, ok := tt.resets[i]; ok {
					b.reset(quick)
				}
				if got := b.next(); got != want {
					t.Errorf("delay %d = %v, want %v", i, got, want)
				}
			}
		})
	}
}

// TestBackoffStaysCapped runs far past the point where min<<attempt overflows.
func TestBackoffStaysCapped(t *testing.T) {
	b := newBackoff()
	b.rand = func() float64 { return 0.999 }
	for i := range 200 {
		if d := b.next(); d < minBackoff/2 || d > maxBackoff {
			t.Fatalf("delay %d = %v, outside [%v, %v]", i, d, minBackoff/2, maxBackoff)
		}
	}
}

func TestHeartbeatInterval(t *testing.T) {
	tests := []struct {
		name string
		in   *durationpb.Duration
		want time.Duration
	}{
		{"unset uses default", nil, defaultHeartbeatInterval},
		{"hub value is honoured", durationpb.New(3 * time.Second), 3 * time.Second},
		{"too small is clamped", durationpb.New(time.Millisecond), minHeartbeatInterval},
		{"zero is clamped", durationpb.New(0), minHeartbeatInterval},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := heartbeatInterval(tt.in); got != tt.want {
				t.Errorf("heartbeatInterval = %v, want %v", got, tt.want)
			}
		})
	}
}
