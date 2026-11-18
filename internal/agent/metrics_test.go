// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"log/slog"
	"testing"
	"time"
)

func TestCPUPercent(t *testing.T) {
	prev := cpuTimes{idle: 850, total: 1000}
	tests := []struct {
		name   string
		cur    cpuTimes
		want   float64
		wantOK bool
	}{
		{"quarter busy", cpuTimes{idle: 925, total: 1100}, 25, true},
		{"idle", cpuTimes{idle: 950, total: 1100}, 0, true},
		{"busy", cpuTimes{idle: 850, total: 1100}, 100, true},
		{"no time passed", prev, 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := cpuPercent(prev, tt.cur)
			if ok != tt.wantOK || got != tt.want {
				t.Errorf("cpuPercent = %v, %v; want %v, %v", got, ok, tt.want, tt.wantOK)
			}
		})
	}
}

func TestRate(t *testing.T) {
	tests := []struct {
		prev, cur uint64
		seconds   float64
		want      float64
		wantOK    bool
	}{
		{1000, 4000, 15, 200, true},
		{1000, 1000, 15, 0, true},
		{4000, 1000, 15, 0, false}, // counter went back
		{1000, 2000, 0, 0, false},
	}
	for _, tt := range tests {
		if got, ok := rate(tt.prev, tt.cur, tt.seconds); ok != tt.wantOK || got != tt.want {
			t.Errorf("rate(%d, %d, %v) = %v, %v; want %v, %v", tt.prev, tt.cur, tt.seconds, got, ok, tt.want, tt.wantOK)
		}
	}
}

func TestCollect(t *testing.T) {
	c := newCollector(slog.New(slog.DiscardHandler))
	now := time.Now()
	first := names(c.collect(t.Context(), now))
	if first["cpu"] || first["net_rx"] {
		t.Errorf("first collection has rates: %v", first)
	}
	if !first["memory"] || !first["disk"] {
		t.Errorf("first collection = %v, want memory and disk", first)
	}
	second := names(c.collect(t.Context(), now.Add(time.Second)))
	if !second["net_rx"] || !second["net_tx"] {
		t.Errorf("second collection = %v, want network rates", second)
	}
}

// BenchmarkCollect measures one collection, and what it allocates: the agent
// runs it every 15 s and must idle under 20 MB.
func BenchmarkCollect(b *testing.B) {
	c := newCollector(slog.New(slog.DiscardHandler))
	now := time.Now()
	b.ReportAllocs()
	for b.Loop() {
		now = now.Add(15 * time.Second)
		c.collect(b.Context(), now)
	}
}

func names[S interface{ GetName() string }](samples []S) map[string]bool {
	out := map[string]bool{}
	for _, s := range samples {
		out[s.GetName()] = true
	}
	return out
}
