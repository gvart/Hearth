// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
)

func TestCPUPercent(t *testing.T) {
	prev := cpu.TimesStat{User: 100, System: 50, Idle: 800, Iowait: 50}
	tests := []struct {
		name   string
		cur    cpu.TimesStat
		want   float64
		wantOK bool
	}{
		{"quarter busy", cpu.TimesStat{User: 120, System: 55, Idle: 870, Iowait: 55}, 25, true},
		{"idle", cpu.TimesStat{User: 100, System: 50, Idle: 900, Iowait: 50}, 0, true},
		{"busy", cpu.TimesStat{User: 150, System: 100, Idle: 800, Iowait: 50}, 100, true},
		{"iowait is idle", cpu.TimesStat{User: 100, System: 50, Idle: 800, Iowait: 150}, 0, true},
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

func TestTemperature(t *testing.T) {
	dir := t.TempDir()
	for zone, v := range map[string]string{"thermal_zone0": "45123\n", "thermal_zone1": "61500\n", "thermal_zone2": "garbage"} {
		if err := os.MkdirAll(filepath.Join(dir, zone), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, zone, "temp"), []byte(v), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	c := newCollector(slog.New(slog.DiscardHandler))
	c.thermalGlob = filepath.Join(dir, "thermal_zone*", "temp")
	if got, ok := c.temperature(); !ok || got != 61.5 {
		t.Errorf("temperature = %v, %v; want 61.5 (the hottest zone)", got, ok)
	}
	c.thermalGlob = filepath.Join(dir, "none*")
	if _, ok := c.temperature(); ok {
		t.Error("temperature without thermal zones reported a value")
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

func names[S interface{ GetName() string }](samples []S) map[string]bool {
	out := map[string]bool{}
	for _, s := range samples {
		out[s.GetName()] = true
	}
	return out
}
