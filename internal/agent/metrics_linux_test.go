// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeProc writes files under a temporary /proc and returns a collector
// reading it.
func fakeProc(t *testing.T, files map[string]string) *collector {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	c := newCollector(slog.New(slog.DiscardHandler))
	c.proc = dir
	c.thermalGlob = filepath.Join(dir, "thermal_zone*", "temp")
	return c
}

func TestProcReaders(t *testing.T) {
	c := fakeProc(t, map[string]string{
		"stat": "cpu  100 10 50 800 40 5 5 0 7 0\ncpu0 1 2 3 4 5 6 7 8 9 10\nintr " + strings.Repeat("0 ", 5000) + "\n",
		"meminfo": "MemTotal:        8000000 kB\nMemFree:          100000 kB\n" +
			"MemAvailable:    6000000 kB\nBuffers:           1000 kB\n",
		"net/dev": "Inter-|   Receive                                                |  Transmit\n" +
			" face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n" +
			"    lo: 9999999     100    0    0    0     0          0         0  9999999     100    0    0    0     0       0          0\n" +
			"  eth0: 1000      10    0    0    0     0          0         0     2000      20    0    0    0     0       0          0\n" +
			" wlan0: 500       5     0    0    0     0          0         0     700       7     0    0    0     0       0          0\n",
		"thermal_zone0/temp": "45123\n",
		"thermal_zone1/temp": "61500\n",
		"thermal_zone2/temp": "garbage\n",
	})
	if got, err := c.cpuTimes(t.Context()); err != nil || got != (cpuTimes{idle: 840, total: 1010}) {
		t.Errorf("cpuTimes = %+v, %v; want idle 840 (idle+iowait), total 1010 (no guest)", got, err)
	}
	if got, err := c.memoryPercent(t.Context()); err != nil || got != 25 {
		t.Errorf("memoryPercent = %v, %v; want 25", got, err)
	}
	if rx, tx, err := c.netBytes(t.Context()); err != nil || rx != 1500 || tx != 2700 {
		t.Errorf("netBytes = %d, %d, %v; want 1500, 2700 without loopback", rx, tx, err)
	}
	if got, ok := c.temperature(); !ok || got != 61.5 {
		t.Errorf("temperature = %v, %v; want 61.5 (the hottest zone)", got, ok)
	}
}

func TestProcReadersMissing(t *testing.T) {
	c := fakeProc(t, map[string]string{
		"stat":    "intr 1 2 3\n",
		"meminfo": "MemTotal: 8000000 kB\n",
	})
	if _, err := c.cpuTimes(t.Context()); err == nil {
		t.Error("cpuTimes without a cpu line: no error")
	}
	if _, err := c.memoryPercent(t.Context()); err == nil {
		t.Error("memoryPercent without MemAvailable: no error")
	}
	if _, _, err := c.netBytes(t.Context()); err == nil {
		t.Error("netBytes without /proc/net/dev: no error")
	}
	if _, ok := c.temperature(); ok {
		t.Error("temperature without thermal zones reported a value")
	}
}

// TestPlatformHostPaths: HOST_PROC and HOST_SYS move /proc and /sys, as for
// an agent in a container that reads the host's mounted read-only.
func TestPlatformHostPaths(t *testing.T) {
	tests := []struct {
		name, proc, sys    string
		wantProc, wantGlob string
	}{
		{"defaults", "", "", "/proc", "/sys/class/thermal/thermal_zone*/temp"},
		{"host mounts", "/host/proc", "/host/sys", "/host/proc", "/host/sys/class/thermal/thermal_zone*/temp"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("HOST_PROC", tt.proc)
			t.Setenv("HOST_SYS", tt.sys)
			p := newPlatform()
			if p.proc != tt.wantProc || p.thermalGlob != tt.wantGlob {
				t.Errorf("newPlatform() = %q, %q; want %q, %q", p.proc, p.thermalGlob, tt.wantProc, tt.wantGlob)
			}
		})
	}
}
