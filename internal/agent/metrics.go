// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/mem"
	psnet "github.com/shirou/gopsutil/v4/net"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
)

// defaultMetricsInterval is how often host metrics are sent.
const defaultMetricsInterval = 15 * time.Second

// collector samples host metrics: cpu, memory and disk (of the root
// filesystem) in percent, temperature in °C (the hottest thermal zone, Linux
// only) and net_rx and net_tx in bytes per second, summed over the
// non-loopback interfaces. CPU and network are rates since the previous
// collection, so the first collection has none. Only sendLoop uses it.
type collector struct {
	log     *slog.Logger
	prevCPU *cpu.TimesStat
	prevNet *netCounters
	// thermalGlob lists the thermal zone temperature files.
	thermalGlob string
}

type netCounters struct {
	rx, tx uint64
	at     time.Time
}

func newCollector(log *slog.Logger) *collector {
	return &collector{log: log, thermalGlob: "/sys/class/thermal/thermal_zone*/temp"}
}

// collect returns the metrics a platform provides; one it cannot read is
// left out and logged at debug level.
func (c *collector) collect(ctx context.Context, now time.Time) []*agentv1.MetricSample {
	var out []*agentv1.MetricSample
	add := func(name string, v float64) {
		out = append(out, &agentv1.MetricSample{Name: name, Value: v, Ts: timestamppb.New(now)})
	}
	skip := func(metric string, err error) {
		c.log.DebugContext(ctx, "metric unavailable", "metric", metric, "err", err)
	}

	if ts, err := cpu.TimesWithContext(ctx, false); err != nil || len(ts) == 0 {
		skip("cpu", err)
	} else {
		if c.prevCPU != nil {
			if v, ok := cpuPercent(*c.prevCPU, ts[0]); ok {
				add("cpu", v)
			}
		}
		c.prevCPU = &ts[0]
	}
	if vm, err := mem.VirtualMemoryWithContext(ctx); err != nil || vm.Total == 0 {
		skip("memory", err)
	} else {
		add("memory", 100*(1-float64(vm.Available)/float64(vm.Total)))
	}
	if u, err := disk.UsageWithContext(ctx, rootPath()); err != nil || u.Total == 0 {
		skip("disk", err)
	} else {
		add("disk", u.UsedPercent)
	}
	if t, ok := c.temperature(); ok {
		add("temperature", t)
	}
	if ios, err := psnet.IOCountersWithContext(ctx, true); err != nil {
		skip("network", err)
	} else {
		cur := &netCounters{at: now}
		for _, n := range ios {
			if !strings.HasPrefix(n.Name, "lo") {
				cur.rx += n.BytesRecv
				cur.tx += n.BytesSent
			}
		}
		if p := c.prevNet; p != nil {
			dt := now.Sub(p.at).Seconds()
			if rx, ok := rate(p.rx, cur.rx, dt); ok {
				add("net_rx", rx)
			}
			if tx, ok := rate(p.tx, cur.tx, dt); ok {
				add("net_tx", tx)
			}
		}
		c.prevNet = cur
	}
	return out
}

// cpuPercent is the busy share of CPU time between two readings, or false if
// no time passed.
func cpuPercent(prev, cur cpu.TimesStat) (float64, bool) {
	total := func(t cpu.TimesStat) float64 {
		// Guest time is already counted in User on Linux.
		return t.User + t.System + t.Idle + t.Nice + t.Iowait + t.Irq + t.Softirq + t.Steal
	}
	dt := total(cur) - total(prev)
	if dt <= 0 {
		return 0, false
	}
	idle := (cur.Idle + cur.Iowait) - (prev.Idle + prev.Iowait)
	return min(max(100*(1-idle/dt), 0), 100), true
}

// rate is the per-second rate of a counter, or false if it went back (an
// interface went away) or no time passed.
func rate(prev, cur uint64, seconds float64) (float64, bool) {
	if cur < prev || seconds <= 0 {
		return 0, false
	}
	return float64(cur-prev) / seconds, true
}

// temperature is the hottest thermal zone in °C, read from sysfs; Linux only.
func (c *collector) temperature() (float64, bool) {
	files, _ := filepath.Glob(c.thermalGlob) // the pattern is valid
	var (
		hottest float64
		found   bool
	)
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		milli, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
		if err != nil {
			continue
		}
		if t := float64(milli) / 1000; !found || t > hottest {
			hottest, found = t, true
		}
	}
	return hottest, found
}

// rootPath is the filesystem the disk metric reports on.
func rootPath() string {
	if runtime.GOOS == "windows" {
		return `C:\`
	}
	return "/"
}
