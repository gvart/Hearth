// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"context"
	"log/slog"
	"runtime"
	"time"

	"github.com/shirou/gopsutil/v4/disk"
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
//
// It runs every 15 s for the agent's whole life, so on Linux it reads /proc
// and /sys into one reused buffer: what it allocates would otherwise grow
// the idle agent's heap (see BenchmarkCollect).
type collector struct {
	log     *slog.Logger
	prevCPU *cpuTimes
	prevNet *netCounters
	platform
}

// cpuTimes are cumulative CPU times, in any unit.
type cpuTimes struct{ idle, total float64 }

type netCounters struct {
	rx, tx uint64
	at     time.Time
}

func newCollector(log *slog.Logger) *collector {
	return &collector{log: log, platform: newPlatform()}
}

// collect returns the metrics a platform provides; one it cannot read is
// left out and logged at debug level.
func (c *collector) collect(ctx context.Context, now time.Time) []*agentv1.MetricSample {
	out := make([]*agentv1.MetricSample, 0, 6)
	ts := timestamppb.New(now)
	add := func(name string, v float64) {
		out = append(out, &agentv1.MetricSample{Name: name, Value: v, Ts: ts})
	}
	skip := func(metric string, err error) {
		c.log.DebugContext(ctx, "metric unavailable", "metric", metric, "err", err)
	}

	if t, err := c.cpuTimes(ctx); err != nil {
		skip("cpu", err)
	} else {
		if c.prevCPU != nil {
			if v, ok := cpuPercent(*c.prevCPU, t); ok {
				add("cpu", v)
			}
		}
		c.prevCPU = &t
	}
	if v, err := c.memoryPercent(ctx); err != nil {
		skip("memory", err)
	} else {
		add("memory", v)
	}
	if u, err := disk.UsageWithContext(ctx, rootPath()); err != nil || u.Total == 0 {
		skip("disk", err)
	} else {
		add("disk", u.UsedPercent)
	}
	if t, ok := c.temperature(); ok {
		add("temperature", t)
	}
	if rx, tx, err := c.netBytes(ctx); err != nil {
		skip("network", err)
	} else {
		if p := c.prevNet; p != nil {
			dt := now.Sub(p.at).Seconds()
			if v, ok := rate(p.rx, rx, dt); ok {
				add("net_rx", v)
			}
			if v, ok := rate(p.tx, tx, dt); ok {
				add("net_tx", v)
			}
		}
		c.prevNet = &netCounters{rx: rx, tx: tx, at: now}
	}
	return out
}

// cpuPercent is the busy share of CPU time between two readings, or false if
// no time passed.
func cpuPercent(prev, cur cpuTimes) (float64, bool) {
	dt := cur.total - prev.total
	if dt <= 0 {
		return 0, false
	}
	return min(max(100*(1-(cur.idle-prev.idle)/dt), 0), 100), true
}

// rate is the per-second rate of a counter, or false if it went back (an
// interface went away) or no time passed.
func rate(prev, cur uint64, seconds float64) (float64, bool) {
	if cur < prev || seconds <= 0 {
		return 0, false
	}
	return float64(cur-prev) / seconds, true
}

// rootPath is the filesystem the disk metric reports on.
func rootPath() string {
	if runtime.GOOS == "windows" {
		return `C:\`
	}
	return "/"
}
