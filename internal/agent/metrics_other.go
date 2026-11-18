// SPDX-License-Identifier: AGPL-3.0-only

//go:build !linux

package agent

import (
	"context"
	"errors"
	"strings"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/mem"
	psnet "github.com/shirou/gopsutil/v4/net"
)

// platform is empty: gopsutil keeps no state between collections.
type platform struct{}

func newPlatform() platform { return platform{} }

// cpuTimes reads the aggregate CPU times.
func (c *collector) cpuTimes(ctx context.Context) (cpuTimes, error) {
	ts, err := cpu.TimesWithContext(ctx, false)
	if err != nil {
		return cpuTimes{}, err
	}
	if len(ts) == 0 {
		return cpuTimes{}, errors.New("no cpu times")
	}
	t := ts[0]
	return cpuTimes{
		idle:  t.Idle + t.Iowait,
		total: t.User + t.System + t.Idle + t.Nice + t.Iowait + t.Irq + t.Softirq + t.Steal,
	}, nil
}

// memoryPercent is the share of memory not available.
func (c *collector) memoryPercent(ctx context.Context) (float64, error) {
	vm, err := mem.VirtualMemoryWithContext(ctx)
	if err != nil {
		return 0, err
	}
	if vm.Total == 0 {
		return 0, errors.New("no memory total")
	}
	return 100 * (1 - float64(vm.Available)/float64(vm.Total)), nil
}

// netBytes sums the received and sent bytes of the non-loopback interfaces.
func (c *collector) netBytes(ctx context.Context) (rx, tx uint64, err error) {
	ios, err := psnet.IOCountersWithContext(ctx, true)
	if err != nil {
		return 0, 0, err
	}
	for _, n := range ios {
		if !strings.HasPrefix(n.Name, "lo") {
			rx += n.BytesRecv
			tx += n.BytesSent
		}
	}
	return rx, tx, nil
}

// temperature is not read outside Linux.
func (c *collector) temperature() (float64, bool) { return 0, false }
