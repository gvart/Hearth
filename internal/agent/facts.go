// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"context"
	"log/slog"
	"net"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/shirou/gopsutil/v4/mem"

	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
)

// collectFacts gathers the host facts carried in Hello. A fact the platform
// cannot provide is left empty and logged at debug level; it never fails.
func collectFacts(ctx context.Context, log *slog.Logger) *agentv1.Hello {
	h := &agentv1.Hello{Arch: runtime.GOARCH, Os: runtime.GOOS}
	skip := func(fact string, err error) { log.DebugContext(ctx, "fact unavailable", "fact", fact, "err", err) }

	if info, err := host.InfoWithContext(ctx); err != nil {
		skip("host", err)
	} else {
		h.Hostname = info.Hostname
		h.Kernel = info.KernelVersion
		if info.Platform != "" {
			h.Os = strings.TrimSpace(info.Platform + " " + info.PlatformVersion)
		}
	}
	if h.Hostname == "" {
		h.Hostname, _ = os.Hostname()
	}

	if cpus, err := cpu.InfoWithContext(ctx); err != nil || len(cpus) == 0 {
		skip("cpu model", err)
	} else {
		h.CpuModel = cpus[0].ModelName
	}
	if n, err := cpu.CountsWithContext(ctx, true); err != nil || n <= 0 {
		skip("cpu cores", err)
		h.CpuCores = uint32(runtime.NumCPU()) //nolint:gosec // CPU counts fit in uint32
	} else {
		h.CpuCores = uint32(n) //nolint:gosec // CPU counts fit in uint32
	}

	if vm, err := mem.VirtualMemoryWithContext(ctx); err != nil {
		skip("memory", err)
	} else {
		h.MemTotalBytes = vm.Total
	}

	h.Disks = disks(ctx, skip)
	h.Interfaces = interfaces(skip)
	return h
}

func disks(ctx context.Context, skip func(string, error)) []*agentv1.Disk {
	parts, err := disk.PartitionsWithContext(ctx, false)
	if err != nil {
		skip("disks", err)
	}
	var out []*agentv1.Disk
	for _, p := range parts {
		u, err := disk.UsageWithContext(ctx, p.Mountpoint)
		if err != nil || u.Total == 0 {
			continue // unreadable or pseudo filesystem
		}
		out = append(out, &agentv1.Disk{Device: p.Device, Mountpoint: p.Mountpoint, Fstype: p.Fstype, TotalBytes: u.Total, UsedBytes: u.Used})
	}
	return out
}

// interfaces lists non-loopback interfaces that have a MAC or an address.
func interfaces(skip func(string, error)) []*agentv1.NetworkInterface {
	ifaces, err := net.Interfaces()
	if err != nil {
		skip("interfaces", err)
		return nil
	}
	var out []*agentv1.NetworkInterface
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		ni := &agentv1.NetworkInterface{Name: ifc.Name, Mac: ifc.HardwareAddr.String()}
		addrs, err := ifc.Addrs()
		if err != nil {
			skip("addresses of "+ifc.Name, err)
		}
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok {
				ni.Ips = append(ni.Ips, ipn.IP.String())
			}
		}
		if ni.Mac == "" && len(ni.Ips) == 0 {
			continue
		}
		out = append(out, ni)
	}
	return out
}

// bootTime returns when the host booted, or the zero time if unknown.
func bootTime(ctx context.Context, log *slog.Logger) time.Time {
	secs, err := host.BootTimeWithContext(ctx)
	if err != nil || secs == 0 {
		log.DebugContext(ctx, "fact unavailable", "fact", "uptime", "err", err)
		return time.Time{}
	}
	return time.Unix(int64(secs), 0) //nolint:gosec // boot time in seconds fits in int64
}
