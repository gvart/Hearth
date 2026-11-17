// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"log/slog"
	"runtime"
	"testing"
)

// TestCollectFacts checks the facts of the machine running the test. Linux and
// macOS must report everything; elsewhere only what gopsutil supports.
func TestCollectFacts(t *testing.T) {
	h := collectFacts(t.Context(), slog.New(slog.DiscardHandler))
	t.Logf("facts: %v", h)

	if h.GetArch() != runtime.GOARCH {
		t.Errorf("arch = %q, want %q", h.GetArch(), runtime.GOARCH)
	}
	if h.GetOs() == "" || h.GetHostname() == "" || h.GetCpuCores() == 0 {
		t.Errorf("os, hostname and cpu cores must always be set: %v", h)
	}
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		return
	}
	if h.GetKernel() == "" || h.GetMemTotalBytes() == 0 {
		t.Errorf("kernel and memory missing: %v", h)
	}
	if len(h.GetDisks()) == 0 {
		t.Error("no disks")
	}
	for _, d := range h.GetDisks() {
		if d.GetMountpoint() == "" || d.GetTotalBytes() == 0 {
			t.Errorf("incomplete disk %v", d)
		}
	}
	if len(h.GetInterfaces()) == 0 {
		t.Error("no network interfaces")
	}
	var withMAC, withIP bool
	for _, ni := range h.GetInterfaces() {
		withMAC = withMAC || ni.GetMac() != ""
		withIP = withIP || len(ni.GetIps()) > 0
	}
	if !withMAC || !withIP {
		t.Errorf("want an interface with a MAC and one with an IP: %v", h.GetInterfaces())
	}
	if bootTime(t.Context(), slog.New(slog.DiscardHandler)).IsZero() {
		t.Error("boot time (uptime) unavailable")
	}
}
