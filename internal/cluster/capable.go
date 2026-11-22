// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/mem"
)

// The least a device needs to become a hub on its own (#328): a 2 GB board
// reports about 1.8 GiB of memory, a 1 GB one does not qualify.
const (
	MinHubMemory   = 1536 << 20
	MinHubDiskFree = 2 << 30
)

// Caps on the hubs devices become on their own: at most MaxAutoMasters
// masters and MaxAutoStorage storage members are counted before a device is
// offered the role (#328).
const (
	MaxAutoMasters = 3
	MaxAutoStorage = 5
)

// HubCounts counts the members of the cluster with the master and the
// storage role that have not left, but for except: a dead member counts
// until it is removed.
func (n *APNode) HubCounts(except string) (masters, storage int) {
	if n.membership == nil {
		return 0, 0
	}
	return hubCounts(n.membership.Members(), except)
}

func hubCounts(members []MemberInfo, except string) (masters, storage int) {
	for _, m := range members {
		if m.State == MemberLeft || m.ID == except {
			continue
		}
		if m.Roles.Has(RoleMaster) {
			masters++
		}
		if m.Roles.Has(RoleStorage) {
			storage++
		}
	}
	return masters, storage
}

// HubOffer describes the host of a device that offers to run a hub.
type HubOffer struct {
	OS, Arch           string
	MemTotal, DiskFree uint64
}

// HubCapable says why a device described by o cannot become a hub on its
// own, or nil when it can: 64-bit Linux (amd64 or arm64), MinHubMemory of
// memory and MinHubDiskFree free for the hub's data. The agent checks it
// before offering a hub, the hub again before minting a join token. macOS
// never qualifies on its own (a later per-device choice, #332).
func HubCapable(o HubOffer) error {
	switch {
	case o.OS != "linux":
		return fmt.Errorf("%s is not Linux", o.OS)
	case o.Arch != "amd64" && o.Arch != "arm64":
		return fmt.Errorf("%s is not a 64-bit amd64 or arm64 CPU", o.Arch)
	case o.MemTotal < MinHubMemory:
		return fmt.Errorf("%d MiB of memory, under %d MiB", o.MemTotal>>20, MinHubMemory>>20)
	case o.DiskFree < MinHubDiskFree:
		return fmt.Errorf("%d MiB free for the hub's data, under %d MiB", o.DiskFree>>20, MinHubDiskFree>>20)
	}
	return nil
}

// LocalHubOffer describes this host for a hub whose data dir is dataDir,
// which need not exist yet: its free space is that of the nearest directory
// above it that does.
func LocalHubOffer(ctx context.Context, dataDir string) (HubOffer, error) {
	o := HubOffer{OS: runtime.GOOS, Arch: runtime.GOARCH}
	vm, err := mem.VirtualMemoryWithContext(ctx)
	if err != nil {
		return o, fmt.Errorf("read memory: %w", err)
	}
	o.MemTotal = vm.Total
	dir, err := filepath.Abs(dataDir)
	if err != nil {
		return o, err
	}
	for {
		if _, err := os.Stat(dir); err == nil {
			break
		} else if !errors.Is(err, os.ErrNotExist) {
			return o, err
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	u, err := disk.UsageWithContext(ctx, dir)
	if err != nil {
		return o, fmt.Errorf("read free space of %s: %w", dir, err)
	}
	o.DiskFree = u.Free
	return o, nil
}
