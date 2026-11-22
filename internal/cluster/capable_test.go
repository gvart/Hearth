// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import (
	"path/filepath"
	"runtime"
	"testing"
)

func TestHubCapable(t *testing.T) {
	const gib = 1 << 30
	ok := HubOffer{OS: "linux", Arch: "arm64", MemTotal: 2 * gib, DiskFree: 20 * gib}
	for _, tc := range []struct {
		name string
		edit func(*HubOffer)
		want bool
		// chosen is HubChosen: as want, but macOS qualifies.
		chosen bool
	}{
		{"pi 4 (7819 MiB, 20 GB free)", func(o *HubOffer) { o.MemTotal = 7819 << 20 }, true, true},
		{"pi 5 (16218 MiB, 93 GB free)", func(o *HubOffer) { o.MemTotal, o.DiskFree = 16218<<20, 93*gib }, true, true},
		{"amd64", func(o *HubOffer) { o.Arch = "amd64" }, true, true},
		{"2 GB board (1.8 GiB)", func(o *HubOffer) { o.MemTotal = 1843 << 20 }, true, true},
		{"exactly the minimum", func(o *HubOffer) { o.MemTotal, o.DiskFree = MinHubMemory, MinHubDiskFree }, true, true},
		{"1 GB board", func(o *HubOffer) { o.MemTotal = 922 << 20 }, false, false},
		{"32-bit arm", func(o *HubOffer) { o.Arch = "arm" }, false, false},
		{"386", func(o *HubOffer) { o.Arch = "386" }, false, false},
		{"low disk", func(o *HubOffer) { o.DiskFree = MinHubDiskFree - 1 }, false, false},
		{"macOS", func(o *HubOffer) { o.OS = "darwin" }, false, true},
		{"macOS with little memory", func(o *HubOffer) { o.OS, o.MemTotal = "darwin", 1<<30 }, false, false},
		{"windows", func(o *HubOffer) { o.OS = "windows" }, false, false},
		{"android", func(o *HubOffer) { o.OS = "android" }, false, false},
		{"empty offer", func(o *HubOffer) { *o = HubOffer{} }, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := ok
			tc.edit(&o)
			if err := HubCapable(o); (err == nil) != tc.want {
				t.Fatalf("HubCapable(%+v) = %v, want capable %v", o, err, tc.want)
			}
			if err := HubChosen(o); (err == nil) != tc.chosen {
				t.Fatalf("HubChosen(%+v) = %v, want capable %v", o, err, tc.chosen)
			}
		})
	}
}

// The offer of a data dir that does not exist yet reads the free space of
// the nearest one above it.
func TestLocalHubOffer(t *testing.T) {
	o, err := LocalHubOffer(t.Context(), filepath.Join(t.TempDir(), "not", "yet", "hub"))
	if err != nil {
		t.Fatal(err)
	}
	if o.OS != runtime.GOOS || o.Arch != runtime.GOARCH || o.MemTotal == 0 || o.DiskFree == 0 {
		t.Fatalf("LocalHubOffer = %+v", o)
	}
}
