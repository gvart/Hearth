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
	}{
		{"pi 4 (7819 MiB, 20 GB free)", func(o *HubOffer) { o.MemTotal = 7819 << 20 }, true},
		{"pi 5 (16218 MiB, 93 GB free)", func(o *HubOffer) { o.MemTotal, o.DiskFree = 16218<<20, 93*gib }, true},
		{"amd64", func(o *HubOffer) { o.Arch = "amd64" }, true},
		{"2 GB board (1.8 GiB)", func(o *HubOffer) { o.MemTotal = 1843 << 20 }, true},
		{"exactly the minimum", func(o *HubOffer) { o.MemTotal, o.DiskFree = MinHubMemory, MinHubDiskFree }, true},
		{"1 GB board", func(o *HubOffer) { o.MemTotal = 922 << 20 }, false},
		{"32-bit arm", func(o *HubOffer) { o.Arch = "arm" }, false},
		{"386", func(o *HubOffer) { o.Arch = "386" }, false},
		{"low disk", func(o *HubOffer) { o.DiskFree = MinHubDiskFree - 1 }, false},
		{"macOS", func(o *HubOffer) { o.OS = "darwin" }, false},
		{"windows", func(o *HubOffer) { o.OS = "windows" }, false},
		{"android", func(o *HubOffer) { o.OS = "android" }, false},
		{"empty offer", func(o *HubOffer) { *o = HubOffer{} }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := ok
			tc.edit(&o)
			if err := HubCapable(o); (err == nil) != tc.want {
				t.Fatalf("HubCapable(%+v) = %v, want capable %v", o, err, tc.want)
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
