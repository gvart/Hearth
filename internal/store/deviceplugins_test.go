// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"errors"
	"testing"
	"time"
)

func TestDevicePlugins(t *testing.T) {
	ctx := t.Context()
	s := openTest(t)
	now := time.UnixMilli(1_700_000_000_000)
	p := DevicePlugin{
		Name: "lamp", OS: "linux", Arch: "arm64", Version: "1.0", SHA256: "aa", Size: 10,
		Manifest: []byte(`{"commands":[]}`), Holder: "hub-a", UploadedAt: now, UploadedBy: "web/10.0.0.1",
	}
	if err := s.DevicePlugins().Set(ctx, p); err != nil {
		t.Fatal(err)
	}
	// A second upload of the same platform replaces the first.
	p.Version, p.SHA256 = "1.1", "bb"
	if err := s.DevicePlugins().Set(ctx, p); err != nil {
		t.Fatal(err)
	}
	amd := p
	amd.Arch = "amd64"
	if err := s.DevicePlugins().Set(ctx, amd); err != nil {
		t.Fatal(err)
	}
	list, err := s.DevicePlugins().List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 || list[0].Arch != "amd64" || list[1].Version != "1.1" || list[1].SHA256 != "bb" ||
		list[1].ID != DevicePluginID("lamp", "linux", "arm64") || !list[1].UploadedAt.Equal(now) || list[1].Holder != "hub-a" {
		t.Fatalf("list = %+v", list)
	}
	if err := s.DevicePlugins().Remove(ctx, list[0].ID); err != nil {
		t.Fatal(err)
	}
	if err := s.DevicePlugins().Remove(ctx, list[0].ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second remove = %v", err)
	}
	// Uploaded again after a removal.
	if err := s.DevicePlugins().Set(ctx, amd); err != nil {
		t.Fatal(err)
	}
	if list, _ := s.DevicePlugins().List(ctx); len(list) != 2 {
		t.Fatalf("list = %+v", list)
	}
	if err := s.DevicePlugins().Set(ctx, DevicePlugin{Name: "x", Manifest: []byte(`{}`)}); err == nil {
		t.Fatal("a plugin without a platform was stored")
	}
}
