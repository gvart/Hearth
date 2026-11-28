// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"errors"
	"testing"
	"time"
)

// TestRemoveDevice: a removed device is gone from Get, List and presence
// writes, a second remove is not found, and an upsert brings it back.
func TestRemoveDevice(t *testing.T) {
	ctx := t.Context()
	s := openTest(t)
	devs := s.Devices()
	now := time.Now()
	id := ProtocolDeviceID("kitchen")
	for _, d := range []Device{
		{ID: id, Name: "kitchen", Labels: map[string]string{LabelSource: SourceDeviceProtocol}, FirstSeen: now, LastSeen: now, Status: StatusOnline},
		{ID: "other", Name: "other", FirstSeen: now, LastSeen: now, Status: StatusOnline},
	} {
		if err := devs.Upsert(ctx, d); err != nil {
			t.Fatal(err)
		}
	}
	if err := devs.Remove(ctx, id); err != nil {
		t.Fatal(err)
	}
	if _, err := devs.Get(ctx, id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("get removed device: %v, want not found", err)
	}
	list, err := devs.List(ctx)
	if err != nil || len(list) != 1 || list[0].ID != "other" {
		t.Fatalf("list = %+v, %v, want only other", list, err)
	}
	if err := devs.Remove(ctx, id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("remove again: %v, want not found", err)
	}
	if _, _, err := devs.MarkSeen(ctx, id, now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("mark a removed device seen: %v, want not found", err)
	}
	changed, err := devs.MarkDevicesOffline(ctx, []string{id, "other"})
	if err != nil || len(changed) != 1 || changed[0].ID != "other" {
		t.Fatalf("mark offline = %+v, %v, want only other", changed, err)
	}
	// It announces itself again: a new row.
	if err := devs.Upsert(ctx, Device{ID: id, Name: "kitchen", FirstSeen: now, LastSeen: now, Status: StatusOnline}); err != nil {
		t.Fatal(err)
	}
	if d, err := devs.Get(ctx, id); err != nil || d.Status != StatusOnline {
		t.Fatalf("get re-announced device: %+v, %v", d, err)
	}
}
