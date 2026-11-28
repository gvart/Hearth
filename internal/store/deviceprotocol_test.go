// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"errors"
	"slices"
	"testing"
	"time"
)

// TestRemoveDeviceReplicates: a device's tombstone merges into another
// member, keeps its digests right through the tombstone GC, and an older
// version of the row merged after it does not bring the device back.
func TestRemoveDeviceReplicates(t *testing.T) {
	ctx := t.Context()
	a := openTestWith(t, WithDigest(), WithOrigin("a"))
	b := openTestWith(t, WithDigest(), WithOrigin("b"))
	id := ProtocolDeviceID("kitchen")
	apply := func(cmd Command) []Mutation {
		t.Helper()
		_, ms, err := a.ApplyLocalMutations(ctx, withStamp(cmd, Stamp{HLC: a.clock.Now(), Origin: "a"}))
		if err != nil {
			t.Fatal(err)
		}
		return ms
	}
	upsert := apply(UpsertDevice{ID: id, Name: "kitchen", Facts: `{}`, Labels: `{}`, FirstSeen: 1, LastSeen: 1, Status: StatusOnline})
	if err := b.Merge(ctx, upsert); err != nil {
		t.Fatal(err)
	}
	if err := b.Merge(ctx, apply(RemoveDevice{ID: id})); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Devices().Get(ctx, id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("removed device on b: %v, want not found", err)
	}
	// The older upsert again, as anti-entropy or a late hint may bring it.
	if err := b.Merge(ctx, upsert); err != nil {
		t.Fatal(err)
	}
	if list, err := b.Devices().List(ctx); err != nil || len(list) != 0 {
		t.Fatalf("devices on b = %+v, %v, want none", list, err)
	}
	if _, err := a.GCTombstones(ctx, time.Now().Add(30*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	for _, s := range []*Store{a, b} {
		for _, sp := range []Space{SpaceShard, SpaceGlobal, SpaceMaster} {
			buckets := make([]int, sp.Buckets())
			for i := range buckets {
				buckets[i] = i
			}
			kept := s.BucketDigests(sp, buckets)
			if err := s.buildDigest(ctx); err != nil {
				t.Fatal(err)
			}
			if built := s.BucketDigests(sp, buckets); !slices.Equal(kept, built) {
				t.Errorf("%s space %d: kept digests differ from built ones", s.origin, sp)
			}
		}
	}
}

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
