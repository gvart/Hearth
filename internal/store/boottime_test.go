// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"errors"
	"testing"
	"time"
)

func TestDevicesSetBootTime(t *testing.T) {
	t0 := time.UnixMilli(1_700_000_000_000).UTC()
	boot := t0.Add(-3 * time.Hour)
	tests := []struct {
		name    string
		initial time.Time // boot time stored before the call; zero leaves it NULL
		set     time.Time
		want    time.Time
	}{
		{"unknown stays unknown", time.Time{}, time.Time{}, time.Time{}},
		{"set from unknown", time.Time{}, boot, boot},
		{"replace on reboot", boot, t0.Add(-time.Minute), t0.Add(-time.Minute)},
		{"zero clears", boot, time.Time{}, time.Time{}},
		{"sub-millisecond is truncated", time.Time{}, boot.Add(1500 * time.Microsecond), boot.Add(time.Millisecond)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := t.Context()
			devs := openTest(t).Devices()
			if err := devs.Upsert(ctx, Device{ID: "pi", FirstSeen: t0, LastSeen: t0, Status: StatusOnline, BootTime: tt.initial}); err != nil {
				t.Fatal(err)
			}
			if got, _ := devs.Get(ctx, "pi"); !got.BootTime.Equal(tt.initial) {
				t.Fatalf("Upsert: boot time = %v, want %v", got.BootTime, tt.initial)
			}
			d, err := devs.SetBootTime(ctx, "pi", tt.set)
			if err != nil {
				t.Fatal(err)
			}
			if !d.BootTime.Equal(tt.want) {
				t.Errorf("returned boot time = %v, want %v", d.BootTime, tt.want)
			}
			got, err := devs.Get(ctx, "pi")
			if err != nil {
				t.Fatal(err)
			}
			if !got.BootTime.Equal(tt.want) || got.Status != StatusOnline || !got.LastSeen.Equal(t0) {
				t.Errorf("stored = boot %v status %q last_seen %v; want boot %v, other fields unchanged",
					got.BootTime, got.Status, got.LastSeen, tt.want)
			}
		})
	}
}

func TestDevicesSetBootTimeMissing(t *testing.T) {
	devs := openTest(t).Devices()
	if _, err := devs.SetBootTime(t.Context(), "missing", time.Now()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("SetBootTime(missing) err = %v, want ErrNotFound", err)
	}
}
