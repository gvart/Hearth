// SPDX-License-Identifier: AGPL-3.0-only

package automation

import (
	"context"
	"testing"
	"time"
)

// fakeDevices hands events to whoever watches.
type fakeDevices struct{ ch chan DeviceEvent }

func (f *fakeDevices) WatchDevices(ctx context.Context, fn func(DeviceEvent)) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		case e := <-f.ch:
			fn(e)
		}
	}
}

func TestDeviceTrigger(t *testing.T) {
	nasOff := DeviceEvent{ID: "d1", Name: "nas", Hostname: "NAS.lan", Online: false}
	nasOn := DeviceEvent{ID: "d1", Name: "nas", Hostname: "NAS.lan", Online: true}
	piOff := DeviceEvent{ID: "d2", Name: "pi", Hostname: "pi.lan", Online: false}
	for _, tc := range []struct {
		name   string
		src    string
		events []DeviceEvent
		want   int32
	}{
		{"offline by name", "device: nas\nto: offline", []DeviceEvent{nasOff, nasOn, piOff, nasOff}, 2},
		{"offline by id", "device: d1\nto: offline", []DeviceEvent{nasOff, piOff}, 1},
		{"offline by hostname, any case", "device: nas.LAN\nto: offline", []DeviceEvent{nasOff}, 1},
		{"online", "device: nas\nto: online", []DeviceEvent{nasOff, nasOn}, 1},
		{"any device", "to: offline", []DeviceEvent{nasOff, piOff, nasOn}, 2},
		{"other device", "device: router\nto: offline", []DeviceEvent{nasOff, piOff}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			devs := &fakeDevices{ch: make(chan DeviceEvent)}
			w := watch(t, mustBuildTrigger(t, TriggerDeps{Devices: devs}, "type: device\n"+tc.src))
			for _, e := range tc.events {
				devs.ch <- e
			}
			// An unmatched event, sent unbuffered, is handled only after
			// every event before it. It is online, so no offline trigger
			// above can match it, and no device is called "none".
			devs.ch <- DeviceEvent{ID: "none", Online: true}
			if n := w.fires.Load(); n != tc.want {
				t.Errorf("fires = %d, want %d", n, tc.want)
			}
		})
	}
}

func TestDeviceTriggerInvalid(t *testing.T) {
	_, err := buildTrigger(t, TriggerDeps{}, "type: device\ndevice: nas")
	wantErrContains(t, err, "to must be online or offline")
	_, err = buildTrigger(t, TriggerDeps{}, "type: device\nto: down")
	wantErrContains(t, err, "to must be online or offline")
}

func TestDeviceTriggerWithoutEvents(t *testing.T) {
	tr := mustBuildTrigger(t, TriggerDeps{}, "type: device\nto: offline")
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	wantErrContains(t, tr.Watch(ctx, func(map[string]any) {}), "not available")
	if got, want := tr.Describe(), "fires when any device goes offline"; got != want {
		t.Errorf("Describe = %q, want %q", got, want)
	}
}
