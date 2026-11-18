// SPDX-License-Identifier: AGPL-3.0-only

package automation

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// deviceTrigger fires when a device goes online or offline.
type deviceTrigger struct {
	// device is an id, name or hostname; "" is any device.
	device string
	online bool
	events DeviceEvents
}

func buildDevice(p Params, deps TriggerDeps) (Trigger, error) {
	var cfg struct {
		Device string `yaml:"device"`
		To     string `yaml:"to"`
	}
	if err := p.Decode(&cfg); err != nil {
		return nil, err
	}
	t := &deviceTrigger{device: cfg.Device, events: deps.Devices}
	switch cfg.To {
	case "online":
		t.online = true
	case "offline":
	default:
		return nil, fmt.Errorf("to must be online or offline, not %q", cfg.To)
	}
	return t, nil
}

func (t *deviceTrigger) Describe() string {
	who := "any device"
	if t.device != "" {
		who = "device " + t.device
	}
	if t.online {
		return "fires when " + who + " comes online"
	}
	return "fires when " + who + " goes offline"
}

func (t *deviceTrigger) Watch(ctx context.Context, fire FireFunc) error {
	if t.events == nil {
		return errors.New("device events are not available")
	}
	return t.events.WatchDevices(ctx, func(e DeviceEvent) {
		if e.Online == t.online && t.matches(e) {
			fire(deviceData(e))
		}
	})
}

func (t *deviceTrigger) Sample() map[string]any {
	return deviceData(DeviceEvent{ID: "device-id", Name: "nas", Hostname: "nas.lan", Online: t.online})
}

// deviceData is what a device trigger tells actions: Device is the id, which
// any action's device field accepts.
func deviceData(e DeviceEvent) map[string]any {
	state := "offline"
	if e.Online {
		state = "online"
	}
	return map[string]any{"Device": e.ID, "Name": e.Name, "Hostname": e.Hostname, "State": state}
}

func (t *deviceTrigger) matches(e DeviceEvent) bool {
	return t.device == "" || t.device == e.ID || t.device == e.Name || strings.EqualFold(t.device, e.Hostname)
}
