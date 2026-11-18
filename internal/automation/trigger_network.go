// SPDX-License-Identifier: AGPL-3.0-only

package automation

import (
	"context"
	"errors"
	"fmt"
	"net"
)

// NetworkEvent is a host network discovery found for the first time, or
// back after an absence.
type NetworkEvent struct {
	// Returned is false for a new host, true for one back after an absence.
	Returned bool
	MAC      string
	IP       string
	Vendor   string
	// Name is the host's mDNS or reverse DNS name, if any.
	Name string
	// Silenced is a host the operator marked known or ignored.
	Silenced bool
}

// NetworkEvents tells the network trigger about the hosts discovery finds:
// the hub's device registry.
type NetworkEvents interface {
	// WatchNetwork calls fn for every new or returned host, until ctx is
	// done.
	WatchNetwork(ctx context.Context, fn func(NetworkEvent)) error
}

// networkTrigger fires when network discovery finds a new host, or one back
// after an absence, unless the operator marked it known or ignored.
type networkTrigger struct {
	// event is "new", "returned" or "" for both.
	event  string
	events NetworkEvents
}

func buildNetwork(p Params, deps TriggerDeps) (Trigger, error) {
	var cfg struct {
		Event string `yaml:"event"`
	}
	if err := p.Decode(&cfg); err != nil {
		return nil, err
	}
	switch cfg.Event {
	case "", "new", "returned":
	default:
		return nil, fmt.Errorf("event must be new or returned, not %q", cfg.Event)
	}
	return &networkTrigger{event: cfg.Event, events: deps.Network}, nil
}

func (t *networkTrigger) Describe() string {
	switch t.event {
	case "new":
		return "fires when network discovery finds a new host"
	case "returned":
		return "fires when a host comes back to the network after an hour or more away"
	}
	return "fires when network discovery finds a new host, or one back after an hour or more away"
}

func (t *networkTrigger) Watch(ctx context.Context, fire FireFunc) error {
	if t.events == nil {
		return errors.New("network discovery events are not available")
	}
	return t.events.WatchNetwork(ctx, func(e NetworkEvent) {
		if !e.Silenced && (t.event == "" || t.event == eventName(e)) {
			fire(networkData(e))
		}
	})
}

func (t *networkTrigger) Sample() map[string]any {
	return networkData(NetworkEvent{
		Returned: t.event == "returned", MAC: "3c:2e:f9:12:34:56", IP: "192.168.1.30", Vendor: "Apple", Name: "phone.local",
	})
}

func eventName(e NetworkEvent) string {
	if e.Returned {
		return "returned"
	}
	return "new"
}

// networkData is what a network trigger tells actions. Private is a
// randomized ("private") MAC, which names no vendor.
func networkData(e NetworkEvent) map[string]any {
	hw, err := net.ParseMAC(e.MAC)
	private := err == nil && len(hw) > 0 && hw[0]&0x02 != 0
	return map[string]any{
		"Event": eventName(e), "MAC": e.MAC, "IP": e.IP, "Vendor": e.Vendor, "Name": e.Name, "Private": private,
	}
}
