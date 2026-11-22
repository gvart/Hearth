// SPDX-License-Identifier: AGPL-3.0-only

package automation

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"unicode/utf8"
)

// Bounds of the host list of a batch firing. Ntfy and Telegram both take
// 4096 bytes at most, title included, so the list leaves room for a title and
// a closing sentence. A line is at most 67 bytes, so at least 50 hosts always
// fit.
const (
	maxHostList   = 3600
	maxHostName   = 16
	maxHostVendor = 12
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
	// Silenced is a host the operator marked known or ignored, or adopted.
	Silenced bool
}

// NetworkEvents tells the network trigger about the hosts discovery finds:
// the hub's device registry.
type NetworkEvents interface {
	// WatchNetwork calls fn with the new hosts of each scan, and with its
	// returned hosts, until ctx is done.
	WatchNetwork(ctx context.Context, fn func([]NetworkEvent)) error
}

// networkTrigger fires when network discovery finds a new host, or one back
// after an absence, unless the operator marked it known or ignored, or
// adopted it.
type networkTrigger struct {
	// event is "new", "returned" or "" for both.
	event string
	// batch fires once for all the hosts of a scan, not once for each.
	batch  bool
	events NetworkEvents
}

func buildNetwork(p Params, deps TriggerDeps) (Trigger, error) {
	var cfg struct {
		Event string `yaml:"event"`
		Batch bool   `yaml:"batch"`
	}
	if err := p.Decode(&cfg); err != nil {
		return nil, err
	}
	switch cfg.Event {
	case "", "new", "returned":
	default:
		return nil, fmt.Errorf("event must be new or returned, not %q", cfg.Event)
	}
	return &networkTrigger{event: cfg.Event, batch: cfg.Batch, events: deps.Network}, nil
}

func (t *networkTrigger) Describe() string {
	var d string
	switch t.event {
	case "new":
		d = "fires when network discovery finds a new host"
	case "returned":
		d = "fires when a host comes back to the network after an hour or more away"
	default:
		d = "fires when network discovery finds a new host, or one back after an hour or more away"
	}
	if t.batch {
		d += ", once per scan"
	}
	return d
}

func (t *networkTrigger) Watch(ctx context.Context, fire FireFunc) error {
	if t.events == nil {
		return errors.New("network discovery events are not available")
	}
	return t.events.WatchNetwork(ctx, func(found []NetworkEvent) {
		var hosts []NetworkEvent
		for _, e := range found {
			if !e.Silenced && (t.event == "" || t.event == eventName(e)) {
				hosts = append(hosts, e)
			}
		}
		if t.batch && len(hosts) > 0 {
			fire(batchData(hosts))
			return
		}
		for _, e := range hosts {
			fire(networkData(e))
		}
	})
}

func (t *networkTrigger) Sample() map[string]any {
	e := NetworkEvent{
		Returned: t.event == "returned", MAC: "3c:2e:f9:12:34:56", IP: "192.168.1.30", Vendor: "Apple", Name: "phone.local",
	}
	if t.batch {
		return batchData([]NetworkEvent{e})
	}
	return networkData(e)
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

// batchData is what a batch firing tells actions: the first host's fields,
// how many hosts the scan found (Count) and a list of them, one per line
// (Hosts), that ends with how many did not fit.
func batchData(hosts []NetworkEvent) map[string]any {
	data := networkData(hosts[0])
	data["Count"] = len(hosts)
	data["Hosts"] = hostList(hosts)
	return data
}

// hostList lists hosts within maxHostList bytes.
func hostList(hosts []NetworkEvent) string {
	var b strings.Builder
	for i, e := range hosts {
		line := hostLine(e)
		// Room for this line and for the last one, which says what is left.
		if b.Len()+len(line)+len("\nand 1024 more") > maxHostList {
			fmt.Fprintf(&b, "and %d more", len(hosts)-i)
			break
		}
		b.WriteString(line)
		if i < len(hosts)-1 {
			b.WriteByte('\n')
		}
	}
	return b.String()
}

// hostLine is one host of a list, with its name and vendor cut short.
func hostLine(e NetworkEvent) string {
	var b strings.Builder
	if e.Name != "" {
		b.WriteString(shorten(e.Name, maxHostName) + " ")
	}
	fmt.Fprintf(&b, "%s (%s", e.IP, e.MAC)
	if networkData(e)["Private"] == true {
		b.WriteString(", private")
	} else if e.Vendor != "" {
		b.WriteString(", " + shorten(e.Vendor, maxHostVendor))
	}
	b.WriteByte(')')
	return b.String()
}

// shorten cuts s to at most limit bytes of valid UTF-8, marking the cut.
func shorten(s string, limit int) string {
	s = strings.ToValidUTF8(s, "")
	if len(s) <= limit {
		return s
	}
	const mark = "…"
	cut := limit - len(mark)
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + mark
}
