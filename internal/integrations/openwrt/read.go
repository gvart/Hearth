// SPDX-License-Identifier: AGPL-3.0-only

package openwrt

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"math"
	"net"
	"net/netip"
	"slices"
	"strings"

	"github.com/gvart/hearth/internal/discovery"
)

const (
	// maxFieldLength caps a name or other text the router reports.
	maxFieldLength = 255
	// maxEntries caps the clients, interfaces or radios of one read.
	maxEntries = 4096
)

// System is what the router says of itself.
type System struct {
	Hostname string `json:"hostname"`
	Model    string `json:"model"`
	Board    string `json:"board_name"`
	Kernel   string `json:"kernel"`
	// Release is the OpenWrt release, such as "OpenWrt 24.10.0 r28427-6df0e3d02a".
	Release string `json:"release"`
	Target  string `json:"target"`
	// Uptime is in seconds.
	Uptime int64 `json:"uptime"`
	// Load is the 1, 5 and 15 minute load averages.
	Load [3]float64 `json:"load"`
	// Memory in bytes.
	MemTotal     int64 `json:"mem_total"`
	MemAvailable int64 `json:"mem_available"`
}

// Interface is one network device and its traffic counters.
type Interface struct {
	Name      string `json:"name"`
	Type      string `json:"type"`
	Up        bool   `json:"up"`
	Carrier   bool   `json:"carrier"`
	MAC       string `json:"mac"`
	RxBytes   int64  `json:"rx_bytes"`
	TxBytes   int64  `json:"tx_bytes"`
	RxPackets int64  `json:"rx_packets"`
	TxPackets int64  `json:"tx_packets"`
	RxErrors  int64  `json:"rx_errors"`
	TxErrors  int64  `json:"tx_errors"`
}

// Client is a host the router knows: from its DHCP leases, its wireless
// associations or both, by MAC.
type Client struct {
	MAC      string `json:"mac"`
	IP       string `json:"ip"`
	Hostname string `json:"hostname"`
	// Lease says the router's DHCP server leased IP to it; LeaseExpires is
	// how many seconds the lease has left, 0 for a static one.
	Lease        bool  `json:"lease"`
	LeaseExpires int64 `json:"lease_expires"`
	// Wireless says the client is associated to Radio right now.
	Wireless bool   `json:"wireless"`
	Radio    string `json:"radio,omitempty"`
	// Signal is in dBm; Inactive is how long since the radio heard it, in
	// milliseconds.
	Signal   int   `json:"signal,omitempty"`
	Inactive int64 `json:"inactive,omitempty"`
}

// reading is one read of a router.
type reading struct {
	system     System
	interfaces []Interface
	clients    []Client
	// missing names what could not be read, and why: a package that is not
	// installed or a call the user's ACL does not allow.
	missing []string
}

// num reads a JSON number that may be out of range or not finite.
type num float64

// UnmarshalJSON implements json.Unmarshaler. What is no finite number counts
// as 0: one odd field must not fail the whole read.
func (n *num) UnmarshalJSON(b []byte) error {
	var f float64
	if err := json.Unmarshal(b, &f); err != nil || math.IsNaN(f) || math.IsInf(f, 0) {
		*n = 0
		return nil //nolint:nilerr // see above
	}
	*n = num(f)
	return nil
}

// signed32 is a value libubus sends as a u32 that is a negative int32 (a
// signal in dBm).
func signed32(n num) int {
	v := int64(n)
	if v > math.MaxInt32 {
		v -= 1 << 32
	}
	return int(max(min(v, 0), -200))
}

type boardReply struct {
	Kernel   string `json:"kernel"`
	Hostname string `json:"hostname"`
	Model    string `json:"model"`
	Board    string `json:"board_name"`
	Release  struct {
		Description string `json:"description"`
		Version     string `json:"version"`
		Target      string `json:"target"`
	} `json:"release"`
}

type infoReply struct {
	Uptime num    `json:"uptime"`
	Load   [3]num `json:"load"`
	Memory struct {
		Total     num `json:"total"`
		Free      num `json:"free"`
		Available num `json:"available"`
	} `json:"memory"`
}

type deviceStatus struct {
	Type       string `json:"type"`
	Up         bool   `json:"up"`
	Carrier    bool   `json:"carrier"`
	MAC        string `json:"macaddr"`
	Statistics struct {
		RxBytes   num `json:"rx_bytes"`
		TxBytes   num `json:"tx_bytes"`
		RxPackets num `json:"rx_packets"`
		TxPackets num `json:"tx_packets"`
		RxErrors  num `json:"rx_errors"`
		TxErrors  num `json:"tx_errors"`
	} `json:"statistics"`
}

type leasesReply struct {
	Leases []struct {
		Expires  num    `json:"expires"`
		Hostname string `json:"hostname"`
		MAC      string `json:"macaddr"`
		IP       string `json:"ipaddr"`
	} `json:"dhcp_leases"`
}

type assocReply struct {
	Results []struct {
		MAC      string `json:"mac"`
		Signal   num    `json:"signal"`
		Inactive num    `json:"inactive"`
	} `json:"results"`
}

// read reads the router once. The system info is required; the interfaces,
// leases and wireless clients each come from a package or an ACL grant the
// router may not have, and are listed as missing instead.
func (c *client) read(ctx context.Context) (reading, error) {
	var r reading
	b := c.batch()
	var board boardReply
	if err := b.call(ctx, "system", "board", nil, &board); err != nil {
		return reading{}, err
	}
	var info infoReply
	if err := b.call(ctx, "system", "info", nil, &info); err != nil {
		return reading{}, err
	}
	r.system = System{
		Hostname: clip(board.Hostname), Model: clip(board.Model), Board: clip(board.Board),
		Kernel: clip(board.Kernel), Release: clip(strings.TrimSpace(board.Release.Description)),
		Target: clip(board.Release.Target), Uptime: int64(info.Uptime),
		MemTotal: int64(info.Memory.Total), MemAvailable: int64(info.Memory.Available),
	}
	if r.system.MemAvailable == 0 {
		r.system.MemAvailable = int64(info.Memory.Free)
	}
	for i, l := range info.Load {
		// The kernel's fixed point: 65536 is a load of 1.
		r.system.Load[i] = math.Round(float64(l)/65536*100) / 100
	}
	optional := func(what string, err error) error {
		if errors.Is(err, errDenied) || errors.Is(err, errMissing) {
			r.missing = append(r.missing, what+": "+err.Error())
			return nil
		}
		return err
	}

	var devs map[string]deviceStatus
	err := b.call(ctx, "network.device", "status", nil, &devs)
	if err = optional("interfaces", err); err != nil {
		return reading{}, err
	}
	r.interfaces = interfaces(devs)

	byMAC := map[string]*Client{}
	get := func(mac string) *Client {
		cl := byMAC[mac]
		if cl == nil && len(byMAC) < maxEntries {
			cl = &Client{MAC: mac}
			byMAC[mac] = cl
		}
		return cl
	}
	var leases leasesReply
	err = b.call(ctx, "luci-rpc", "getDHCPLeases", map[string]any{"family": 4}, &leases)
	if err = optional("DHCP leases", err); err != nil {
		return reading{}, err
	}
	for _, l := range leases.Leases {
		mac, ok := hostMAC(l.MAC)
		ip, err := netip.ParseAddr(l.IP)
		if !ok || err != nil || !ip.Is4() {
			continue
		}
		if cl := get(mac); cl != nil {
			cl.IP, cl.Lease, cl.LeaseExpires = ip.String(), true, max(int64(l.Expires), 0)
			if name := clip(strings.TrimSpace(l.Hostname)); name != "*" {
				cl.Hostname = name
			}
		}
	}

	var radios struct {
		Devices []string `json:"devices"`
	}
	err = b.call(ctx, "iwinfo", "devices", nil, &radios)
	if err = optional("wireless clients", err); err != nil {
		return reading{}, err
	}
	for _, radio := range radios.Devices[:min(len(radios.Devices), 64)] {
		if !validName(radio) {
			continue
		}
		var assoc assocReply
		err := b.call(ctx, "iwinfo", "assoclist", map[string]any{"device": radio}, &assoc)
		if err = optional("wireless clients of "+radio, err); err != nil {
			return reading{}, err
		}
		for _, a := range assoc.Results {
			mac, ok := hostMAC(a.MAC)
			if !ok {
				continue
			}
			if cl := get(mac); cl != nil {
				cl.Wireless, cl.Radio, cl.Signal, cl.Inactive = true, radio, signed32(a.Signal), max(int64(a.Inactive), 0)
			}
		}
	}
	r.clients = make([]Client, 0, len(byMAC))
	for _, cl := range byMAC {
		r.clients = append(r.clients, *cl)
	}
	slices.SortFunc(r.clients, func(a, b Client) int {
		return cmp.Or(cmp.Compare(noName(a), noName(b)), cmp.Compare(a.Hostname, b.Hostname), cmp.Compare(a.MAC, b.MAC))
	})
	return r, nil
}

// noName sorts the clients without a hostname last.
func noName(c Client) int {
	if c.Hostname == "" {
		return 1
	}
	return 0
}

// interfaces lists the network devices by name, leaving out loopback.
func interfaces(devs map[string]deviceStatus) []Interface {
	out := []Interface{}
	for name, d := range devs {
		if name == "lo" || !validName(name) || len(out) == maxEntries {
			continue
		}
		mac, _ := hostMAC(d.MAC)
		s := d.Statistics
		out = append(out, Interface{
			Name: name, Type: clip(d.Type), Up: d.Up, Carrier: d.Carrier, MAC: mac,
			RxBytes: int64(s.RxBytes), TxBytes: int64(s.TxBytes), RxPackets: int64(s.RxPackets),
			TxPackets: int64(s.TxPackets), RxErrors: int64(s.RxErrors), TxErrors: int64(s.TxErrors),
		})
	}
	slices.SortFunc(out, func(a, b Interface) int { return cmp.Compare(a.Name, b.Name) })
	return out
}

// hostMAC returns mac lower-case and colon-separated if it is a 6-byte
// unicast address.
func hostMAC(mac string) (string, bool) {
	hw, err := net.ParseMAC(strings.TrimSpace(mac))
	if err != nil || len(hw) != 6 || hw[0]&1 == 1 {
		return "", false
	}
	return hw.String(), true
}

func clip(s string) string { return discovery.ClipText(s, maxFieldLength) }
