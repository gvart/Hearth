// SPDX-License-Identifier: AGPL-3.0-only

package unifi

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"math"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"

	"github.com/gvart/hearth/internal/discovery"
)

const (
	// maxFieldLength caps a name or other text the controller reports.
	maxFieldLength = 255
	// maxEntries caps the devices or clients of one read.
	maxEntries = 4096
)

// Device kinds.
const (
	DeviceGateway     = "gateway"
	DeviceSwitch      = "switch"
	DeviceAccessPoint = "access_point"
	DeviceOther       = "other"
)

// Device is a UniFi device the site has adopted.
type Device struct {
	MAC  string `json:"mac"`
	IP   string `json:"ip"`
	Name string `json:"name"`
	// Model is UniFi's model code, such as U6LR or UDMPRO.
	Model string `json:"model"`
	// Kind is gateway, switch, access_point or other; Type is UniFi's own
	// (ugw, udm, uxg, usw, uap, ...).
	Kind    string `json:"kind"`
	Type    string `json:"type"`
	Version string `json:"version"`
	// State is connected, disconnected, upgrading, ... (see deviceStates).
	State string `json:"state"`
	// Uptime is in seconds.
	Uptime  int64 `json:"uptime"`
	Clients int   `json:"clients"`
}

// Client is a host connected to the site right now.
type Client struct {
	MAC      string `json:"mac"`
	IP       string `json:"ip"`
	Hostname string `json:"hostname"`
	Vendor   string `json:"vendor,omitempty"`
	Wired    bool   `json:"wired"`
	// Uplink names the access point or switch it is connected to, and
	// UplinkMAC is that device's MAC; Port is the switch port of a wired
	// client, 0 if the controller does not say.
	Uplink    string `json:"uplink"`
	UplinkMAC string `json:"uplink_mac"`
	Port      int    `json:"port,omitempty"`
	// SSID and Signal (dBm) are a wireless client's.
	SSID   string `json:"ssid,omitempty"`
	Signal int    `json:"signal,omitempty"`
	// LastSeen is when the controller last heard of it, in Unix seconds.
	LastSeen int64 `json:"last_seen"`
}

// Health is one subsystem of the site: wan, www (the internet), lan, wlan
// or vpn.
type Health struct {
	Subsystem string `json:"subsystem"`
	// Status is ok, warning, error or unknown, as the controller says.
	Status string `json:"status"`
	WANIP  string `json:"wan_ip,omitempty"`
	ISP    string `json:"isp,omitempty"`
	// LatencyMS is the www latency.
	LatencyMS int64 `json:"latency_ms,omitempty"`
	// RxRate and TxRate are the wan throughput, in bytes per second.
	RxRate int64 `json:"rx_rate,omitempty"`
	TxRate int64 `json:"tx_rate,omitempty"`
	Users  int   `json:"users,omitempty"`
}

// reading is one read of a controller's site.
type reading struct {
	devices []Device
	clients []Client
	health  []Health
	// missing names what could not be read, and why: an endpoint the
	// account may not use.
	missing []string
}

// num reads a JSON number that may be out of range, not finite, or not a
// number at all: one odd field must not fail the whole read.
type num float64

// UnmarshalJSON implements json.Unmarshaler.
func (n *num) UnmarshalJSON(b []byte) error {
	var f float64
	if err := json.Unmarshal(b, &f); err != nil || math.IsNaN(f) || math.IsInf(f, 0) {
		*n = 0
		return nil //nolint:nilerr // see above
	}
	*n = num(f)
	return nil
}

type deviceReply struct {
	MAC     string `json:"mac"`
	IP      string `json:"ip"`
	Name    string `json:"name"`
	Model   string `json:"model"`
	Type    string `json:"type"`
	Version string `json:"version"`
	State   num    `json:"state"`
	Uptime  num    `json:"uptime"`
	NumSta  num    `json:"num_sta"`
}

type staReply struct {
	MAC      string `json:"mac"`
	IP       string `json:"ip"`
	Hostname string `json:"hostname"`
	Name     string `json:"name"`
	OUI      string `json:"oui"`
	IsWired  bool   `json:"is_wired"`
	APMAC    string `json:"ap_mac"`
	ESSID    string `json:"essid"`
	Signal   num    `json:"signal"`
	SwMAC    string `json:"sw_mac"`
	SwPort   num    `json:"sw_port"`
	LastSeen num    `json:"last_seen"`
}

type healthReply struct {
	Subsystem string `json:"subsystem"`
	Status    string `json:"status"`
	WANIP     string `json:"wan_ip"`
	ISP       string `json:"isp_name"`
	Latency   num    `json:"latency"`
	RxRate    num    `json:"rx_bytes-r"`
	TxRate    num    `json:"tx_bytes-r"`
	NumUser   num    `json:"num_user"`
}

// deviceStates names the controller's device states.
var deviceStates = map[int]string{
	0: "disconnected", 1: "connected", 2: "pending adoption", 4: "upgrading", 5: "provisioning",
	6: "heartbeat missed", 7: "adopting", 9: "adoption failed", 10: "isolated", 11: "isolated",
}

func deviceKind(typ string) string {
	switch typ {
	case "ugw", "udm", "uxg":
		return DeviceGateway
	case "usw":
		return DeviceSwitch
	case "uap":
		return DeviceAccessPoint
	}
	return DeviceOther
}

// read reads the site once. The devices are required; the clients and the
// health are each listed as missing when the account may not read them.
func (c *client) read(ctx context.Context) (reading, error) {
	var r reading
	b := c.batch()
	var devs []deviceReply
	if err := b.call(ctx, http.MethodGet, "/stat/device", nil, &devs); err != nil {
		return reading{}, err
	}
	optional := func(what string, err error) error {
		if errors.Is(err, errForbidden) || errors.Is(err, errMissing) {
			r.missing = append(r.missing, what+": "+err.Error())
			return nil
		}
		return err
	}
	var stas []staReply
	if err := optional("clients", b.call(ctx, http.MethodGet, "/stat/sta", nil, &stas)); err != nil {
		return reading{}, err
	}
	var health []healthReply
	if err := optional("health", b.call(ctx, http.MethodGet, "/stat/health", nil, &health)); err != nil {
		return reading{}, err
	}

	byMAC := map[string]string{}
	for _, d := range devs[:min(len(devs), maxEntries)] {
		mac, ok := hostMAC(d.MAC)
		if !ok {
			continue
		}
		state, ok := deviceStates[int(d.State)]
		if !ok {
			state = "unknown"
		}
		dev := Device{
			MAC: mac, IP: ipv4(d.IP), Name: clip(d.Name), Model: clip(d.Model), Type: clip(d.Type),
			Kind: deviceKind(d.Type), Version: clip(d.Version), State: state,
			Uptime: max(int64(d.Uptime), 0), Clients: max(int(d.NumSta), 0),
		}
		if dev.Name == "" {
			dev.Name = dev.Model
		}
		byMAC[mac] = dev.Name
		r.devices = append(r.devices, dev)
	}
	slices.SortFunc(r.devices, func(a, b Device) int {
		return cmp.Or(cmp.Compare(kindOrder(a.Kind), kindOrder(b.Kind)), cmp.Compare(a.Name, b.Name), cmp.Compare(a.MAC, b.MAC))
	})

	seen := map[string]bool{}
	for _, s := range stas[:min(len(stas), maxEntries)] {
		mac, ok := hostMAC(s.MAC)
		if !ok || seen[mac] {
			continue
		}
		seen[mac] = true
		cl := Client{
			MAC: mac, IP: ipv4(s.IP), Hostname: clip(strings.TrimSpace(cmp.Or(s.Name, s.Hostname))), Vendor: clip(s.OUI),
			Wired: s.IsWired, LastSeen: max(int64(s.LastSeen), 0),
		}
		uplink := s.APMAC
		if s.IsWired {
			uplink = s.SwMAC
			cl.Port = max(int(s.SwPort), 0)
		} else {
			cl.SSID, cl.Signal = clip(s.ESSID), int(max(min(int64(s.Signal), 0), -200))
		}
		if m, ok := hostMAC(uplink); ok {
			cl.UplinkMAC, cl.Uplink = m, cmp.Or(byMAC[m], m)
		}
		r.clients = append(r.clients, cl)
	}
	slices.SortFunc(r.clients, func(a, b Client) int {
		return cmp.Or(cmp.Compare(noName(a), noName(b)), cmp.Compare(a.Hostname, b.Hostname), cmp.Compare(a.MAC, b.MAC))
	})

	for _, h := range health[:min(len(health), 16)] {
		if !validName(h.Subsystem) {
			continue
		}
		r.health = append(r.health, Health{
			Subsystem: clip(h.Subsystem), Status: clip(h.Status), WANIP: ipv4(h.WANIP), ISP: clip(h.ISP),
			LatencyMS: max(int64(h.Latency), 0), RxRate: max(int64(h.RxRate), 0), TxRate: max(int64(h.TxRate), 0),
			Users: max(int(h.NumUser), 0),
		})
	}
	return r, nil
}

// kindOrder lists gateways first, then switches, then access points.
func kindOrder(kind string) int {
	switch kind {
	case DeviceGateway:
		return 0
	case DeviceSwitch:
		return 1
	case DeviceAccessPoint:
		return 2
	}
	return 3
}

// noName sorts the clients without a hostname last.
func noName(c Client) int {
	if c.Hostname == "" {
		return 1
	}
	return 0
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

// ipv4 returns s if it is an IPv4 address, else "".
func ipv4(s string) string {
	ip, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil || !ip.Is4() {
		return ""
	}
	return ip.String()
}

func clip(s string) string { return discovery.ClipText(s, maxFieldLength) }
