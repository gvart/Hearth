// SPDX-License-Identifier: AGPL-3.0-only

package opnsense

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"math"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/gvart/hearth/internal/discovery"
)

const (
	// maxFieldLength caps a name or other text the firewall reports.
	maxFieldLength = 255
	// maxEntries caps the clients, interfaces or table rows of one read.
	maxEntries = 4096
)

// The API endpoints Hearth reads, in the snake_case form OPNsense's ACLs
// match (24.7 and later).
const (
	pathSystemInfo  = "/api/diagnostics/system/system_information"
	pathSystemTime  = "/api/diagnostics/system/system_time"
	pathResources   = "/api/diagnostics/system/system_resources"
	pathFirmware    = "/api/core/firmware/status"
	pathISCLeases   = "/api/dhcpv4/leases/search_lease"
	pathKeaLeases   = "/api/kea/leases4/search"
	pathDnsmasq     = "/api/dnsmasq/leases/search"
	pathARP         = "/api/diagnostics/interface/get_arp"
	pathNDP         = "/api/diagnostics/interface/get_ndp"
	pathTraffic     = "/api/diagnostics/traffic/interface"
	pathRestartDNS  = "/api/unbound/service/restart"
	maxIPv6PerHost  = 8
	leaseSourceISC  = "isc"
	leaseSourceKea  = "kea"
	leaseSourceDnsm = "dnsmasq"
)

// System is what the firewall says of itself.
type System struct {
	// Hostname is the firewall's host and domain name.
	Hostname string `json:"hostname"`
	// Versions are the product, the FreeBSD and the OpenSSL versions, as the
	// dashboard shows them.
	Versions []string `json:"versions"`
	// Uptime and Load are as the firewall formats them: "3 days, 04:12:01"
	// and "0.24, 0.31, 0.29".
	Uptime string `json:"uptime"`
	Load   string `json:"load"`
	// Memory in bytes; 0 when unknown.
	MemTotal int64 `json:"mem_total"`
	MemUsed  int64 `json:"mem_used"`
}

// Firmware is the firmware status as of the firewall's last update check.
// Hearth never starts a check.
type Firmware struct {
	Product string `json:"product"`
	Version string `json:"version"`
	// Latest is the newest version the last check saw.
	Latest string `json:"latest"`
	// Status is none (up to date, or never checked), update, upgrade or error.
	Status  string `json:"status"`
	Message string `json:"message"`
}

// Interface is one assigned interface and its traffic counters since boot.
type Interface struct {
	// Name is the interface's key (lan, wan, opt1); Description its name in
	// the web GUI.
	Name        string `json:"name"`
	Description string `json:"description"`
	Device      string `json:"device"`
	RxBytes     int64  `json:"rx_bytes"`
	TxBytes     int64  `json:"tx_bytes"`
	RxPackets   int64  `json:"rx_packets"`
	TxPackets   int64  `json:"tx_packets"`
	RxErrors    int64  `json:"rx_errors"`
	TxErrors    int64  `json:"tx_errors"`
}

// Client is a host the firewall knows: from its DHCP leases, its ARP or NDP
// table, or several, by MAC.
type Client struct {
	MAC string `json:"mac"`
	// IP is its IPv4 address; IPv6 the addresses the NDP table has for it.
	IP        string   `json:"ip"`
	IPv6      []string `json:"ipv6"`
	Hostname  string   `json:"hostname"`
	Vendor    string   `json:"vendor"`
	Interface string   `json:"interface"`
	// Lease says a DHCP server of the firewall leased IP to it: LeaseSource
	// is isc, kea or dnsmasq. Static is a reservation. LeaseEnds is when the
	// lease ends, in Unix seconds; 0 when the server does not say.
	Lease       bool   `json:"lease"`
	LeaseSource string `json:"lease_source"`
	Static      bool   `json:"static"`
	LeaseEnds   int64  `json:"lease_ends"`
	// ARP says it is in the ARP table right now, not expired.
	ARP bool `json:"arp"`
}

// reading is one read of a firewall.
type reading struct {
	system     System
	firmware   Firmware
	interfaces []Interface
	clients    []Client
	// missing names what could not be read, and why: an endpoint the key's
	// privileges do not allow, or one the firewall does not have.
	missing []string
}

// num reads a JSON number or numeric string: OPNsense sends counters as
// strings. What is no finite number counts as 0: one odd field must not fail
// the whole read.
type num float64

// UnmarshalJSON implements json.Unmarshaler.
func (n *num) UnmarshalJSON(b []byte) error {
	var f float64
	if err := json.Unmarshal(b, &f); err != nil {
		var s string
		if json.Unmarshal(b, &s) != nil {
			*n = 0
			return nil
		}
		if f, err = strconv.ParseFloat(strings.TrimSpace(s), 64); err != nil {
			*n = 0
			return nil //nolint:nilerr // see above
		}
	}
	if math.IsNaN(f) || math.IsInf(f, 0) || f > math.MaxInt64 || f < math.MinInt64 {
		*n = 0
		return nil
	}
	*n = num(f)
	return nil
}

// flag reads a JSON boolean, or anything else as false.
type flag bool

// UnmarshalJSON implements json.Unmarshaler.
func (f *flag) UnmarshalJSON(b []byte) error {
	var v bool
	*f = flag(json.Unmarshal(b, &v) == nil && v)
	return nil
}

type systemInfoReply struct {
	Name     string   `json:"name"`
	Versions []string `json:"versions"`
}

type systemTimeReply struct {
	Uptime  string `json:"uptime"`
	LoadAvg string `json:"loadavg"`
}

type resourcesReply struct {
	Memory struct {
		Total num `json:"total"`
		Used  num `json:"used"`
	} `json:"memory"`
}

type firmwareReply struct {
	Status    string `json:"status"`
	StatusMsg string `json:"status_msg"`
	Product   struct {
		Name    string `json:"product_name"`
		Version string `json:"product_version"`
		Latest  string `json:"product_latest"`
	} `json:"product"`
}

// leaseRow is a row of any of the three lease searches: ISC names the MAC
// mac and its type type, Kea and dnsmasq hwaddr and lease_type.
type leaseRow struct {
	Address   string `json:"address"`
	MAC       string `json:"mac"`
	HWAddr    string `json:"hwaddr"`
	Hostname  string `json:"hostname"`
	Type      string `json:"type"`
	LeaseType string `json:"lease_type"`
	IfDescr   string `json:"if_descr"`
	// Kea and dnsmasq: when the lease ends, in Unix seconds.
	Expire num `json:"expire"`
	// ISC: active, expired, ...; Kea: 0 for a default (active) lease.
	State json.RawMessage `json:"state"`
}

type leasesReply struct {
	Rows []leaseRow `json:"rows"`
}

type arpRow struct {
	MAC          string `json:"mac"`
	IP           string `json:"ip"`
	Expired      flag   `json:"expired"`
	Permanent    flag   `json:"permanent"`
	Manufacturer string `json:"manufacturer"`
	Hostname     string `json:"hostname"`
	IntfDescr    string `json:"intf_description"`
}

type trafficReply struct {
	Interfaces map[string]struct {
		Name      string `json:"name"`
		Device    string `json:"device"`
		RxBytes   num    `json:"bytes received"`
		TxBytes   num    `json:"bytes transmitted"`
		RxPackets num    `json:"packets received"`
		TxPackets num    `json:"packets transmitted"`
		RxErrors  num    `json:"input errors"`
		TxErrors  num    `json:"output errors"`
	} `json:"interfaces"`
}

// optional reports whether err is an endpoint the firewall refused or does
// not have, which leaves a part of the read out instead of failing it.
func optional(err error) bool { return errors.Is(err, errDenied) || errors.Is(err, errMissing) }

// read reads the firewall once. The system info is required; everything
// else comes from a privilege the key may lack or a plugin the firewall may
// not have, and is listed as missing instead.
func (c *client) read(ctx context.Context) (reading, error) {
	var r reading
	var info systemInfoReply
	if err := c.get(ctx, pathSystemInfo, &info); err != nil {
		return reading{}, err
	}
	r.system.Hostname = clip(info.Name)
	for _, v := range info.Versions[:min(len(info.Versions), 8)] {
		r.system.Versions = append(r.system.Versions, clip(v))
	}
	// part reads one optional part, and fails the read only on what is no
	// refusal: the firewall gone, an answer of the wrong form.
	part := func(what, path string, out any) (bool, error) {
		err := c.get(ctx, path, out)
		if optional(err) {
			r.missing = append(r.missing, what+": "+errors.Unwrap(err).Error())
			return false, nil
		}
		return err == nil, err
	}

	var tm systemTimeReply
	if ok, err := part("uptime and load", pathSystemTime, &tm); err != nil {
		return reading{}, err
	} else if ok {
		r.system.Uptime, r.system.Load = clip(tm.Uptime), clip(tm.LoadAvg)
	}
	var res resourcesReply
	if ok, err := part("memory", pathResources, &res); err != nil {
		return reading{}, err
	} else if ok {
		r.system.MemTotal, r.system.MemUsed = max(int64(res.Memory.Total), 0), max(int64(res.Memory.Used), 0)
	}
	var fw firmwareReply
	if ok, err := part("firmware status", pathFirmware, &fw); err != nil {
		return reading{}, err
	} else if ok {
		r.firmware = Firmware{
			Product: clip(fw.Product.Name), Version: clip(fw.Product.Version), Latest: clip(fw.Product.Latest),
			Status: clip(fw.Status), Message: clip(fw.StatusMsg),
		}
	}
	var traffic trafficReply
	if ok, err := part("interfaces", pathTraffic, &traffic); err != nil {
		return reading{}, err
	} else if ok {
		r.interfaces = interfaces(traffic)
	}

	byMAC := map[string]*Client{}
	get := func(mac string) *Client {
		cl := byMAC[mac]
		if cl == nil && len(byMAC) < maxEntries {
			cl = &Client{MAC: mac, IPv6: []string{}}
			byMAC[mac] = cl
		}
		return cl
	}
	if err := c.readLeases(ctx, &r, get); err != nil {
		return reading{}, err
	}

	var arp []arpRow
	ok, err := part("ARP table", pathARP, &arp)
	if err != nil {
		return reading{}, err
	}
	// The firewall's own interfaces: permanent ARP entries. Their NDP
	// entries are no clients either.
	own := map[string]bool{}
	for _, a := range arp[:min(len(arp), maxEntries)] {
		mac, macOK := hostMAC(a.MAC)
		ip, err := netip.ParseAddr(a.IP)
		if !ok || !macOK || err != nil || !ip.Is4() {
			continue
		}
		if a.Permanent {
			own[mac] = true
			continue
		}
		if a.Expired {
			continue
		}
		if cl := get(mac); cl != nil {
			cl.ARP = true
			if cl.IP == "" {
				cl.IP = ip.String()
			}
			if cl.Hostname == "" {
				cl.Hostname = clip(strings.TrimSuffix(strings.TrimSpace(a.Hostname), "."))
			}
			cl.Vendor = clip(a.Manufacturer)
			if cl.Interface == "" {
				cl.Interface = clip(a.IntfDescr)
			}
		}
	}

	var ndp []arpRow
	if ok, err = part("NDP table", pathNDP, &ndp); err != nil {
		return reading{}, err
	}
	for _, n := range ndp[:min(len(ndp), maxEntries)] {
		mac, macOK := hostMAC(n.MAC)
		addr, _, _ := strings.Cut(n.IP, "%") // a link-local address names its interface
		ip, err := netip.ParseAddr(addr)
		if !ok || !macOK || err != nil || !ip.Is6() || ip.Is4In6() || own[mac] {
			continue
		}
		if cl := get(mac); cl != nil && len(cl.IPv6) < maxIPv6PerHost && !slices.Contains(cl.IPv6, ip.String()) {
			cl.IPv6 = append(cl.IPv6, ip.String())
			if cl.Vendor == "" {
				cl.Vendor = clip(n.Manufacturer)
			}
			if cl.Interface == "" {
				cl.Interface = clip(n.IntfDescr)
			}
		}
	}

	r.clients = make([]Client, 0, len(byMAC))
	for _, cl := range byMAC {
		slices.Sort(cl.IPv6)
		r.clients = append(r.clients, *cl)
	}
	slices.SortFunc(r.clients, func(a, b Client) int {
		return cmp.Or(cmp.Compare(noName(a), noName(b)), cmp.Compare(a.Hostname, b.Hostname), cmp.Compare(a.MAC, b.MAC))
	})
	return r, nil
}

// readLeases reads the leases of every DHCP server OPNsense has: ISC dhcpd
// (a plugin since 25.7), Kea and dnsmasq (the default of new installs). A
// firewall runs one or two of them, and a key needs the privilege of only
// those: while one is read, the others' refusals are not listed as missing.
func (c *client) readLeases(ctx context.Context, r *reading, get func(string) *Client) error {
	var refused []string
	read := 0
	for _, src := range []struct{ name, path string }{
		{leaseSourceISC, pathISCLeases}, {leaseSourceKea, pathKeaLeases}, {leaseSourceDnsm, pathDnsmasq},
	} {
		var reply leasesReply
		err := c.get(ctx, src.path, &reply)
		if optional(err) {
			if errors.Is(err, errDenied) {
				refused = append(refused, "DHCP leases ("+src.name+"): "+errDenied.Error())
			}
			continue
		}
		if err != nil {
			return err
		}
		read++
		for _, l := range reply.Rows[:min(len(reply.Rows), maxEntries)] {
			mac, ok := hostMAC(cmp.Or(l.MAC, l.HWAddr))
			ip, err := netip.ParseAddr(l.Address)
			if !ok || err != nil || !ip.Is4() || !activeLease(src.name, l.State) {
				continue
			}
			cl := get(mac)
			if cl == nil || cl.Lease {
				continue // a host leased by two servers keeps the first
			}
			cl.IP, cl.Lease, cl.LeaseSource = ip.String(), true, src.name
			cl.Static = cmp.Or(l.Type, l.LeaseType) == "static"
			if src.name != leaseSourceISC && l.Expire > 0 {
				cl.LeaseEnds = int64(l.Expire)
			}
			if name := clip(strings.TrimSuffix(strings.TrimSpace(l.Hostname), ".")); name != "*" {
				cl.Hostname = name
			}
			cl.Interface = clip(l.IfDescr)
		}
	}
	switch {
	case read == 0 && len(refused) == 0:
		r.missing = append(r.missing, "DHCP leases: "+errMissing.Error())
	case read == 0:
		r.missing = append(r.missing, refused...)
	}
	return nil
}

// activeLease reports whether a lease row is a lease in use. ISC's search
// lists active leases only unless asked; Kea's state 0 is the default
// (active) state; dnsmasq lists only what it holds.
func activeLease(source string, state json.RawMessage) bool {
	switch source {
	case leaseSourceISC:
		var s string
		return len(state) == 0 || (json.Unmarshal(state, &s) == nil && (s == "" || s == "active"))
	case leaseSourceKea:
		var n num
		return len(state) == 0 || (n.UnmarshalJSON(state) == nil && n == 0)
	}
	return true
}

// noName sorts the clients without a hostname last.
func noName(c Client) int {
	if c.Hostname == "" {
		return 1
	}
	return 0
}

// interfaces lists the assigned interfaces by key.
func interfaces(t trafficReply) []Interface {
	out := []Interface{}
	for name, d := range t.Interfaces {
		if !validName(name) || len(out) == maxEntries {
			continue
		}
		out = append(out, Interface{
			Name: clip(name), Description: clip(d.Name), Device: clip(d.Device),
			RxBytes: max(int64(d.RxBytes), 0), TxBytes: max(int64(d.TxBytes), 0),
			RxPackets: max(int64(d.RxPackets), 0), TxPackets: max(int64(d.TxPackets), 0),
			RxErrors: max(int64(d.RxErrors), 0), TxErrors: max(int64(d.TxErrors), 0),
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
