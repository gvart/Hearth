// SPDX-License-Identifier: AGPL-3.0-only

package discovery

import (
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
)

// Auto is the --discover-subnet value that scans the hub's own LANs: the
// IPv4 subnet of every up, private-addressed interface, narrowed to the /24
// around the hub's address when it is wider.
const Auto = "auto"

// MaxHosts caps the addresses one scan sweeps (a /22). A wider sweep would
// be noisy and could overflow a Linux host's neighbour table (gc_thresh3
// defaults to 1024 entries).
const MaxHosts = 1024

// ParseSubnets parses --discover-subnet values: IPv4 CIDRs, such as
// 192.168.2.0/24, or Auto. It refuses IPv6 (a /64 cannot be swept), host
// routes and anything wider than MaxHosts in all.
func ParseSubnets(vals []string) (subnets []netip.Prefix, auto bool, err error) {
	total := 0
	for _, v := range vals {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if strings.EqualFold(v, Auto) {
			auto = true
			continue
		}
		p, err := netip.ParsePrefix(v)
		if err != nil {
			return nil, false, fmt.Errorf("discover subnet %q: %w", v, err)
		}
		if !p.Addr().Is4() {
			return nil, false, fmt.Errorf("discover subnet %s: only IPv4 subnets can be swept", v)
		}
		if p.Bits() > 30 {
			return nil, false, fmt.Errorf("discover subnet %s: narrower than /30", v)
		}
		p = p.Masked()
		if slices.Contains(subnets, p) {
			continue
		}
		total += 1<<(32-p.Bits()) - 2
		if total > MaxHosts {
			return nil, false, fmt.Errorf("discover subnet %s: the subnets add up to more than %d addresses", v, MaxHosts)
		}
		subnets = append(subnets, p)
	}
	return subnets, auto, nil
}

// ParseSubnetsFrom parses --discover-subnet values as ParseSubnets does,
// where a value may also name the device to scan it from: CIDR@device, such
// as 10.0.5.0/24@nas, has the agent of device (a device id, name or
// hostname) sweep the subnet, for a subnet the hub is not attached to. It
// returns the hub's subnets and auto as ParseSubnets does, and the subnets of
// each device; MaxHosts applies to each scanner on its own. Auto names the
// hub's LANs and takes no device.
func ParseSubnetsFrom(vals []string) (subnets []netip.Prefix, auto bool, from map[string][]netip.Prefix, err error) {
	var hub []string
	byDevice := map[string][]string{}
	for _, v := range vals {
		cidr, device, ok := strings.Cut(v, "@")
		if !ok {
			hub = append(hub, v)
			continue
		}
		cidr, device = strings.TrimSpace(cidr), strings.TrimSpace(device)
		if device == "" || strings.EqualFold(cidr, Auto) {
			return nil, false, nil, fmt.Errorf("discover subnet %q: want CIDR@device", v)
		}
		byDevice[device] = append(byDevice[device], cidr)
	}
	if subnets, auto, err = ParseSubnets(hub); err != nil {
		return nil, false, nil, err
	}
	for device, vals := range byDevice {
		p, _, err := ParseSubnets(vals)
		if err != nil {
			return nil, false, nil, fmt.Errorf("from %s: %w", device, err)
		}
		if from == nil {
			from = map[string][]netip.Prefix{}
		}
		from[device] = p
	}
	return subnets, auto, from, nil
}

// hostsOf returns the host addresses of an IPv4 prefix no wider than
// MaxHosts: every address but the network and broadcast ones.
func hostsOf(p netip.Prefix) []netip.Addr {
	var out []netip.Addr
	first := p.Masked().Addr()
	for a := first.Next(); p.Contains(a) && p.Contains(a.Next()); a = a.Next() {
		out = append(out, a)
	}
	return out
}

// localNet is an IPv4 address of this host and its subnet.
type localNet struct {
	iface  net.Interface
	addr   netip.Addr
	prefix netip.Prefix
}

// localNets returns this host's IPv4 addresses on up, non-loopback
// interfaces.
func localNets() ([]localNet, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("list interfaces: %w", err)
	}
	var out []localNet
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip, ok := netip.AddrFromSlice(ipn.IP)
			if !ok {
				continue
			}
			ip = ip.Unmap()
			ones, _ := ipn.Mask.Size()
			if !ip.Is4() {
				continue
			}
			out = append(out, localNet{iface: ifc, addr: ip, prefix: netip.PrefixFrom(ip, ones).Masked()})
		}
	}
	return out, nil
}

// autoSubnets is what Auto stands for on a host with nets: the subnet of
// each private address, narrowed to its /24 when wider.
func autoSubnets(nets []localNet) []netip.Prefix {
	var out []netip.Prefix
	for _, n := range nets {
		if !n.addr.IsPrivate() {
			continue
		}
		p := n.prefix
		if p.Bits() < 24 {
			p = netip.PrefixFrom(n.addr, 24).Masked()
		}
		if p.Bits() <= 30 && !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	return out
}
