// SPDX-License-Identifier: AGPL-3.0-only

package discovery

import (
	"fmt"
	"net"
	"net/netip"
	"syscall"

	"golang.org/x/net/route"
)

// readNeighbors dumps the ARP entries of the routing table through the
// sysctl `arp -an` uses (NET_RT_FLAGS with RTF_LLINFO), which needs no
// privileges.
func readNeighbors() ([]Neighbor, error) {
	typ := route.RIBType(syscall.NET_RT_FLAGS)
	b, err := route.FetchRIB(syscall.AF_INET, typ, syscall.RTF_LLINFO)
	if err != nil {
		return nil, fmt.Errorf("read neighbour table: %w", err)
	}
	msgs, err := route.ParseRIB(typ, b)
	if err != nil {
		return nil, fmt.Errorf("read neighbour table: %w", err)
	}
	var out []Neighbor
	for _, m := range msgs {
		rm, ok := m.(*route.RouteMessage)
		if !ok || len(rm.Addrs) <= syscall.RTAX_GATEWAY {
			continue
		}
		dst, ok := rm.Addrs[syscall.RTAX_DST].(*route.Inet4Addr)
		if !ok {
			continue
		}
		link, ok := rm.Addrs[syscall.RTAX_GATEWAY].(*route.LinkAddr)
		if !ok {
			continue
		}
		mac := net.HardwareAddr(link.Addr)
		if !usableMAC(mac) {
			continue
		}
		out = append(out, Neighbor{IP: netip.AddrFrom4(dst.IP), MAC: mac})
	}
	return out, nil
}
