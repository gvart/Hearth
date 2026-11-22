// SPDX-License-Identifier: AGPL-3.0-only

package discovery

import (
	"fmt"
	"net/netip"
	"slices"
	"syscall"

	"golang.org/x/net/route"
)

// defaultGateways reads the gateways of the IPv4 default routes from the
// routing table, through the sysctl `netstat -rn` uses (NET_RT_DUMP), which
// needs no privileges. Interface-scoped defaults count too: with a VPN up,
// the LAN's gateway is often only on one.
func defaultGateways() ([]netip.Addr, error) {
	b, err := route.FetchRIB(syscall.AF_INET, route.RIBTypeRoute, 0)
	if err != nil {
		return nil, fmt.Errorf("read default gateway: %w", err)
	}
	msgs, err := route.ParseRIB(route.RIBTypeRoute, b)
	if err != nil {
		return nil, fmt.Errorf("read default gateway: %w", err)
	}
	var out []netip.Addr
	for _, m := range msgs {
		rm, ok := m.(*route.RouteMessage)
		if !ok || rm.Flags&syscall.RTF_GATEWAY == 0 || len(rm.Addrs) <= syscall.RTAX_GATEWAY {
			continue
		}
		dst, ok := rm.Addrs[syscall.RTAX_DST].(*route.Inet4Addr)
		if !ok || dst.IP != [4]byte{} {
			continue
		}
		if len(rm.Addrs) > syscall.RTAX_NETMASK {
			if mask, ok := rm.Addrs[syscall.RTAX_NETMASK].(*route.Inet4Addr); ok && mask.IP != [4]byte{} {
				continue
			}
		}
		gw, ok := rm.Addrs[syscall.RTAX_GATEWAY].(*route.Inet4Addr)
		if !ok || gw.IP == [4]byte{} {
			continue
		}
		if ip := netip.AddrFrom4(gw.IP); !slices.Contains(out, ip) {
			out = append(out, ip)
		}
	}
	return out, nil
}
