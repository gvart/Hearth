// SPDX-License-Identifier: AGPL-3.0-only

package discovery

import (
	"encoding/binary"
	"net"
	"net/netip"
)

// ReadNeighbors6 returns the resolved unicast entries of the operating
// system's IPv6 neighbour (NDP) table, which any user may read. On a
// platform whose table it cannot read it returns none.
func ReadNeighbors6() ([]Neighbor, error) { return readNeighbors6() }

// Netlink and neighbour constants of Linux (linux/netlink.h, rtnetlink.h,
// neighbour.h), spelled out so the parser builds and is tested everywhere.
const (
	nlmsgHdrLen  = 16
	ndmsgLen     = 12
	nlmsgDone    = 3
	rtmNewNeigh  = 28
	afInet6Linux = 10
	ndaDst       = 1
	ndaLLAddr    = 2
	// nudResolved are the states of an entry whose link address is known:
	// REACHABLE, STALE, DELAY, PROBE and PERMANENT; not INCOMPLETE, FAILED
	// or NOARP.
	nudResolved = 0x02 | 0x04 | 0x08 | 0x10 | 0x80
)

// parseNeigh6 reads the reply of an RTM_GETNEIGH dump for AF_INET6: a run of
// netlink messages, each an ndmsg and its attributes, in host byte order. It
// keeps the resolved entries with a unicast address (link-local ones without
// their zone) and a usable MAC; it stops at the end of the dump or at a
// malformed message.
func parseNeigh6(b []byte) []Neighbor {
	var out []Neighbor
	for len(b) >= nlmsgHdrLen {
		l := int(binary.NativeEndian.Uint32(b))
		typ := binary.NativeEndian.Uint16(b[4:])
		if l < nlmsgHdrLen || l > len(b) || typ == nlmsgDone {
			break
		}
		msg := b[nlmsgHdrLen:l]
		b = b[min(align4(l), len(b)):]
		if typ != rtmNewNeigh || len(msg) < ndmsgLen || msg[0] != afInet6Linux {
			continue
		}
		if binary.NativeEndian.Uint16(msg[8:])&nudResolved == 0 {
			continue
		}
		var n Neighbor
		for a := msg[ndmsgLen:]; len(a) >= 4; {
			al := int(binary.NativeEndian.Uint16(a))
			if al < 4 || al > len(a) {
				break
			}
			switch v := a[4:al]; binary.NativeEndian.Uint16(a[2:]) {
			case ndaDst:
				if ip, ok := netip.AddrFromSlice(v); ok && ip.Is6() {
					n.IP = ip
				}
			case ndaLLAddr:
				n.MAC = net.HardwareAddr(v)
			}
			a = a[min(align4(al), len(a)):]
		}
		ip := n.IP
		if !ip.IsValid() || ip.Is4In6() || ip.IsMulticast() || ip.IsUnspecified() || ip.IsLoopback() || !usableMAC(n.MAC) {
			continue
		}
		n.MAC = append(net.HardwareAddr(nil), n.MAC...) // off the dump's buffer
		out = append(out, n)
	}
	return out
}

func align4(n int) int { return (n + 3) &^ 3 }
