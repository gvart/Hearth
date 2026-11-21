// SPDX-License-Identifier: AGPL-3.0-only

package discovery

import (
	"bufio"
	"encoding/binary"
	"io"
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

// rtfGateway is RTF_GATEWAY, the flag of a route through a gateway.
const rtfGateway = 0x2

// parseProcRoute returns the gateways of the IPv4 default routes in Linux's
// /proc/net/route, whose addresses are hex in the kernel's (little-endian,
// on every platform Hearth ships for) byte order:
//
//	Iface  Destination  Gateway   Flags  RefCnt  Use  Metric  Mask      MTU  Window  IRTT
//	eth0   00000000     0102A8C0  0003   0       0    100     00000000  0    0       0
func parseProcRoute(r io.Reader) ([]netip.Addr, error) {
	sc := bufio.NewScanner(r)
	var out []netip.Addr
	for first := true; sc.Scan(); first = false {
		f := strings.Fields(sc.Text())
		if first || len(f) < 8 || f[1] != "00000000" || f[7] != "00000000" {
			continue
		}
		flags, err := strconv.ParseUint(f[3], 16, 32)
		if err != nil || flags&rtfGateway == 0 {
			continue
		}
		gw, err := strconv.ParseUint(f[2], 16, 32)
		if err != nil || gw == 0 {
			continue
		}
		var b [4]byte
		binary.LittleEndian.PutUint32(b[:], uint32(gw))
		if ip := netip.AddrFrom4(b); !slices.Contains(out, ip) {
			out = append(out, ip)
		}
	}
	return out, sc.Err()
}
