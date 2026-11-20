// SPDX-License-Identifier: AGPL-3.0-only

package discovery

import (
	"bufio"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// Neighbor is a resolved entry of the operating system's IPv4 neighbour
// (ARP) table.
type Neighbor struct {
	IP  netip.Addr
	MAC net.HardwareAddr
}

// ReadNeighbors returns the complete unicast entries of the operating
// system's IPv4 neighbour (ARP) table, which any user may read.
func ReadNeighbors() ([]Neighbor, error) { return readNeighbors() }

// usableMAC reports whether mac names one host: not empty, all zeros
// (incomplete) or a group (broadcast, multicast) address.
func usableMAC(mac net.HardwareAddr) bool {
	if len(mac) != 6 || mac[0]&0x01 != 0 {
		return false
	}
	for _, b := range mac {
		if b != 0 {
			return true
		}
	}
	return false
}

// atfCom is ATF_COM, the flag of a complete entry in /proc/net/arp.
const atfCom = 0x2

// parseProcARP reads Linux's /proc/net/arp:
//
//	IP address       HW type     Flags       HW address            Mask     Device
//	192.168.2.1      0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0
func parseProcARP(r io.Reader) ([]Neighbor, error) {
	sc := bufio.NewScanner(r)
	var out []Neighbor
	for first := true; sc.Scan(); first = false {
		f := strings.Fields(sc.Text())
		if first || len(f) < 4 {
			continue
		}
		ip, err := netip.ParseAddr(f[0])
		if err != nil || !ip.Is4() {
			continue
		}
		flags, err := strconv.ParseUint(strings.TrimPrefix(f[2], "0x"), 16, 32)
		if err != nil || flags&atfCom == 0 {
			continue
		}
		mac, err := net.ParseMAC(f[3])
		if err != nil || !usableMAC(mac) {
			continue
		}
		out = append(out, Neighbor{IP: ip, MAC: mac})
	}
	return out, sc.Err()
}
