// SPDX-License-Identifier: AGPL-3.0-only

package policy

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"

	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
)

// A virtual IP (#49) is an IPv4 address a service answers on that Hearth
// moves between devices: the vip_claim automation action adds it to an
// interface of one device and announces it with gratuitous ARP, vip_release
// removes it. A device allows only the exact interface=address pairs its
// ceiling's vip lists, so a claim cannot take another host's address (the
// gateway's) and a release cannot remove the device's own.

// maxInterfaceName is the longest Linux interface name (IFNAMSIZ - 1).
const maxInterfaceName = 15

// ValidInterface reports whether name may name a network interface in a
// virtual IP: 1-15 letters, digits, '.', '_' and '-', starting with a letter
// or digit, and not the loopback interface lo.
func ValidInterface(name string) bool {
	if name == "" || len(name) > maxInterfaceName || name == "lo" {
		return false
	}
	for i, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case i > 0 && (r == '_' || r == '.' || r == '-'):
		default:
			return false
		}
	}
	return true
}

// ParseVIPAddress parses a virtual IP's address: an IPv4 address with its
// prefix length, such as 192.168.1.53/24, that a host may hold: not
// loopback, multicast, link-local, unspecified or broadcast, nor the network
// or broadcast address of its prefix.
func ParseVIPAddress(s string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(s)
	if err != nil || !p.Addr().Is4() {
		return netip.Prefix{}, fmt.Errorf("address %q: want an IPv4 address with its prefix length, such as 192.168.1.53/24", s)
	}
	a := p.Addr()
	if p.Bits() < 8 || a.IsLoopback() || a.IsMulticast() || a.IsUnspecified() || a.IsLinkLocalUnicast() ||
		a == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
		return netip.Prefix{}, fmt.Errorf("address %q: not an address a virtual IP may take", s)
	}
	if p.Bits() <= 30 {
		b := a.As4()
		n := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
		host := uint32(1)<<(32-p.Bits()) - 1
		if n&host == 0 || n&host == host {
			return netip.Prefix{}, fmt.Errorf("address %q: the network or broadcast address of its prefix", s)
		}
	}
	return p, nil
}

// VIPEntry is a ceiling's vip entry for an interface and an address:
// IFACE=ADDRESS/PREFIX.
func VIPEntry(iface, address string) string { return iface + "=" + address }

// CheckVIP checks a virtual IP's interface and address (ValidInterface,
// ParseVIPAddress).
func CheckVIP(iface, address string) error {
	if !ValidInterface(iface) {
		return fmt.Errorf("interface %q: want 1-15 letters, digits, '.', '_' or '-', not lo", iface)
	}
	_, err := ParseVIPAddress(address)
	return err
}

// checkVIPEntries checks a ceiling's vip entries: each IFACE=ADDRESS/PREFIX,
// written as ParseVIPAddress prints it.
func checkVIPEntries(entries []string) error {
	for _, e := range entries {
		iface, address, ok := strings.Cut(e, "=")
		if !ok {
			return fmt.Errorf("vip entry %q: want IFACE=ADDRESS/PREFIX, such as eth0=192.168.1.53/24", e)
		}
		if err := CheckVIP(iface, address); err != nil {
			return fmt.Errorf("vip entry %q: %w", e, err)
		}
		if p, _ := ParseVIPAddress(address); p.String() != address {
			return fmt.Errorf("vip entry %q: write the address as %s", e, p)
		}
	}
	return nil
}

// vipWithinCeiling checks a VirtualIP request against c: it must name a
// valid interface and address, and c must list the pair exactly. Errors for
// a pair c does not list wrap ErrBeyondCeiling; those for an invalid one
// wrap ErrDenied.
func vipWithinCeiling(c *agentv1.Ceiling, v *agentv1.VirtualIP) error {
	verb := "vip claim"
	if v.GetRelease() {
		verb = "vip release"
	}
	if err := CheckVIP(v.GetInterface(), v.GetAddress()); err != nil {
		return fmt.Errorf("%s: %w: %w", verb, err, ErrDenied)
	}
	if !slices.Contains(c.GetVip(), VIPEntry(v.GetInterface(), v.GetAddress())) {
		return fmt.Errorf("%s %s on %s: %w", verb, v.GetAddress(), v.GetInterface(), ErrBeyondCeiling)
	}
	return nil
}
