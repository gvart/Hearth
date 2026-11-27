// SPDX-License-Identifier: AGPL-3.0-only

package discovery

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

// neighMsg builds one netlink message of an RTM_GETNEIGH dump: an ndmsg of
// family and state, then the NDA_DST and (unless empty) NDA_LLADDR
// attributes, each padded to four bytes.
func neighMsg(typ uint16, family byte, state uint16, dst []byte, mac []byte) []byte {
	nd := make([]byte, ndmsgLen)
	nd[0] = family
	binary.NativeEndian.PutUint16(nd[8:], state)
	attr := func(t uint16, v []byte) []byte {
		a := make([]byte, align4(4+len(v)))
		binary.NativeEndian.PutUint16(a, uint16(4+len(v))) //nolint:gosec // small
		binary.NativeEndian.PutUint16(a[2:], t)
		copy(a[4:], v)
		return a
	}
	body := append(nd, attr(ndaDst, dst)...)
	if len(mac) > 0 {
		body = append(body, attr(ndaLLAddr, mac)...)
	}
	h := make([]byte, nlmsgHdrLen)
	binary.NativeEndian.PutUint32(h, uint32(nlmsgHdrLen+len(body))) //nolint:gosec // small
	binary.NativeEndian.PutUint16(h[4:], typ)
	return append(h, body...)
}

func TestParseNeigh6(t *testing.T) {
	ip := func(s string) []byte { return netip.MustParseAddr(s).AsSlice() }
	mac := []byte{0x2c, 0xcf, 0x67, 0, 0, 1}
	const reachable, stale, incomplete, failed, noarp = 0x02, 0x04, 0x01, 0x20, 0x40
	var dump []byte
	for _, m := range [][]byte{
		neighMsg(rtmNewNeigh, afInet6Linux, reachable, ip("fe80::1"), mac),                          // kept, without zone
		neighMsg(rtmNewNeigh, afInet6Linux, stale, ip("2001:db8::7"), []byte{2, 0, 0, 0, 0, 7}),     // kept
		neighMsg(rtmNewNeigh, afInet6Linux, incomplete, ip("2001:db8::8"), nil),                     // unresolved
		neighMsg(rtmNewNeigh, afInet6Linux, failed, ip("2001:db8::9"), mac),                         // failed
		neighMsg(rtmNewNeigh, afInet6Linux, noarp, ip("ff02::1"), []byte{0x33, 0x33, 0, 0, 0, 1}),   // multicast
		neighMsg(rtmNewNeigh, afInet6Linux, reachable, ip("2001:db8::a"), []byte{0, 0, 0, 0, 0, 0}), // zero MAC
		neighMsg(rtmNewNeigh, 2, reachable, ip("192.168.2.1"), mac),                                 // IPv4
		neighMsg(nlmsgDone, 0, 0, nil, nil),
		neighMsg(rtmNewNeigh, afInet6Linux, reachable, ip("2001:db8::b"), mac), // after the end
	} {
		dump = append(dump, m...)
	}
	got := parseNeigh6(dump)
	if len(got) != 2 || got[0].IP.String() != "fe80::1" || got[0].MAC.String() != "2c:cf:67:00:00:01" ||
		got[1].IP.String() != "2001:db8::7" || got[1].MAC.String() != "02:00:00:00:00:07" {
		t.Fatalf("parseNeigh6 = %v; want fe80::1 and 2001:db8::7", got)
	}

	// A truncated dump is read up to the malformed message, never past it.
	if got := parseNeigh6(dump[:len(dump)/3]); len(got) > 2 {
		t.Fatalf("parseNeigh6(truncated) = %v", got)
	}
	if got := parseNeigh6([]byte{0xff, 0xff, 0xff, 0xff}); got != nil {
		t.Fatalf("parseNeigh6(garbage) = %v", got)
	}
}
