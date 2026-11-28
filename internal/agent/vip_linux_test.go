// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package agent

import (
	"bytes"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/gvart/hearth/internal/policy"
)

// TestVIPIntegration claims and releases a real virtual IP. It changes the
// interface it is given, so it runs only when asked to, in a throwaway
// network namespace with CAP_NET_ADMIN and CAP_NET_RAW, such as a container:
//
//	GOOS=linux go test -c -o agent.test ./internal/agent
//	docker run --rm --cap-add NET_ADMIN --cap-add NET_RAW -v "$PWD/agent.test:/agent.test" \
//	  -e HEARTH_VIP_TEST_IFACE=eth0 -e HEARTH_VIP_TEST_ADDR=10.250.0.53/24 \
//	  alpine /agent.test -test.run TestVIPIntegration -test.v
func TestVIPIntegration(t *testing.T) {
	iface, address := os.Getenv("HEARTH_VIP_TEST_IFACE"), os.Getenv("HEARTH_VIP_TEST_ADDR")
	if iface == "" || address == "" {
		t.Skip("set HEARTH_VIP_TEST_IFACE and HEARTH_VIP_TEST_ADDR, in a throwaway network namespace")
	}
	p, err := policy.ParseVIPAddress(address)
	if err != nil {
		t.Fatal(err)
	}
	c := Ceiling{VIP: []string{policy.VIPEntry(iface, address)}}
	holds := func() bool {
		_, addrs, err := interfaceAddrs(iface)
		if err != nil {
			t.Fatal(err)
		}
		return holdsAddr(addrs, p.Addr())
	}
	if holds() {
		t.Fatalf("%s already holds %s", iface, address)
	}

	// Watch the interface's outgoing ARP, to see the announcements.
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		t.Fatal(err)
	}
	// Outgoing frames reach ETH_P_ALL sockets only.
	const ethPAll = 0x0300 // htons(ETH_P_ALL)
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, ethPAll)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: ethPAll, Ifindex: ifi.Index}); err != nil {
		t.Fatal(err)
	}
	tv := unix.NsecToTimeval(int64(3 * time.Second))
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		t.Fatal(err)
	}

	for i := range 2 { // a second claim announces again
		if res := c.execute(t.Context(), vipReq(iface, address, false)); res.GetError() != "" || res.GetExitCode() != 0 {
			t.Fatalf("claim %d: %v", i, res)
		}
		if !holds() {
			t.Fatalf("claim %d: %s does not hold %s", i, iface, address)
		}
	}
	want := map[uint16]bool{}
	buf := make([]byte, 128)
	for len(want) < 2 {
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			t.Fatalf("no gratuitous ARP seen (%v), saw %v", err, want)
		}
		f := buf[:n]
		a := p.Addr().As4()
		if n >= 42 && f[12] == 0x08 && f[13] == 0x06 && bytes.Equal(f[6:12], ifi.HardwareAddr) && bytes.Equal(f[28:32], a[:]) && bytes.Equal(f[38:42], a[:]) {
			want[uint16(f[20])<<8|uint16(f[21])] = true
		}
	}
	if !want[arpRequest] || !want[arpReply] {
		t.Errorf("announced with ARP operations %v, want a request and a reply", want)
	}

	// Beyond the ceiling: another address is refused, and not added.
	other := netip.PrefixFrom(p.Addr().Next(), p.Bits()).String()
	if res := c.execute(t.Context(), vipReq(iface, other, false)); !res.GetDenied() {
		t.Errorf("claim of %s beyond the ceiling: %v", other, res)
	}

	for i := range 2 { // releasing an address not held succeeds
		if res := c.execute(t.Context(), vipReq(iface, address, true)); res.GetError() != "" {
			t.Fatalf("release %d: %v", i, res)
		}
		if holds() {
			t.Fatalf("release %d: %s still holds %s", i, iface, address)
		}
	}
}
