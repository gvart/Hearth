// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package agent

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"

	"golang.org/x/sys/unix"
)

// VIPSupported reports whether this platform's agent can claim and release
// virtual IPs (Ceiling.VIP).
const VIPSupported = true

const (
	// garpRounds is how many times a claim announces the address, each time
	// with an ARP request and an ARP reply: hosts differ in which of the two
	// updates their cache.
	garpRounds = 3
	// garpInterval is the time between two rounds.
	garpInterval = 500 * time.Millisecond
)

// ethPARP is ETH_P_ARP (0x0806) in network byte order, as AF_PACKET takes it.
const ethPARP = 0x0608

// announce sends gratuitous ARP for ip from ifi, garpRounds times, over a
// raw AF_PACKET socket (CAP_NET_RAW).
func announce(ctx context.Context, ifi *net.Interface, ip netip.Addr) error {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, ethPARP)
	if err != nil {
		return fmt.Errorf("gratuitous ARP on %s: open a raw socket: %w", ifi.Name, err)
	}
	defer unix.Close(fd)
	to := &unix.SockaddrLinklayer{
		Protocol: ethPARP, Ifindex: ifi.Index, Halen: 6,
		Addr: [8]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
	}
	for i := range garpRounds {
		if i > 0 {
			select {
			case <-ctx.Done():
				return fmt.Errorf("gratuitous ARP on %s: %w", ifi.Name, ctx.Err())
			case <-time.After(garpInterval):
			}
		}
		for _, op := range []uint16{arpRequest, arpReply} {
			if err := unix.Sendto(fd, garpFrame(ifi.HardwareAddr, ip, op), 0, to); err != nil {
				return fmt.Errorf("gratuitous ARP on %s: %w", ifi.Name, err)
			}
		}
	}
	return nil
}
