// SPDX-License-Identifier: AGPL-3.0-only

package discovery

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"
)

// Sweep timing. Each round sends one empty UDP datagram to every target;
// before the kernel can send it, it must resolve the target's MAC, so it
// ARPs for every address and fills its neighbour table with those that
// answer. No raw socket and no privilege is needed, and no port is probed:
// the datagram goes to the discard port, and its fate does not matter.
const (
	sweepRounds = 2
	// sweepGap is the pause between rounds, and after the last one, for
	// late ARP replies.
	sweepGap = time.Second
	// sweepBurst datagrams go out back to back, then the sweep pauses
	// sweepPace: about 250 ms per /24.
	sweepBurst = 16
	sweepPace  = 15 * time.Millisecond
	// sweepWriteTimeout gives up a write that would block (see sweep).
	sweepWriteTimeout = 50 * time.Millisecond
	discardPort       = 9
)

// sweep makes the kernel resolve the MAC of every target, so that
// readNeighbors finds every host that answered.
//
// A datagram waiting for ARP holds its socket's send buffer until the
// address resolves or fails (seconds, on Linux), so a whole sweep on one
// socket would block once the buffer is full: each burst gets a socket of
// its own.
func sweep(ctx context.Context, targets []netip.Addr) error {
	for range sweepRounds {
		for i := 0; i < len(targets); i += sweepBurst {
			if err := sendBurst(targets[i:min(i+sweepBurst, len(targets))]); err != nil {
				return err
			}
			if err := sleep(ctx, sweepPace); err != nil {
				return err
			}
		}
		if err := sleep(ctx, sweepGap); err != nil {
			return err
		}
	}
	return nil
}

func sendBurst(targets []netip.Addr) error {
	conn, err := net.ListenUDP("udp4", nil)
	if err != nil {
		return fmt.Errorf("sweep: %w", err)
	}
	defer conn.Close()
	_ = conn.SetWriteDeadline(time.Now().Add(sweepWriteTimeout))
	for _, ip := range targets {
		// Errors (host down, no route) are what a sweep expects.
		_, _ = conn.WriteToUDPAddrPort(nil, netip.AddrPortFrom(ip, discardPort))
	}
	return nil
}

func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
