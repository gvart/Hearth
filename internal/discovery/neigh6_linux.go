// SPDX-License-Identifier: AGPL-3.0-only

package discovery

import (
	"fmt"
	"syscall"
)

// readNeighbors6 dumps the kernel's IPv6 neighbour table over netlink
// (RTM_GETNEIGH, what `ip -6 neigh` reads), which needs no privileges.
func readNeighbors6() ([]Neighbor, error) {
	b, err := syscall.NetlinkRIB(syscall.RTM_GETNEIGH, syscall.AF_INET6)
	if err != nil {
		return nil, fmt.Errorf("read ipv6 neighbour table: %w", err)
	}
	return parseNeigh6(b), nil
}
