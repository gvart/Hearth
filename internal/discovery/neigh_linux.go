// SPDX-License-Identifier: AGPL-3.0-only

package discovery

import (
	"fmt"
	"os"
)

// readNeighbors reads the kernel's ARP table, which any user may read.
func readNeighbors() ([]Neighbor, error) {
	f, err := os.Open("/proc/net/arp")
	if err != nil {
		return nil, fmt.Errorf("read neighbour table: %w", err)
	}
	defer f.Close()
	n, err := parseProcARP(f)
	if err != nil {
		return nil, fmt.Errorf("read neighbour table: %w", err)
	}
	return n, nil
}
