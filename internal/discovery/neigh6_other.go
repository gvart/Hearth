// SPDX-License-Identifier: AGPL-3.0-only

//go:build !linux

package discovery

// readNeighbors6 reads nothing: only Linux's IPv6 neighbour table is read.
func readNeighbors6() ([]Neighbor, error) { return nil, nil }
