// SPDX-License-Identifier: AGPL-3.0-only

//go:build !linux && !darwin

package discovery

import "errors"

// errNoNeighborTable is returned on a platform whose neighbour table the
// scanner cannot read.
var errNoNeighborTable = errors.New("reading the neighbour table is not supported on this platform")

func readNeighbors() ([]Neighbor, error) { return nil, errNoNeighborTable }
