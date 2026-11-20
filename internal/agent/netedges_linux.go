// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"os"

	"github.com/gvart/hearth/internal/discovery"
	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
)

// NetEdgesSupported reports whether this platform's agent can report its
// network edges (Ceiling.NetEdges).
const NetEdgesSupported = true

// readNetEdges reads the neighbour table and the TCP connections from /proc,
// which any user may read: no privileges, no conntrack.
func readNetEdges() (*agentv1.NetEdges, error) {
	return collectNetEdges(os.DirFS("/proc/net"), discovery.ReadNeighbors)
}
