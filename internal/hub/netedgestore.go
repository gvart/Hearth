// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"cmp"
	"slices"
	"strings"
	"sync"
	"time"
)

// Kinds of network edge (NetEdge.Kind).
const (
	// EdgeNeighbor is an entry of the device's neighbour (ARP) table.
	EdgeNeighbor = "neighbor"
	// EdgeConnection is a group of the device's established TCP
	// connections with one peer.
	EdgeConnection = "connection"
)

// NetEdge is one network edge a device's agent reported: a neighbour, or a
// group of TCP connections with one peer.
type NetEdge struct {
	// Kind is EdgeNeighbor or EdgeConnection.
	Kind string
	// IP is the peer's address.
	IP string
	// MAC is a neighbour's MAC address, lower-case and colon-separated;
	// empty for a connection.
	MAC string
	// Port is a connection's service port: the peer's for an outbound
	// connection, the device's own for an inbound one; 0 for a neighbour.
	Port uint16
	// Inbound is set when the peer connected to the device.
	Inbound bool
	// Count is how many connections the group holds; 0 for a neighbour.
	Count uint32
}

func compareEdges(a, b NetEdge) int {
	return cmp.Or(strings.Compare(a.Kind, b.Kind), strings.Compare(a.IP, b.IP), cmp.Compare(a.Port, b.Port),
		cmp.Compare(boolInt(a.Inbound), boolInt(b.Inbound)))
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// NetEdges keeps the network edges each device's agent last reported. Like
// the host metrics, they are hub-local: kept in this hub's memory, never in
// the replicated store, so a report every minute from every agent costs no
// replicated write. Each agent streams to one master; after it moves or a
// restart the agents refill it within a minute. It is safe for concurrent
// use.
type NetEdges struct {
	mu       sync.Mutex
	byDevice map[string]deviceEdges
}

type deviceEdges struct {
	edges   []NetEdge
	updated time.Time
}

// NewNetEdges returns an empty edge store.
func NewNetEdges() *NetEdges { return &NetEdges{byDevice: map[string]deviceEdges{}} }

// set makes edges the device's edges, sorted and without repeats. The time
// they last changed moves to at only when they differ from the last report.
func (n *NetEdges) set(deviceID string, at time.Time, edges []NetEdge) (changed bool) {
	edges = slices.Clone(edges)
	slices.SortFunc(edges, compareEdges)
	edges = slices.CompactFunc(edges, func(a, b NetEdge) bool { return compareEdges(a, b) == 0 })
	n.mu.Lock()
	defer n.mu.Unlock()
	cur, ok := n.byDevice[deviceID]
	if ok && slices.Equal(cur.edges, edges) {
		return false
	}
	n.byDevice[deviceID] = deviceEdges{edges: edges, updated: at}
	return true
}

// clear forgets the device's edges.
func (n *NetEdges) clear(deviceID string) {
	n.mu.Lock()
	delete(n.byDevice, deviceID)
	n.mu.Unlock()
}

// Get returns the edges the device's agent last reported, by kind, IP, port
// and direction, and when they last changed (zero for none).
func (n *NetEdges) Get(deviceID string) ([]NetEdge, time.Time) {
	n.mu.Lock()
	defer n.mu.Unlock()
	d := n.byDevice[deviceID]
	return slices.Clone(d.edges), d.updated
}
