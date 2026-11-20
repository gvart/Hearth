// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"cmp"
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

// Kinds of topology node (TopologyNodeJSON.Kind).
const (
	nodeDevice  = "device"
	nodeHub     = "hub"
	nodeHost    = "host"
	nodeUnknown = "unknown"
)

// TopologyJSON is the API representation of the network edges of every
// device at once: a graph of devices, the hub, discovered hosts and unknown
// addresses.
type TopologyJSON struct {
	// Reporting is how many devices' agents report network edges (run with
	// --allow-net-edges); the edges are theirs only.
	Reporting int `json:"reporting"`
	// UpdatedAt is when the edges of a reporting device last changed; null
	// when none has any.
	UpdatedAt *time.Time         `json:"updated_at"`
	Nodes     []TopologyNodeJSON `json:"nodes"`
	Edges     []TopologyEdgeJSON `json:"edges"`
}

// TopologyNodeJSON is a node of the topology graph.
type TopologyNodeJSON struct {
	// ID is "device:<id>", "hub", "host:<mac>" or "ip:<address>".
	ID string `json:"id"`
	// Kind is "device", "hub", "host" (a host network discovery found) or
	// "unknown" (an address the hub knows nothing of).
	Kind string `json:"kind"`
	Name string `json:"name"`
	// DeviceID is a device's id.
	DeviceID string `json:"device_id,omitempty"`
	// IP is the address a host or unknown node was seen at.
	IP string `json:"ip,omitempty"`
	// Reports is set on a device whose agent reports network edges.
	Reports bool `json:"reports,omitempty"`
}

// TopologyEdgeJSON is an edge of the topology graph.
type TopologyEdgeJSON struct {
	// Kind is "neighbor" or "connection".
	Kind string `json:"kind"`
	// From and To are node ids. A connection goes from the client to the
	// server, whichever end reported it; a neighbour's ends are in id order.
	From string `json:"from"`
	To   string `json:"to"`
	// Port is a connection's server port.
	Port uint16 `json:"port,omitempty"`
	// Count is how many connections the edge holds: the most either end
	// reported.
	Count uint32 `json:"count,omitempty"`
}

// netTopology serves GET /api/v1/net-edges: the network edges every device's
// agent last reported, as one graph. It is the policy action
// network.topology, one audited read for every device; a device whose
// ceiling does not allow network edges contributes none.
func (a *api) netTopology(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var out TopologyJSON
	err := a.policy.Do(ctx, policy.Request{
		ActorKind: policy.ActorWeb, ActorID: remoteHost(r), Action: policy.NetworkTopology, Target: "devices",
	}, func(ctx context.Context) error {
		var err error
		out, err = a.readTopology(ctx)
		return err
	})
	switch {
	case err == nil:
		writeJSON(w, http.StatusOK, out)
	case errors.Is(err, policy.ErrDenied):
		writeError(w, http.StatusForbidden, "forbidden", "denied by policy")
	case errors.Is(err, store.ErrUnavailable):
		writeUnavailable(w)
	default:
		a.log.ErrorContext(ctx, "read network topology", "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "cannot read network topology")
	}
}

func (a *api) readTopology(ctx context.Context) (TopologyJSON, error) {
	out := TopologyJSON{Nodes: []TopologyNodeJSON{}, Edges: []TopologyEdgeJSON{}}
	devs, err := a.store.Devices().List(ctx)
	if err != nil {
		return out, err
	}
	nodes := map[string]TopologyNodeJSON{}
	edges := map[TopologyEdgeJSON]uint32{} // without Count: the largest reported
	var peers *peerIndex
	for _, d := range devs {
		if !netEdgesEnabled(d) {
			continue
		}
		out.Reporting++
		self := TopologyNodeJSON{ID: "device:" + d.ID, Kind: nodeDevice, Name: cmp.Or(d.Name, d.Hostname, d.ID), DeviceID: d.ID, Reports: true}
		nodes[self.ID] = self
		if a.netEdges == nil {
			continue
		}
		list, at := a.netEdges.Get(d.ID)
		if len(list) == 0 {
			continue
		}
		if out.UpdatedAt == nil || at.After(*out.UpdatedAt) {
			out.UpdatedAt = &at
		}
		if peers == nil {
			p, err := a.peerIndex(ctx)
			if err != nil {
				return out, err
			}
			peers = &p
		}
		for _, e := range list {
			peer := topologyNode(peers.resolve(e.MAC, e.IP), e.IP)
			if peer.ID == self.ID {
				continue // the device's own address
			}
			if _, ok := nodes[peer.ID]; !ok {
				nodes[peer.ID] = peer // a reporting device's own node replaces it
			}
			k := TopologyEdgeJSON{Kind: e.Kind, From: self.ID, To: peer.ID}
			if e.Kind == EdgeNeighbor {
				if k.To < k.From {
					k.From, k.To = k.To, k.From
				}
			} else {
				k.Port = e.Port
				if e.Inbound {
					k.From, k.To = k.To, k.From
				}
			}
			edges[k] = max(edges[k], e.Count)
		}
	}
	for _, n := range nodes {
		out.Nodes = append(out.Nodes, n)
	}
	slices.SortFunc(out.Nodes, func(a, b TopologyNodeJSON) int { return strings.Compare(a.ID, b.ID) })
	for k, count := range edges {
		k.Count = count
		out.Edges = append(out.Edges, k)
	}
	slices.SortFunc(out.Edges, func(a, b TopologyEdgeJSON) int {
		return cmp.Or(strings.Compare(a.Kind, b.Kind), strings.Compare(a.From, b.From), strings.Compare(a.To, b.To),
			cmp.Compare(a.Port, b.Port))
	})
	return out, nil
}

// topologyNode is the node of a peer the hub resolved, or of an unknown ip.
func topologyNode(p *PeerJSON, ip string) TopologyNodeJSON {
	switch {
	case p == nil:
		return TopologyNodeJSON{ID: "ip:" + ip, Kind: nodeUnknown, Name: ip, IP: ip}
	case p.Kind == nodeDevice:
		return TopologyNodeJSON{ID: "device:" + p.ID, Kind: nodeDevice, Name: p.Name, DeviceID: p.ID}
	case p.Kind == nodeHub:
		return TopologyNodeJSON{ID: "hub", Kind: nodeHub, Name: p.Name}
	default:
		return TopologyNodeJSON{ID: "host:" + p.ID, Kind: nodeHost, Name: p.Name, IP: ip}
	}
}
