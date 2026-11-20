// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/gvart/hearth/internal/policy"
	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
	"github.com/gvart/hearth/internal/store"
)

// maxNetEdges bounds the neighbours, and apart from them the connections,
// the hub keeps of one report.
const maxNetEdges = 512

// netEdgesRecorder stores the network edges agents report (store.NetEdges).
type netEdgesRecorder interface {
	Replace(ctx context.Context, deviceID string, at time.Time, edges []store.NetEdge) (bool, error)
}

// allowsNetEdges reports whether the agent's last reported ceiling allows
// it to report network edges.
func (s *agentSession) allowsNetEdges() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ceiling.GetNetEdges()
}

// recordNetEdges stores the network edges a device's agent reported, if its
// ceiling allows it to report them: the hub drops a report the device's own
// configuration does not allow. Malformed entries are skipped.
func (s *AgentStream) recordNetEdges(ctx context.Context, log *slog.Logger, deviceID string, sess *agentSession, e *agentv1.NetEdges) {
	if s.netEdges == nil {
		return
	}
	if !sess.allowsNetEdges() {
		log.WarnContext(ctx, "network edges dropped: the agent's ceiling does not allow them")
		return
	}
	edges := netEdgesFrom(e)
	changed, err := s.netEdges.Replace(ctx, deviceID, s.now(), edges)
	switch {
	case errors.Is(err, store.ErrSchemaTooOld):
		log.DebugContext(ctx, "network edges dropped", "err", err)
	case err != nil:
		log.WarnContext(ctx, "record network edges", "err", err)
	default:
		log.DebugContext(ctx, "net edges", "edges", len(edges), "changed", changed)
	}
}

// netEdgesFrom validates a report: addresses must parse, MACs must be
// unicast Ethernet addresses, ports must be ports.
func netEdgesFrom(e *agentv1.NetEdges) []store.NetEdge {
	var out []store.NetEdge
	n := 0
	for _, nb := range e.GetNeighbors() {
		ip, err := netip.ParseAddr(nb.GetIp())
		hw, merr := net.ParseMAC(nb.GetMac())
		if err != nil || merr != nil || len(hw) != 6 || hw[0]&0x01 != 0 {
			continue
		}
		if n++; n > maxNetEdges {
			break
		}
		out = append(out, store.NetEdge{Kind: store.EdgeNeighbor, IP: ip.Unmap().String(), MAC: hw.String()})
	}
	n = 0
	for _, c := range e.GetConnections() {
		ip, err := netip.ParseAddr(c.GetPeerIp())
		if err != nil || c.GetPort() == 0 || c.GetPort() > 65535 || c.GetCount() == 0 {
			continue
		}
		if n++; n > maxNetEdges {
			break
		}
		out = append(out, store.NetEdge{
			Kind: store.EdgeConnection, IP: ip.Unmap().String(), Port: uint16(c.GetPort()), Inbound: c.GetInbound(), Count: c.GetCount(),
		})
	}
	return out
}

// NetEdgesJSON is the API representation of a device's network edges.
type NetEdgesJSON struct {
	// Enabled is whether the device's agent reports network edges (it runs
	// with --allow-net-edges). When it does not, no edge is listed.
	Enabled bool `json:"enabled"`
	// UpdatedAt is when the edges last changed; null when there are none.
	UpdatedAt   *time.Time       `json:"updated_at"`
	Neighbors   []NeighborJSON   `json:"neighbors"`
	Connections []ConnectionJSON `json:"connections"`
}

// NeighborJSON is an entry of a device's neighbour table.
type NeighborJSON struct {
	IP   string    `json:"ip"`
	MAC  string    `json:"mac"`
	Peer *PeerJSON `json:"peer"`
}

// ConnectionJSON is a group of a device's established TCP connections with
// one peer.
type ConnectionJSON struct {
	IP string `json:"ip"`
	// Port is the peer's port of an outbound connection, the device's own
	// of an inbound one.
	Port    uint16    `json:"port"`
	Inbound bool      `json:"inbound"`
	Count   uint32    `json:"count"`
	Peer    *PeerJSON `json:"peer"`
}

// PeerJSON is what the hub knows the other end of an edge to be; null when
// it knows nothing of it.
type PeerJSON struct {
	// Kind is "device" (an enrolled device), "hub" (this hub) or "host" (a
	// host network discovery found).
	Kind string `json:"kind"`
	// ID is the device's id, or the host's MAC; empty for the hub.
	ID   string `json:"id,omitempty"`
	Name string `json:"name"`
}

func (a *api) netEdgeRoutes(mux *http.ServeMux) {
	mux.Handle("GET /api/v1/devices/{id}/net-edges", a.auth(a.deviceNetEdges))
}

// deviceNetEdges serves GET /api/v1/devices/{id}/net-edges: the network
// edges the device's agent last reported, each peer resolved to an enrolled
// device, this hub or a host network discovery found, by MAC, then by IP.
// It is the policy action device.net_edges, audited on every read:
// connections say who talks to whom.
func (a *api) deviceNetEdges(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	d, err := a.store.Devices().Get(ctx, r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not_found", "no such device")
		return
	}
	if err != nil {
		a.log.ErrorContext(ctx, "get device", "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "cannot get device")
		return
	}
	var out NetEdgesJSON
	err = a.policy.Do(ctx, policy.Request{
		ActorKind: policy.ActorWeb, ActorID: remoteHost(r), Action: policy.DeviceNetEdges, Target: d.ID,
	}, func(ctx context.Context) error {
		var err error
		out, err = a.netEdges(ctx, d)
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
		a.log.ErrorContext(ctx, "read network edges", "device_id", d.ID, "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "cannot read network edges")
	}
}

// netEdges reads and resolves d's edges. An agent that no longer reports
// them (its ceiling dropped --allow-net-edges) lists none, whatever it
// reported before.
func (a *api) netEdges(ctx context.Context, d store.Device) (NetEdgesJSON, error) {
	out := NetEdgesJSON{Neighbors: []NeighborJSON{}, Connections: []ConnectionJSON{}}
	var f Facts
	if json.Unmarshal(d.Facts, &f) == nil && f.Ceiling != nil {
		out.Enabled = f.Ceiling.NetEdges
	}
	if !out.Enabled {
		return out, nil
	}
	edges, err := a.store.NetEdges().Get(ctx, d.ID)
	if err != nil {
		return out, err
	}
	if len(edges.Edges) == 0 {
		return out, nil
	}
	at := edges.UpdatedAt
	out.UpdatedAt = &at
	peers, err := a.peerIndex(ctx)
	if err != nil {
		return out, err
	}
	for _, e := range edges.Edges {
		if e.Kind == store.EdgeNeighbor {
			out.Neighbors = append(out.Neighbors, NeighborJSON{IP: e.IP, MAC: e.MAC, Peer: peers.resolve(e.MAC, e.IP)})
			continue
		}
		out.Connections = append(out.Connections, ConnectionJSON{
			IP: e.IP, Port: e.Port, Inbound: e.Inbound, Count: e.Count, Peer: peers.resolve("", e.IP),
		})
	}
	return out, nil
}

// peerIndex maps MACs and IPs to what the hub knows them to be.
type peerIndex struct {
	deviceByMAC, deviceByIP map[string]*PeerJSON
	hostByMAC, hostByIP     map[string]*PeerJSON
	hub                     map[string]bool
}

func (a *api) peerIndex(ctx context.Context) (peerIndex, error) {
	p := peerIndex{
		deviceByMAC: map[string]*PeerJSON{}, deviceByIP: map[string]*PeerJSON{},
		hostByMAC: map[string]*PeerJSON{}, hostByIP: map[string]*PeerJSON{},
		hub: hubAddrs(),
	}
	devs, err := a.store.Devices().List(ctx)
	if err != nil {
		return p, err
	}
	for _, d := range devs {
		peer := &PeerJSON{Kind: "device", ID: d.ID, Name: cmp.Or(d.Name, d.Hostname, d.ID)}
		var f Facts
		if json.Unmarshal(d.Facts, &f) != nil {
			continue
		}
		for _, i := range f.Interfaces {
			if i.MAC != "" {
				p.deviceByMAC[strings.ToLower(i.MAC)] = peer
			}
			for _, ip := range i.IPs {
				ip, _, _ = strings.Cut(ip, "/") // with a prefix length or without
				if a, err := netip.ParseAddr(ip); err == nil && !a.IsLoopback() {
					p.deviceByIP[a.String()] = peer
				}
			}
		}
	}
	hosts, err := a.store.NetworkHosts().List(ctx)
	if err != nil {
		return p, err
	}
	for _, h := range hosts {
		peer := &PeerJSON{Kind: "host", ID: h.MAC, Name: cmp.Or(h.Hostname, h.Vendor, h.MAC)}
		p.hostByMAC[h.MAC] = peer
		p.hostByIP[h.IP] = peer
	}
	return p, nil
}

// resolve finds the peer of mac (if known) and ip: an enrolled device first,
// then this hub, then a discovered host; nil if none.
func (p peerIndex) resolve(mac, ip string) *PeerJSON {
	if d := p.deviceByMAC[mac]; mac != "" && d != nil {
		return d
	}
	if d := p.deviceByIP[ip]; d != nil {
		return d
	}
	if p.hub[ip] {
		return &PeerJSON{Kind: "hub", Name: "this hub"}
	}
	if h := p.hostByMAC[mac]; mac != "" && h != nil {
		return h
	}
	return p.hostByIP[ip]
}

// hubAddrs are the addresses of this hub's own interfaces.
func hubAddrs() map[string]bool {
	out := map[string]bool{}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return out
	}
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok {
			if ip, ok := netip.AddrFromSlice(n.IP); ok && !ip.IsLoopback() {
				out[ip.Unmap().String()] = true
			}
		}
	}
	return out
}
