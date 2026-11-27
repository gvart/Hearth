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

const (
	// maxNetEdges bounds the neighbours, and apart from them the connections,
	// the hub keeps of one report.
	maxNetEdges = 512
	// minNetEdgesGap is the least time between two reports of one stream
	// the hub takes; agents report every minute. A report sooner is dropped.
	minNetEdgesGap = 30 * time.Second
)

// takeNetEdges reports whether a report arriving at now is to be recorded:
// the agent's last reported ceiling allows network edges, and the last
// report of this stream is at least minNetEdgesGap old.
func (s *agentSession) takeNetEdges(now time.Time) (allowed, due bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.ceiling.GetNetEdges() {
		return false, false
	}
	if !s.lastNetEdges.IsZero() && now.Sub(s.lastNetEdges) < minNetEdgesGap {
		return true, false
	}
	s.lastNetEdges = now
	return true, true
}

// recordNetEdges keeps the network edges a device's agent reported, if its
// ceiling allows it to report them (the hub drops a report the device's own
// configuration does not allow) and the stream's last report is at least
// minNetEdgesGap old. Malformed entries are skipped.
func (s *AgentStream) recordNetEdges(ctx context.Context, log *slog.Logger, deviceID string, sess *agentSession, e *agentv1.NetEdges) {
	if s.netEdges == nil {
		return
	}
	now := s.now()
	switch allowed, due := sess.takeNetEdges(now); {
	case !allowed:
		log.WarnContext(ctx, "network edges dropped: the agent's ceiling does not allow them")
		return
	case !due:
		log.WarnContext(ctx, "network edges dropped: the agent reports too often")
		return
	}
	edges := netEdgesFrom(e)
	changed := s.netEdges.set(deviceID, now, edges)
	log.DebugContext(ctx, "net edges", "edges", len(edges), "changed", changed, "connections_dropped", e.GetConnectionsDropped())
}

// forgetNetEdges forgets the device's edges once its agent reports a
// ceiling that does not allow them: the operator turned them off.
func (s *AgentStream) forgetNetEdges(deviceID string, c *agentv1.Ceiling) {
	if s.netEdges != nil && !c.GetNetEdges() {
		s.netEdges.clear(deviceID)
	}
}

// netEdgesFrom validates a report: addresses must parse without a zone,
// neighbours must be unicast IPv4 or IPv6 with a unicast Ethernet MAC, ports
// must be ports.
func netEdgesFrom(e *agentv1.NetEdges) []NetEdge {
	var out []NetEdge
	n := 0
	for _, nb := range e.GetNeighbors() {
		ip, err := netip.ParseAddr(nb.GetIp())
		hw, merr := net.ParseMAC(nb.GetMac())
		if err != nil || ip.Zone() != "" || ip.Is4In6() || ip.IsMulticast() || ip.IsUnspecified() || ip.IsLoopback() ||
			merr != nil || len(hw) != 6 || hw[0]&0x01 != 0 {
			continue
		}
		if n++; n > maxNetEdges {
			break
		}
		out = append(out, NetEdge{Kind: EdgeNeighbor, IP: ip.String(), MAC: hw.String()})
	}
	n = 0
	for _, c := range e.GetConnections() {
		ip, err := netip.ParseAddr(c.GetPeerIp())
		if err != nil || ip.Zone() != "" || c.GetPort() == 0 || c.GetPort() > 65535 || c.GetCount() == 0 {
			continue
		}
		if n++; n > maxNetEdges {
			break
		}
		out = append(out, NetEdge{
			Kind: EdgeConnection, IP: ip.Unmap().String(), Port: uint16(c.GetPort()), //nolint:gosec // checked above
			Inbound: c.GetInbound(), Count: c.GetCount(),
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

// NeighborJSON is an entry of a device's IPv4 (ARP) or IPv6 (NDP) neighbour
// table.
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
	Port uint16 `json:"port"`
	// Service names the port's well-known service (22 ssh, 443 https);
	// empty when the hub knows no name for it.
	Service string    `json:"service,omitempty"`
	Inbound bool      `json:"inbound"`
	Count   uint32    `json:"count"`
	Peer    *PeerJSON `json:"peer"`
}

// PeerJSON is what the hub knows the other end of an edge to be; null when
// it knows nothing of it.
type PeerJSON struct {
	// Kind is "device" (an enrolled device), "hub" (the hub's own host: an
	// address of its interfaces, which other services there share) or "host" (a
	// host network discovery found).
	Kind string `json:"kind"`
	// ID is the device's id, or the host's MAC; empty for the hub.
	ID   string `json:"id,omitempty"`
	Name string `json:"name"`
}

func (a *api) netEdgeRoutes(mux *http.ServeMux) {
	mux.Handle("GET /api/v1/devices/{id}/net-edges", a.auth(a.deviceNetEdges))
	mux.Handle("GET /api/v1/net-edges", a.auth(a.netTopology))
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
		out, err = a.readNetEdges(ctx, d)
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

// readNetEdges reads and resolves d's edges. An agent that no longer reports
// them (its ceiling dropped --allow-net-edges) lists none, whatever it
// reported before.
func (a *api) readNetEdges(ctx context.Context, d store.Device) (NetEdgesJSON, error) {
	out := NetEdgesJSON{Neighbors: []NeighborJSON{}, Connections: []ConnectionJSON{}, Enabled: netEdgesEnabled(d)}
	if !out.Enabled {
		return out, nil
	}
	if a.netEdges == nil {
		return out, nil
	}
	edges, at := a.netEdges.Get(d.ID)
	if len(edges) == 0 {
		return out, nil
	}
	out.UpdatedAt = &at
	peers, err := a.peerIndex(ctx)
	if err != nil {
		return out, err
	}
	for _, e := range edges {
		if e.Kind == EdgeNeighbor {
			out.Neighbors = append(out.Neighbors, NeighborJSON{IP: e.IP, MAC: e.MAC, Peer: peers.resolve(e.MAC, e.IP)})
			continue
		}
		out.Connections = append(out.Connections, ConnectionJSON{
			IP: e.IP, Port: e.Port, Service: serviceName(e.Port), Inbound: e.Inbound, Count: e.Count, Peer: peers.resolve("", e.IP),
		})
	}
	return out, nil
}

// netEdgesEnabled reports whether d's agent last reported a ceiling that
// allows network edges (it runs with --allow-net-edges).
func netEdgesEnabled(d store.Device) bool {
	var f Facts
	return json.Unmarshal(d.Facts, &f) == nil && f.Ceiling != nil && f.Ceiling.NetEdges
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
// then this hub, then a discovered host; nil if none. An IPv6 link-local
// address names a host on one link only (every host may have fe80::1), so
// it is resolved by MAC alone.
func (p peerIndex) resolve(mac, ip string) *PeerJSON {
	if d := p.deviceByMAC[mac]; mac != "" && d != nil {
		return d
	}
	if a, err := netip.ParseAddr(ip); err == nil && a.Is6() && a.IsLinkLocalUnicast() {
		if h := p.hostByMAC[mac]; mac != "" && h != nil {
			return h
		}
		return nil
	}
	if d := p.deviceByIP[ip]; d != nil {
		return d
	}
	if p.hub[ip] {
		return &PeerJSON{Kind: "hub", Name: "hub host"}
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
