// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"cmp"
	"context"
	"database/sql"
	"fmt"
	"slices"
	"strings"
	"time"
)

// netEdgesSchema is the schema version whose migration (00027) added the
// net_edges table. Before it no edge is stored or listed.
const netEdgesSchema = 27

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
	Kind string `json:"kind"`
	// IP is the peer's address.
	IP string `json:"ip"`
	// MAC is the neighbour's MAC address, lower-case and colon-separated;
	// empty for a connection.
	MAC string `json:"mac,omitempty"`
	// Port is a connection's service port: the peer's for an outbound
	// connection, the device's own for an inbound one; 0 for a neighbour.
	Port uint16 `json:"port,omitempty"`
	// Inbound is set when the peer connected to the device.
	Inbound bool `json:"inbound,omitempty"`
	// Count is how many connections the group holds; 0 for a neighbour.
	Count uint32 `json:"count,omitempty"`
}

// compareEdges orders edges as Get lists them.
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

// DeviceNetEdges are the edges a device's agent last reported.
type DeviceNetEdges struct {
	Edges []NetEdge
	// UpdatedAt is when the set last changed; zero when there is none.
	UpdatedAt time.Time
}

// ReplaceNetEdges replaces every network edge of a device with Edges.
type ReplaceNetEdges struct {
	DeviceID string    `json:"device_id"`
	At       int64     `json:"at"`
	Edges    []NetEdge `json:"edges"`
}

// Op implements Command.
func (ReplaceNetEdges) Op() string { return "replace_net_edges" }

func (ReplaceNetEdges) minSchema() int64 { return netEdgesSchema }

func (c ReplaceNetEdges) apply(ctx context.Context, tx *sql.Tx) (Result, error) {
	if _, err := tx.ExecContext(ctx, `DELETE FROM net_edges WHERE device_id = ?`, c.DeviceID); err != nil {
		return Result{}, err
	}
	for _, e := range c.Edges {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO net_edges (device_id, kind, ip, mac, port, inbound, count, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT DO NOTHING`,
			c.DeviceID, e.Kind, e.IP, e.MAC, e.Port, e.Inbound, e.Count, c.At); err != nil {
			return Result{}, err
		}
	}
	return Result{Count: len(c.Edges)}, nil
}

// NetEdges is the repository for the network edges agents report.
type NetEdges struct{ s *Store }

// NetEdges returns the network edge repository.
func (s *Store) NetEdges() NetEdges { return NetEdges{s: s} }

// Replace stores edges as the device's edges at time at, unless they are the
// ones already stored (in any order): an agent reports every minute, and an
// unchanged report writes nothing. changed reports whether it wrote. Before
// schema 27 it fails with ErrSchemaTooOld.
func (r NetEdges) Replace(ctx context.Context, deviceID string, at time.Time, edges []NetEdge) (changed bool, err error) {
	v, err := schemaVersion(ctx, r.s.db)
	if err != nil {
		return false, fmt.Errorf("replace network edges: %w", err)
	}
	if v < netEdgesSchema {
		return false, fmt.Errorf("replace network edges: %w: it needs %d, the database is at %d; run `hearth cluster migrate` first",
			ErrSchemaTooOld, netEdgesSchema, v)
	}
	edges = slices.Clone(edges)
	slices.SortFunc(edges, compareEdges)
	edges = slices.CompactFunc(edges, func(a, b NetEdge) bool { return compareEdges(a, b) == 0 })
	cur, err := r.Get(ctx, deviceID)
	if err != nil {
		return false, fmt.Errorf("replace network edges: %w", err)
	}
	if slices.Equal(cur.Edges, edges) {
		return false, nil
	}
	if _, err := r.s.apply(ctx, ReplaceNetEdges{DeviceID: deviceID, At: toMillis(at), Edges: edges}); err != nil {
		return false, fmt.Errorf("replace network edges: %w", err)
	}
	return true, nil
}

// Get returns the edges a device's agent last reported, by kind, IP, port
// and direction. Before schema 27 there are none.
func (r NetEdges) Get(ctx context.Context, deviceID string) (DeviceNetEdges, error) {
	v, err := schemaVersion(ctx, r.s.db)
	if err != nil {
		return DeviceNetEdges{}, fmt.Errorf("get network edges: %w", err)
	}
	if v < netEdgesSchema {
		return DeviceNetEdges{}, nil
	}
	rows, err := r.s.db.QueryContext(ctx, `
		SELECT kind, ip, mac, port, inbound, count, updated_at FROM net_edges
		WHERE device_id = ? ORDER BY kind, ip, port, inbound`, deviceID)
	if err != nil {
		return DeviceNetEdges{}, fmt.Errorf("get network edges: %w", err)
	}
	defer rows.Close()
	var out DeviceNetEdges
	for rows.Next() {
		var (
			e  NetEdge
			at int64
		)
		if err := rows.Scan(&e.Kind, &e.IP, &e.MAC, &e.Port, &e.Inbound, &e.Count, &at); err != nil {
			return DeviceNetEdges{}, fmt.Errorf("get network edges: %w", err)
		}
		out.Edges = append(out.Edges, e)
		out.UpdatedAt = fromMillis(at)
	}
	if err := rows.Err(); err != nil {
		return DeviceNetEdges{}, fmt.Errorf("get network edges: %w", err)
	}
	return out, nil
}
