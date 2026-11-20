// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

func TestAPINetTopology(t *testing.T) {
	f := newAPIFixture(t, true, func(c *Config) { c.NetEdges = NewNetEdges() })
	ctx := t.Context()
	now := time.UnixMilli(1_700_000_000_000).UTC()
	device := func(id, facts string) {
		t.Helper()
		if err := f.st.Devices().Upsert(ctx, store.Device{
			ID: id, Name: id, FirstSeen: now, LastSeen: now, Status: store.StatusOnline, Facts: json.RawMessage(facts),
		}); err != nil {
			t.Fatal(err)
		}
	}
	device("pi", `{"ceiling":{"net_edges":true},"interfaces":[{"name":"eth0","mac":"aa:bb:cc:00:00:05","ips":["192.0.2.5/24"]}]}`)
	device("nas", `{"ceiling":{"net_edges":true},"interfaces":[{"name":"eth0","mac":"aa:bb:cc:00:00:06","ips":["192.0.2.6/24"]}]}`)
	device("off", `{"ceiling":{"net_edges":false},"interfaces":[{"name":"eth0","mac":"aa:bb:cc:00:00:08","ips":["192.0.2.8"]}]}`)
	if _, err := f.st.NetworkHosts().RecordScan(ctx, now, time.Hour, []store.NetworkHost{
		{MAC: "aa:bb:cc:00:00:01", IP: "192.0.2.1", Hostname: "router"},
	}); err != nil {
		t.Fatal(err)
	}
	f.api.netEdges.set("pi", now, []NetEdge{
		{Kind: EdgeNeighbor, IP: "192.0.2.1", MAC: "aa:bb:cc:00:00:01"},
		{Kind: EdgeNeighbor, IP: "192.0.2.6", MAC: "aa:bb:cc:00:00:06"},
		{Kind: EdgeConnection, IP: "192.0.2.6", Port: 445, Count: 2},
		{Kind: EdgeConnection, IP: "192.0.2.5", Port: 22, Inbound: true, Count: 1}, // itself: dropped
		{Kind: EdgeConnection, IP: "198.51.100.9", Port: 443, Count: 1},
	})
	later := now.Add(time.Minute)
	f.api.netEdges.set("nas", later, []NetEdge{
		{Kind: EdgeNeighbor, IP: "192.0.2.5", MAC: "aa:bb:cc:00:00:05"},
		{Kind: EdgeConnection, IP: "192.0.2.5", Port: 445, Inbound: true, Count: 3}, // the pi's 445, seen from the NAS
	})
	// Reported before its agent dropped --allow-net-edges: never listed.
	f.api.netEdges.set("off", now, []NetEdge{
		{Kind: EdgeConnection, IP: "203.0.113.7", Port: 8080, Count: 1},
	})

	if resp := f.do(t, http.MethodGet, "/api/v1/net-edges", "", nil); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("without a session: %d, want 401", resp.StatusCode)
	}
	cookie := sessionCookie(t, f.login(t, testPassword))
	resp := f.do(t, http.MethodGet, "/api/v1/net-edges", "", cookie)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	got := decode[TopologyJSON](t, resp)
	if got.Reporting != 2 || got.UpdatedAt == nil || !got.UpdatedAt.Equal(later) {
		t.Errorf("reporting %d, updated %v; want 2, %v", got.Reporting, got.UpdatedAt, later)
	}
	var nodes []string
	for _, n := range got.Nodes {
		nodes = append(nodes, fmt.Sprintf("%s %s %s %s %s %t", n.ID, n.Kind, n.Name, n.DeviceID, n.IP, n.Reports))
	}
	wantNodes := []string{
		"device:nas device nas nas  true",
		"device:pi device pi pi  true",
		"host:aa:bb:cc:00:00:01 host router  192.0.2.1 false",
		"ip:198.51.100.9 unknown 198.51.100.9  198.51.100.9 false",
	}
	if !slices.Equal(nodes, wantNodes) {
		t.Errorf("nodes:\n%q\nwant\n%q", nodes, wantNodes)
	}
	var edges []string
	for _, e := range got.Edges {
		edges = append(edges, fmt.Sprintf("%s %s>%s %d x%d", e.Kind, e.From, e.To, e.Port, e.Count))
	}
	wantEdges := []string{
		"connection device:pi>device:nas 445 x3", // both ends reported it: one edge, the larger count
		"connection device:pi>ip:198.51.100.9 443 x1",
		"neighbor device:nas>device:pi 0 x0", // both ends: one edge
		"neighbor device:pi>host:aa:bb:cc:00:00:01 0 x0",
	}
	if !slices.Equal(edges, wantEdges) {
		t.Errorf("edges:\n%q\nwant\n%q", edges, wantEdges)
	}

	// One audited read for every device, not one per device.
	es, err := f.st.Audit().List(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	var reads []string
	for _, e := range es {
		if e.Action == string(policy.NetworkTopology) || e.Action == string(policy.DeviceNetEdges) {
			reads = append(reads, e.Action+" "+e.Decision)
		}
	}
	if want := []string{"network.topology allow"}; !slices.Equal(reads, want) {
		t.Errorf("audit = %q, want %q", reads, want)
	}
}

func TestAPINetTopologyEmpty(t *testing.T) {
	for _, tc := range []struct {
		name      string
		edges     *NetEdges
		facts     string
		reporting int
		nodes     int
	}{
		{"no devices", NewNetEdges(), "", 0, 0},
		{"no agent reports", NewNetEdges(), `{"ceiling":{}}`, 0, 0},
		{"nothing reported yet", NewNetEdges(), `{"ceiling":{"net_edges":true}}`, 1, 1},
		{"edges not kept", nil, `{"ceiling":{"net_edges":true}}`, 1, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newAPIFixture(t, true, func(c *Config) { c.NetEdges = tc.edges })
			if tc.facts != "" {
				if err := f.st.Devices().Upsert(t.Context(), store.Device{
					ID: "pi", Name: "pi", Status: store.StatusOnline, Facts: json.RawMessage(tc.facts),
				}); err != nil {
					t.Fatal(err)
				}
			}
			cookie := sessionCookie(t, f.login(t, testPassword))
			resp := f.do(t, http.MethodGet, "/api/v1/net-edges", "", cookie)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status %d", resp.StatusCode)
			}
			var raw map[string]json.RawMessage
			if err := json.Unmarshal(resp.body, &raw); err != nil {
				t.Fatal(err)
			}
			if string(raw["edges"]) != "[]" || string(raw["updated_at"]) != "null" {
				t.Errorf("edges %s, updated_at %s; want [], null", raw["edges"], raw["updated_at"])
			}
			got := decode[TopologyJSON](t, resp)
			if got.Reporting != tc.reporting || len(got.Nodes) != tc.nodes {
				t.Errorf("reporting %d, nodes %d; want %d, %d", got.Reporting, len(got.Nodes), tc.reporting, tc.nodes)
			}
		})
	}
}

func TestAPINetTopologyDenied(t *testing.T) {
	f := newAPIFixture(t, true, func(c *Config) {
		c.NetEdges = NewNetEdges()
		c.Policy = policy.NewWithConfig(c.Store.Audit(), nil, policy.Config{
			Actors: map[string]map[policy.Class]policy.Mode{policy.ActorWeb: {policy.Read: policy.ModeDeny}},
		})
	})
	cookie := sessionCookie(t, f.login(t, testPassword))
	if resp := f.do(t, http.MethodGet, "/api/v1/net-edges", "", cookie); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("denied read: %d, want 403", resp.StatusCode)
	}
	es, err := f.st.Audit().List(t.Context(), 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(es) == 0 || es[0].Action != string(policy.NetworkTopology) || es[0].Decision != "deny" {
		t.Errorf("last audit entry = %+v, want a denied network.topology", es)
	}
}
