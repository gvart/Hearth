// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/gvart/hearth/internal/policy"
	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
	"github.com/gvart/hearth/internal/store"
)

var testNetEdges = &agentv1.NetEdges{
	Neighbors: []*agentv1.Neighbor{
		{Ip: "192.0.2.1", Mac: "AA:BB:CC:00:00:01"},
		{Ip: "192.0.2.2", Mac: "ff:ff:ff:ff:ff:ff"}, // broadcast: dropped
		{Ip: "not an ip", Mac: "aa:bb:cc:00:00:02"},
	},
	Connections: []*agentv1.Connection{
		{PeerIp: "192.0.2.10", Port: 7443, Count: 2},
		{PeerIp: "192.0.2.20", Port: 22, Inbound: true, Count: 1},
		{PeerIp: "192.0.2.30", Port: 70000, Count: 1}, // not a port: dropped
		{PeerIp: "192.0.2.31", Port: 80},              // no connection: dropped
	},
}

// The hub stores a report only from an agent whose ceiling allows it: an
// agent that sends one without --allow-net-edges is ignored.
func TestRecordNetEdges(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		ceiling *agentv1.Ceiling
		want    int
	}{
		{"allowed", &agentv1.Ceiling{NetEdges: true}, 3},
		{"not allowed", &agentv1.Ceiling{Probe: true, Shell: true}, 0},
		{"no ceiling", nil, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			st := newTestStore(t)
			enrollDevice(t, st, "dev-1")
			client, _ := newExecClient(t, st)
			stream := connectAgent(ctx, t, client, 8, tc.ceiling)
			if err := stream.Send(&agentv1.AgentMessage{Payload: &agentv1.AgentMessage_NetEdges{NetEdges: testNetEdges}}); err != nil {
				t.Fatal(err)
			}
			// A heartbeat after the report: once it is recorded, so is the report.
			if err := stream.Send(&agentv1.AgentMessage{Payload: &agentv1.AgentMessage_Heartbeat{Heartbeat: &agentv1.Heartbeat{Uptime: durationpb.New(time.Hour)}}}); err != nil {
				t.Fatal(err)
			}
			waitUntil(t, func() bool {
				d, err := st.Devices().Get(ctx, "dev-1")
				return err == nil && !d.BootTime.IsZero()
			})
			got, err := st.NetEdges().Get(ctx, "dev-1")
			if tc.want > 0 {
				waitUntil(t, func() bool {
					got, err = st.NetEdges().Get(ctx, "dev-1")
					return err == nil && len(got.Edges) == tc.want
				})
			}
			if err != nil || len(got.Edges) != tc.want {
				t.Fatalf("stored edges = %+v, %v; want %d", got.Edges, err, tc.want)
			}
			if tc.want > 0 && !slices.Contains(got.Edges, store.NetEdge{Kind: store.EdgeNeighbor, IP: "192.0.2.1", MAC: "aa:bb:cc:00:00:01"}) {
				t.Errorf("stored edges = %+v, want the neighbour's MAC in lower case", got.Edges)
			}
		})
	}
}

func waitUntil(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("timed out")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestAPIDeviceNetEdges(t *testing.T) {
	f := newAPIFixture(t, true)
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
	device("pi", `{"ceiling":{"net_edges":true},"interfaces":[{"name":"eth0","mac":"aa:bb:cc:00:00:05","ips":["192.0.2.5"]}]}`)
	device("nas", `{"interfaces":[{"name":"eth0","mac":"AA:BB:CC:00:00:06","ips":["192.0.2.6/24"]}]}`)
	device("off", `{"ceiling":{"net_edges":false}}`)
	if _, err := f.st.NetworkHosts().RecordScan(ctx, now, time.Hour, []store.NetworkHost{
		{MAC: "aa:bb:cc:00:00:01", IP: "192.0.2.1", Hostname: "router"},
		{MAC: "aa:bb:cc:00:00:07", IP: "192.0.2.7", Vendor: "Synology"},
	}); err != nil {
		t.Fatal(err)
	}
	edges := []store.NetEdge{
		{Kind: store.EdgeNeighbor, IP: "192.0.2.1", MAC: "aa:bb:cc:00:00:01"},  // a host, by MAC
		{Kind: store.EdgeNeighbor, IP: "192.0.2.66", MAC: "aa:bb:cc:00:00:06"}, // the NAS, by MAC
		{Kind: store.EdgeConnection, IP: "192.0.2.6", Port: 445, Count: 2},     // the NAS, by IP
		{Kind: store.EdgeConnection, IP: "192.0.2.7", Port: 22, Inbound: true, Count: 1},
		{Kind: store.EdgeConnection, IP: "198.51.100.9", Port: 443, Count: 1}, // unknown
	}
	for _, id := range []string{"pi", "off"} {
		if _, err := f.st.NetEdges().Replace(ctx, id, now, edges); err != nil {
			t.Fatal(err)
		}
	}

	if resp := f.do(t, http.MethodGet, "/api/v1/devices/pi/net-edges", "", nil); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("without a session: %d, want 401", resp.StatusCode)
	}
	cookie := sessionCookie(t, f.login(t, testPassword))
	if resp := f.do(t, http.MethodGet, "/api/v1/devices/nope/net-edges", "", cookie); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown device: %d, want 404", resp.StatusCode)
	}
	resp := f.do(t, http.MethodGet, "/api/v1/devices/pi/net-edges", "", cookie)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	got := decode[NetEdgesJSON](t, resp)
	if !got.Enabled || got.UpdatedAt == nil || !got.UpdatedAt.Equal(now) || len(got.Neighbors) != 2 || len(got.Connections) != 3 {
		t.Fatalf("edges = %+v", got)
	}
	peer := func(p *PeerJSON) string {
		if p == nil {
			return "-"
		}
		return p.Kind + ":" + p.ID + ":" + p.Name
	}
	for i, want := range []string{"host:aa:bb:cc:00:00:01:router", "device:nas:nas"} {
		if g := peer(got.Neighbors[i].Peer); g != want {
			t.Errorf("neighbour %s = %s, want %s", got.Neighbors[i].IP, g, want)
		}
	}
	for i, want := range []string{"device:nas:nas", "host:aa:bb:cc:00:00:07:Synology", "-"} {
		if g := peer(got.Connections[i].Peer); g != want {
			t.Errorf("connection %s = %s, want %s", got.Connections[i].IP, g, want)
		}
	}
	if c := got.Connections[1]; c.Port != 22 || !c.Inbound || c.Count != 1 {
		t.Errorf("inbound connection = %+v", c)
	}

	// An agent no longer started with --allow-net-edges lists nothing, whatever it reported before.
	off := decode[NetEdgesJSON](t, f.do(t, http.MethodGet, "/api/v1/devices/off/net-edges", "", cookie))
	if off.Enabled || off.UpdatedAt != nil || len(off.Neighbors)+len(off.Connections) != 0 {
		t.Errorf("edges of a device whose agent stopped reporting = %+v, want none", off)
	}

	// Every read is audited.
	es, err := f.st.Audit().List(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	var reads []string
	for _, e := range es {
		if e.Action == string(policy.DeviceNetEdges) {
			reads = append(reads, e.Decision+" "+e.Target)
		}
	}
	slices.Sort(reads)
	if want := []string{"allow off", "allow pi"}; !slices.Equal(reads, want) {
		t.Errorf("audit = %q, want %q", reads, want)
	}
}

func TestAPIDeviceNetEdgesDenied(t *testing.T) {
	f := newAPIFixture(t, true, func(c *Config) {
		c.Policy = policy.NewWithConfig(c.Store.Audit(), nil, policy.Config{
			Actors: map[string]map[policy.Class]policy.Mode{policy.ActorWeb: {policy.Read: policy.ModeDeny}},
		})
	})
	ctx := t.Context()
	if err := f.st.Devices().Upsert(ctx, store.Device{
		ID: "pi", Name: "pi", Status: store.StatusOnline,
		Facts: json.RawMessage(`{"ceiling":{"net_edges":true}}`),
	}); err != nil {
		t.Fatal(err)
	}
	cookie := sessionCookie(t, f.login(t, testPassword))
	if resp := f.do(t, http.MethodGet, "/api/v1/devices/pi/net-edges", "", cookie); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("denied read: %d, want 403", resp.StatusCode)
	}
	es, err := f.st.Audit().List(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(es) == 0 || es[0].Action != string(policy.DeviceNetEdges) || es[0].Decision != "deny" {
		t.Errorf("last audit entry = %+v, want a denied device.net_edges", es)
	}
}
