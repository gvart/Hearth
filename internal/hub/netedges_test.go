// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/gvart/hearth/internal/policy"
	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
	"github.com/gvart/hearth/internal/proto/hearth/agent/v1/agentv1connect"
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

// newNetEdgesClient serves an AgentStream for dev-1 that keeps network
// edges, as NewHandler serves it, and returns a client and the edges.
func newNetEdgesClient(t *testing.T, st *store.Store) (agentv1connect.AgentServiceClient, *NetEdges) {
	t.Helper()
	as := NewAgentStream(slog.New(slog.DiscardHandler), 5*time.Second, NewRegistry(RegistryConfig{Store: st}))
	as.netEdges = NewNetEdges()
	path, h := agentServiceHandler(as)
	mux := http.NewServeMux()
	mux.Handle(path, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r.WithContext(withDeviceID(r.Context(), "dev-1")))
	}))
	srv := httptest.NewUnstartedServer(mux)
	srv.Config.Protocols = new(http.Protocols)
	srv.Config.Protocols.SetUnencryptedHTTP2(true)
	srv.Start()
	t.Cleanup(srv.Close)
	transport := &http.Transport{Protocols: new(http.Protocols)}
	transport.Protocols.SetUnencryptedHTTP2(true)
	t.Cleanup(transport.CloseIdleConnections)
	return agentv1connect.NewAgentServiceClient(&http.Client{Transport: transport}, srv.URL), as.netEdges
}

func sendNetEdges(t *testing.T, stream *connect.BidiStreamForClient[agentv1.AgentMessage, agentv1.HubMessage], e *agentv1.NetEdges) {
	t.Helper()
	if err := stream.Send(&agentv1.AgentMessage{Payload: &agentv1.AgentMessage_NetEdges{NetEdges: e}}); err != nil {
		t.Fatal(err)
	}
}

// settle waits until the hub handled every message sent before: a heartbeat
// with uptime sets the device's boot time once it is handled.
func settle(ctx context.Context, t *testing.T, st *store.Store, stream *connect.BidiStreamForClient[agentv1.AgentMessage, agentv1.HubMessage], uptime time.Duration) {
	t.Helper()
	if err := stream.Send(&agentv1.AgentMessage{Payload: &agentv1.AgentMessage_Heartbeat{Heartbeat: &agentv1.Heartbeat{Uptime: durationpb.New(uptime)}}}); err != nil {
		t.Fatal(err)
	}
	want := time.Now().Add(-uptime)
	waitUntil(t, func() bool {
		d, err := st.Devices().Get(ctx, "dev-1")
		return err == nil && !d.BootTime.IsZero() && d.BootTime.Sub(want).Abs() < time.Minute
	})
}

// The hub keeps a report only from an agent whose ceiling allows it: an
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
			client, edges := newNetEdgesClient(t, st)
			stream := connectAgent(ctx, t, client, 8, tc.ceiling)
			sendNetEdges(t, stream, testNetEdges)
			settle(ctx, t, st, stream, time.Hour)
			got, _ := edges.Get("dev-1")
			if len(got) != tc.want {
				t.Fatalf("kept edges = %+v; want %d", got, tc.want)
			}
			if tc.want > 0 && !slices.Contains(got, NetEdge{Kind: EdgeNeighbor, IP: "192.0.2.1", MAC: "aa:bb:cc:00:00:01"}) {
				t.Errorf("kept edges = %+v, want the neighbour's MAC in lower case", got)
			}
		})
	}
}

// Addresses with a zone, which may be of any length, and neighbours that
// are not unicast IPv4 or IPv6 are dropped.
func TestNetEdgesFromRejects(t *testing.T) {
	zone := strings.Repeat("z", 100<<10)
	got := netEdgesFrom(&agentv1.NetEdges{
		Neighbors: []*agentv1.Neighbor{
			{Ip: "fe80::1%" + zone, Mac: "aa:bb:cc:00:00:01"},
			{Ip: "2001:db8::1", Mac: "aa:bb:cc:00:00:02"},
			{Ip: "::ffff:192.0.2.3", Mac: "aa:bb:cc:00:00:03"},
			{Ip: "192.0.2.4", Mac: "aa:bb:cc:00:00:04"},
			{Ip: "fe80::5", Mac: "aa:bb:cc:00:00:05"},
			{Ip: "ff02::1", Mac: "aa:bb:cc:00:00:06"},
			{Ip: "::1", Mac: "aa:bb:cc:00:00:07"},
			{Ip: "::", Mac: "aa:bb:cc:00:00:08"},
			{Ip: "fe80::9", Mac: "33:33:00:00:00:01"},
		},
		Connections: []*agentv1.Connection{
			{PeerIp: "fe80::1%" + zone, Port: 22, Count: 1},
			{PeerIp: "fe80::1", Port: 22, Count: 1},
		},
	})
	want := []NetEdge{
		{Kind: EdgeNeighbor, IP: "2001:db8::1", MAC: "aa:bb:cc:00:00:02"},
		{Kind: EdgeNeighbor, IP: "192.0.2.4", MAC: "aa:bb:cc:00:00:04"},
		{Kind: EdgeNeighbor, IP: "fe80::5", MAC: "aa:bb:cc:00:00:05"},
		{Kind: EdgeConnection, IP: "fe80::1", Port: 22, Count: 1},
	}
	if !slices.Equal(got, want) {
		t.Errorf("netEdgesFrom = %+v, want %+v", got, want)
	}
}

// One stream's reports are taken at most every minNetEdgesGap: an agent that
// reports in a loop changes nothing between two.
func TestRecordNetEdgesRateLimit(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	st := newTestStore(t)
	enrollDevice(t, st, "dev-1")
	client, edges := newNetEdgesClient(t, st)
	stream := connectAgent(ctx, t, client, 8, &agentv1.Ceiling{NetEdges: true})
	first := &agentv1.NetEdges{Connections: []*agentv1.Connection{{PeerIp: "192.0.2.10", Port: 7443, Count: 1}}}
	sendNetEdges(t, stream, first)
	for range 50 {
		sendNetEdges(t, stream, testNetEdges)
	}
	settle(ctx, t, st, stream, time.Hour)
	if got, _ := edges.Get("dev-1"); len(got) != 1 || got[0].IP != "192.0.2.10" {
		t.Errorf("kept edges = %+v, want only the first report's", got)
	}
}

// When the agent reports a ceiling without net_edges, in its facts or when
// it reconnects, the hub forgets what it reported before.
func TestNetEdgesForgottenWhenTurnedOff(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	st := newTestStore(t)
	enrollDevice(t, st, "dev-1")
	client, edges := newNetEdgesClient(t, st)
	stream := connectAgent(ctx, t, client, 8, &agentv1.Ceiling{NetEdges: true})
	sendNetEdges(t, stream, testNetEdges)
	settle(ctx, t, st, stream, time.Hour)
	if got, _ := edges.Get("dev-1"); len(got) == 0 {
		t.Fatal("no edges kept")
	}
	facts := hello(ProtocolMajor).GetHello()
	facts.Ceiling = &agentv1.Ceiling{Probe: true}
	if err := stream.Send(&agentv1.AgentMessage{Payload: &agentv1.AgentMessage_Facts{Facts: facts}}); err != nil {
		t.Fatal(err)
	}
	settle(ctx, t, st, stream, 2*time.Hour)
	if got, _ := edges.Get("dev-1"); len(got) != 0 {
		t.Errorf("edges after the flag was turned off = %+v, want none", got)
	}

	// A reconnect without the flag forgets them too.
	edges.set("dev-1", time.Now(), []NetEdge{{Kind: EdgeNeighbor, IP: "192.0.2.1", MAC: "aa:bb:cc:00:00:01"}})
	_ = stream.CloseRequest()
	stream2 := connectAgent(ctx, t, client, 8, &agentv1.Ceiling{Shell: true})
	settle(ctx, t, st, stream2, 3*time.Hour)
	if got, _ := edges.Get("dev-1"); len(got) != 0 {
		t.Errorf("edges after a reconnect without the flag = %+v, want none", got)
	}
}

// A message larger than maxAgentMessage ends the stream; a full batch of
// log lines, the largest an agent sends, fits well within it.
func TestAgentMessageCap(t *testing.T) {
	t.Parallel()
	batch := &agentv1.LogLines{Id: "l"}
	for range 64 {
		batch.Lines = append(batch.Lines, &agentv1.LogLine{Text: strings.Repeat("x", 4<<10)})
	}
	if n := proto.Size(&agentv1.AgentMessage{Payload: &agentv1.AgentMessage_LogLines{LogLines: batch}}); n > maxAgentMessage/8 {
		t.Errorf("a full log batch is %d bytes, too close to the cap of %d", n, maxAgentMessage)
	}

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	st := newTestStore(t)
	enrollDevice(t, st, "dev-1")
	client, edges := newNetEdgesClient(t, st)
	stream := connectAgent(ctx, t, client, 8, &agentv1.Ceiling{NetEdges: true})
	huge := &agentv1.NetEdges{Connections: []*agentv1.Connection{{PeerIp: "fe80::1%" + strings.Repeat("z", maxAgentMessage), Port: 22, Count: 1}}}
	_ = stream.Send(&agentv1.AgentMessage{Payload: &agentv1.AgentMessage_NetEdges{NetEdges: huge}})
	_, err := stream.Receive()
	if connect.CodeOf(err) != connect.CodeResourceExhausted {
		t.Errorf("stream after an oversized message: %v, want ResourceExhausted", err)
	}
	if got, _ := edges.Get("dev-1"); len(got) != 0 {
		t.Errorf("kept edges = %+v, want none", got)
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
	device("pi", `{"ceiling":{"net_edges":true},"interfaces":[{"name":"eth0","mac":"aa:bb:cc:00:00:05","ips":["192.0.2.5"]}]}`)
	device("nas", `{"interfaces":[{"name":"eth0","mac":"AA:BB:CC:00:00:06","ips":["192.0.2.6/24","fe80::6/64"]}]}`)
	device("off", `{"ceiling":{"net_edges":false}}`)
	if _, err := f.st.NetworkHosts().RecordScan(ctx, now, time.Hour, []store.NetworkHost{
		{MAC: "aa:bb:cc:00:00:01", IP: "192.0.2.1", Hostname: "router"},
		{MAC: "aa:bb:cc:00:00:07", IP: "192.0.2.7", Vendor: "Synology"},
	}); err != nil {
		t.Fatal(err)
	}
	edges := []NetEdge{
		{Kind: EdgeNeighbor, IP: "192.0.2.1", MAC: "aa:bb:cc:00:00:01"},  // a host, by MAC
		{Kind: EdgeNeighbor, IP: "192.0.2.66", MAC: "aa:bb:cc:00:00:06"}, // the NAS, by MAC
		{Kind: EdgeNeighbor, IP: "fe80::1", MAC: "aa:bb:cc:00:00:01"},    // the router's IPv6 address, by MAC
		{Kind: EdgeNeighbor, IP: "fe80::6", MAC: "aa:bb:cc:00:00:09"},    // the NAS's link-local address, on another link: unknown
		{Kind: EdgeConnection, IP: "192.0.2.6", Port: 445, Count: 2},     // the NAS, by IP
		{Kind: EdgeConnection, IP: "192.0.2.7", Port: 22, Inbound: true, Count: 1},
		{Kind: EdgeConnection, IP: "198.51.100.9", Port: 443, Count: 1}, // unknown
		{Kind: EdgeConnection, IP: "fe80::6", Port: 445, Count: 1},      // the NAS by its link-local address: a connection has no MAC
	}
	for _, id := range []string{"pi", "off"} {
		f.api.netEdges.set(id, now, edges)
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
	if !got.Enabled || got.UpdatedAt == nil || !got.UpdatedAt.Equal(now) || len(got.Neighbors) != 4 || len(got.Connections) != 4 {
		t.Fatalf("edges = %+v", got)
	}
	peer := func(p *PeerJSON) string {
		if p == nil {
			return "-"
		}
		return p.Kind + ":" + p.ID + ":" + p.Name
	}
	for i, want := range []string{"host:aa:bb:cc:00:00:01:router", "device:nas:nas", "host:aa:bb:cc:00:00:01:router", "-"} {
		if g := peer(got.Neighbors[i].Peer); g != want {
			t.Errorf("neighbour %s = %s, want %s", got.Neighbors[i].IP, g, want)
		}
	}
	for i, want := range []string{"device:nas:nas", "host:aa:bb:cc:00:00:07:Synology", "-", "device:nas:nas"} {
		if g := peer(got.Connections[i].Peer); g != want {
			t.Errorf("connection %s = %s, want %s", got.Connections[i].IP, g, want)
		}
	}
	if c := got.Connections[1]; c.Port != 22 || !c.Inbound || c.Count != 1 {
		t.Errorf("inbound connection = %+v", c)
	}
	for i, want := range []string{"smb", "ssh", "https"} {
		if g := got.Connections[i].Service; g != want {
			t.Errorf("connection %s:%d service = %q, want %q", got.Connections[i].IP, got.Connections[i].Port, g, want)
		}
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

// A peer resolves to an enrolled device first, by MAC then by IP, then to
// the hub's own host, then to a discovered host.
func TestPeerIndexResolve(t *testing.T) {
	dev := &PeerJSON{Kind: "device", ID: "pi", Name: "pi"}
	host := &PeerJSON{Kind: "host", ID: "aa:bb:cc:00:00:07", Name: "nas"}
	p := peerIndex{
		deviceByMAC: map[string]*PeerJSON{"aa:bb:cc:00:00:05": dev},
		deviceByIP:  map[string]*PeerJSON{"192.0.2.5": dev},
		hostByMAC:   map[string]*PeerJSON{"aa:bb:cc:00:00:07": host},
		hostByIP:    map[string]*PeerJSON{"192.0.2.7": host, "192.0.2.10": host},
		hub:         map[string]bool{"192.0.2.10": true, "192.0.2.5": true},
	}
	for _, tc := range []struct{ mac, ip, want string }{
		{"aa:bb:cc:00:00:05", "192.0.2.99", "device:pi"}, // the device's MAC at a new address
		{"", "192.0.2.5", "device:pi"},                   // a device on the hub's host is the device
		{"", "192.0.2.10", "hub:"},                       // the hub before a host of the same IP
		{"aa:bb:cc:00:00:07", "192.0.2.99", "host:aa:bb:cc:00:00:07"},
		{"", "192.0.2.7", "host:aa:bb:cc:00:00:07"},
		{"aa:bb:cc:00:00:99", "198.51.100.1", "-"},
	} {
		got := "-"
		if r := p.resolve(tc.mac, tc.ip); r != nil {
			got = r.Kind + ":" + r.ID
		}
		if got != tc.want {
			t.Errorf("resolve(%q, %q) = %s, want %s", tc.mac, tc.ip, got, tc.want)
		}
	}
}
