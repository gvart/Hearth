// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/integrations/talos"
	"github.com/gvart/hearth/internal/store"
)

type fixedTalos talos.Snapshot

func (s fixedTalos) Snapshot() talos.Snapshot { return talos.Snapshot(s) }

func TestAPITalosNodesNotConfigured(t *testing.T) {
	f := newAPIFixture(t, true)
	if resp := f.do(t, http.MethodGet, "/api/v1/talos/nodes", "", nil); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("without a session: %d, want 401", resp.StatusCode)
	}
	cookie := sessionCookie(t, f.login(t, testPassword))
	got := decode[TalosNodesJSON](t, f.do(t, http.MethodGet, "/api/v1/talos/nodes", "", cookie))
	if got.Status != "not_configured" || got.Nodes == nil || len(got.Nodes) != 0 || got.ReadAt != nil {
		t.Errorf("body = %+v", got)
	}
}

// Each node is matched to the enrolled device it is (the DaemonSet's agent
// on it): by the address it is read at, then by its hostname. A node is
// never a device of its own, so it is not listed twice.
func TestAPITalosNodes(t *testing.T) {
	now := time.UnixMilli(1_700_000_000_000).UTC()
	snap := fixedTalos{State: talos.StateOK, ReadAt: now, Nodes: []talos.Node{
		{Address: "192.168.2.196", Hostname: "k8s-cp-01", Version: "v1.12.7", Healthy: true},
		{Address: "192.168.2.197", Hostname: "k8s-worker-01", Version: "v1.12.7"},
		{Address: "192.168.2.198", Hostname: "k8s-worker-02"},
		{Address: "192.168.2.224", Error: "no route to host"},
	}}
	f := newAPIFixture(t, true, func(c *Config) { c.Talos = snap })
	for _, d := range []store.Device{
		{
			ID: "cp", Name: "k8s-cp-01", Hostname: "k8s-cp-01", FirstSeen: now, LastSeen: now, Status: store.StatusOnline,
			Facts: json.RawMessage(`{"interfaces":[{"name":"enp1s0","ips":["192.168.2.196/24"]}]}`),
		},
		{ID: "w1", Name: "worker one", Hostname: "K8S-WORKER-01.lan", FirstSeen: now, LastSeen: now, Status: store.StatusOnline},
	} {
		if err := f.st.Devices().Upsert(t.Context(), d); err != nil {
			t.Fatal(err)
		}
	}
	cookie := sessionCookie(t, f.login(t, testPassword))
	got := decode[TalosNodesJSON](t, f.do(t, http.MethodGet, "/api/v1/talos/nodes", "", cookie))
	if got.Status != "ok" || got.ReadAt == nil || !got.ReadAt.Equal(now) || len(got.Nodes) != 4 {
		t.Fatalf("body = %+v", got)
	}
	for i, want := range []string{"cp", "w1", "", ""} {
		if n := got.Nodes[i]; n.DeviceID != want {
			t.Errorf("node %s matched %q; want %q", n.Address, n.DeviceID, want)
		}
	}
	if n := got.Nodes[1]; n.DeviceName != "worker one" || n.Version != "v1.12.7" {
		t.Errorf("node 1 = %+v", n)
	}
	if n := got.Nodes[3]; n.Error != "no route to host" {
		t.Errorf("node 3 = %+v", n)
	}
}

func TestAPITalosNodesUnavailable(t *testing.T) {
	snap := fixedTalos{State: talos.StateUnavailable, Error: "talos Version: connection refused"}
	f := newAPIFixture(t, true, func(c *Config) { c.Talos = snap })
	cookie := sessionCookie(t, f.login(t, testPassword))
	got := decode[TalosNodesJSON](t, f.do(t, http.MethodGet, "/api/v1/talos/nodes", "", cookie))
	if got.Status != "unavailable" || got.Error != snap.Error || got.ReadAt != nil || len(got.Nodes) != 0 {
		t.Errorf("body = %+v", got)
	}
}
