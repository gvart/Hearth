// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"net/http"
	"time"

	"github.com/gvart/hearth/internal/integrations/talos"
	"github.com/gvart/hearth/internal/store"
)

// TalosSnapshotter gives what the hub last read from the Talos API:
// *talos.Reader.
type TalosSnapshotter interface {
	Snapshot() talos.Snapshot
}

// TalosNodeJSON is a Talos node, with the Hearth device it is, if any.
type TalosNodeJSON struct {
	talos.Node
	// DeviceID and DeviceName are the enrolled device the node is (the
	// agent of the Hearth DaemonSet on it, say); "" if none.
	DeviceID   string `json:"device_id"`
	DeviceName string `json:"device_name"`
}

// TalosNodesJSON is the body of GET /api/v1/talos/nodes.
type TalosNodesJSON struct {
	// Status is "not_configured", "connecting", "ok", "unavailable" or
	// "standby" (a hub of a cluster it does not lead: only the leader reads).
	Status string `json:"status"`
	// Error is why the last read failed.
	Error string `json:"error,omitempty"`
	// ReadAt is when the last read that succeeded finished.
	ReadAt *time.Time      `json:"read_at"`
	Nodes  []TalosNodeJSON `json:"nodes"`
}

// listTalosNodes serves GET /api/v1/talos/nodes: the Talos nodes the hub
// last read, each matched to the enrolled device it is. It reads nothing
// from the Talos API itself.
func (a *api) listTalosNodes(w http.ResponseWriter, r *http.Request) {
	out := TalosNodesJSON{Status: "not_configured", Nodes: []TalosNodeJSON{}}
	if a.talos == nil {
		writeJSON(w, http.StatusOK, out)
		return
	}
	ctx := r.Context()
	snap := a.talos.Snapshot()
	out.Status, out.Error = snap.State, snap.Error
	if !snap.ReadAt.IsZero() {
		out.ReadAt = &snap.ReadAt
	}
	devs, err := a.store.Devices().List(ctx)
	if err != nil {
		a.log.ErrorContext(ctx, "list devices", "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "cannot list talos nodes")
		return
	}
	m := newTalosMatcher(devs)
	for _, n := range snap.Nodes {
		out.Nodes = append(out.Nodes, m.match(n))
	}
	writeJSON(w, http.StatusOK, out)
}

// talosMatcher finds the device a Talos node is: by the address it is read
// at, then by its hostname or the name it is read at. When devices share an
// address or a name (a node re-enrolled, a reused address), the one seen last
// wins.
type talosMatcher struct {
	byAddr, byName map[string]store.Device
}

func newTalosMatcher(devs []store.Device) talosMatcher {
	m := talosMatcher{byAddr: map[string]store.Device{}, byName: map[string]store.Device{}}
	keep := func(idx map[string]store.Device, k string, d store.Device) {
		if old, ok := idx[k]; !ok || d.LastSeen.After(old.LastSeen) {
			idx[k] = d
		}
	}
	for _, d := range devs {
		pd := promDevice(d)
		for _, n := range nameKeys(pd.Hostname) {
			keep(m.byName, n, d)
		}
		for _, a := range pd.Addrs {
			if k, ok := addrKey(a); ok {
				keep(m.byAddr, k, d)
			}
		}
	}
	return m
}

func (m talosMatcher) match(n talos.Node) TalosNodeJSON {
	out := TalosNodeJSON{Node: n}
	if k, ok := addrKey(n.Address); ok {
		if d, ok := m.byAddr[k]; ok {
			out.DeviceID, out.DeviceName = d.ID, d.Name
			return out
		}
	}
	for _, k := range append(nameKeys(n.Hostname), nameKeys(n.Address)...) {
		if d, ok := m.byName[k]; ok {
			out.DeviceID, out.DeviceName = d.ID, d.Name
			return out
		}
	}
	return out
}
