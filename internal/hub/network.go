// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/gvart/hearth/internal/store"
)

// NetworkHostJSON is the API representation of a host network discovery
// found (see internal/discovery).
type NetworkHostJSON struct {
	MAC      string `json:"mac"`
	IP       string `json:"ip"`
	Hostname string `json:"hostname"`
	Vendor   string `json:"vendor"`
	// DeviceID is the enrolled device one of whose interfaces has this MAC;
	// "" for an unmanaged host.
	DeviceID  string    `json:"device_id"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

func networkHostJSON(h store.NetworkHost, deviceID string) NetworkHostJSON {
	return NetworkHostJSON{
		MAC: h.MAC, IP: h.IP, Hostname: h.Hostname, Vendor: h.Vendor, DeviceID: deviceID,
		FirstSeen: h.FirstSeen, LastSeen: h.LastSeen,
	}
}

// NetworkHost publishes a discovery event (discovery.EventNew or
// discovery.EventReturned) about h. It implements discovery.Events.
func (r *Registry) NetworkHost(typ string, h store.NetworkHost) {
	r.bus.publish(Event{Type: typ, Host: &h})
}

// listNetworkHosts serves GET /api/v1/network/hosts: every host discovery
// found, with the enrolled device it is, if any.
func (a *api) listNetworkHosts(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	hosts, err := a.store.NetworkHosts().List(ctx)
	if err != nil {
		a.log.ErrorContext(ctx, "list network hosts", "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "cannot list network hosts")
		return
	}
	devs, err := a.store.Devices().List(ctx)
	if err != nil {
		a.log.ErrorContext(ctx, "list devices", "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "cannot list network hosts")
		return
	}
	byMAC := deviceMACs(devs)
	out := struct {
		Hosts []NetworkHostJSON `json:"hosts"`
	}{Hosts: make([]NetworkHostJSON, 0, len(hosts))}
	for _, h := range hosts {
		out.Hosts = append(out.Hosts, networkHostJSON(h, byMAC[h.MAC]))
	}
	writeJSON(w, http.StatusOK, out)
}

// deviceMACs maps the interface MACs the agents reported to their devices.
func deviceMACs(devs []store.Device) map[string]string {
	out := map[string]string{}
	for _, d := range devs {
		var f Facts
		if json.Unmarshal(d.Facts, &f) != nil {
			continue
		}
		for _, i := range f.Interfaces {
			if i.MAC != "" {
				out[strings.ToLower(i.MAC)] = d.ID
			}
		}
	}
	return out
}
