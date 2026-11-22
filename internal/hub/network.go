// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/gvart/hearth/internal/discovery"
	"github.com/gvart/hearth/internal/policy"
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
	// State is "" (not reviewed), "known", "ignored" or "adopted".
	State string `json:"state"`
	// Name is the name the host was adopted under; "" unless it is adopted.
	Name string `json:"name"`
	// Online is whether a scan or an import saw the host within twice the
	// discover interval.
	Online bool `json:"online"`
	// Sources are where the host was learned: "scan", "pihole", "dhcp",
	// "netalertx".
	Sources []string `json:"sources"`
	// HostnameSource is the source that gave Hostname; "" if none did.
	HostnameSource string `json:"hostname_source"`
	// ScannedBy is the device whose agent last found the host in a scan;
	// "" when the hub did, or no scan found it.
	ScannedBy string `json:"scanned_by"`
	// Services are the mDNS service types the host answers for, as
	// "_ipp._tcp", sorted.
	Services []string `json:"services"`
	// Kind is what the host looks like (discovery.Classify): "router",
	// "printer", "media", "phone", "computer", "nas", "iot" or "unknown".
	Kind discovery.Kind `json:"kind"`
	// AgentCapable is whether the host looks able to run a Hearth agent.
	AgentCapable bool `json:"agent_capable"`
}

func (a *api) networkHostJSON(h store.NetworkHost, deviceID string) NetworkHostJSON {
	sources := h.Sources
	if sources == nil {
		sources = []string{}
	}
	services := h.Services
	if services == nil {
		services = []string{}
	}
	kind, agent := discovery.Classify(h.Services, h.Vendor, h.Hostname, h.Gateway)
	return NetworkHostJSON{
		MAC: h.MAC, IP: h.IP, Hostname: h.Hostname, Vendor: h.Vendor, DeviceID: deviceID,
		FirstSeen: h.FirstSeen, LastSeen: h.LastSeen, State: h.State, Name: h.Name,
		Online:  a.now().Sub(h.LastSeen) <= 2*orDefault(a.discoverInterval, discovery.DefaultInterval),
		Sources: sources, HostnameSource: h.HostnameSource, ScannedBy: h.ScannedBy,
		Services: services, Kind: kind, AgentCapable: agent,
	}
}

// NetworkHosts publishes a discovery event (discovery.EventNew or
// discovery.EventReturned) about the hosts of one scan, if there are any. It
// implements discovery.Events.
func (r *Registry) NetworkHosts(typ string, hosts []store.NetworkHost) {
	if len(hosts) > 0 {
		r.fanout(Event{Type: typ, Hosts: hosts})
	}
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
		out.Hosts = append(out.Hosts, a.networkHostJSON(h, byMAC[h.MAC]))
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

// markNetworkHost serves POST /api/v1/network/hosts/{mac}/known, /ignore and
// /unmark: it sets the host's state, through policy (network.host.mark, with
// the MAC as target and the state as detail). Known and ignored hosts fire
// no new-device alerts.
func (a *api) markNetworkHost(state string) http.HandlerFunc {
	label := state
	if label == store.HostUnreviewed {
		label = "unmarked"
	}
	return func(w http.ResponseWriter, r *http.Request) {
		hw, err := net.ParseMAC(r.PathValue("mac"))
		if err != nil || len(hw) != 6 {
			writeError(w, http.StatusBadRequest, "bad_request", "not a MAC address")
			return
		}
		mac := hw.String()
		err = a.policy.Do(r.Context(), policy.Request{
			ActorKind: policy.ActorWeb, ActorID: remoteHost(r), Action: policy.NetworkHostMark, Target: mac,
			Detail: map[string]any{"state": label},
		}, func(ctx context.Context) error {
			return a.store.NetworkHosts().SetState(ctx, mac, state)
		})
		switch {
		case err == nil:
			w.WriteHeader(http.StatusNoContent)
		case errors.Is(err, policy.ErrDenied):
			writeError(w, http.StatusForbidden, "forbidden", "denied by policy")
		case errors.Is(err, store.ErrNotFound):
			writeError(w, http.StatusNotFound, "not_found", "no such host")
		case errors.Is(err, store.ErrSchemaTooOld):
			writeError(w, http.StatusConflict, "schema_too_old",
				"the hub cluster's database predates marking hosts: upgrade every hub of the cluster first")
		case errors.Is(err, store.ErrUnavailable):
			writeUnavailable(w)
		default:
			a.log.ErrorContext(r.Context(), "mark network host", "err", err)
			writeError(w, http.StatusInternalServerError, "internal", "cannot mark the host")
		}
	}
}

// maxHostName is the longest name, in characters, a host may be adopted
// under.
const maxHostName = 63

// hostName trims an adopted host's name and reports whether it is one: 1 to
// maxHostName printable characters.
func hostName(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if s == "" || utf8.RuneCountInString(s) > maxHostName || !utf8.ValidString(s) {
		return "", false
	}
	for _, r := range s {
		if !unicode.IsPrint(r) {
			return "", false
		}
	}
	return s, true
}

// adoptNetworkHost serves POST /api/v1/network/hosts/{mac}/adopt (adopt
// true, with {"name": "..."}) and /unadopt: it adopts the host as an
// agentless device under the name, or renames it, or unadopts it, through
// policy (network.host.adopt, with the MAC as target and the name, or
// "unadopt", as detail). A host that is an enrolled device's interface is
// that device, and cannot be adopted.
func (a *api) adoptNetworkHost(adopt bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		hw, err := net.ParseMAC(r.PathValue("mac"))
		if err != nil || len(hw) != 6 {
			writeError(w, http.StatusBadRequest, "bad_request", "not a MAC address")
			return
		}
		mac := hw.String()
		detail := map[string]any{"op": "unadopt"}
		var name string
		if adopt {
			var body struct {
				Name string `json:"name"`
			}
			if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<10)).Decode(&body); err != nil {
				writeError(w, http.StatusBadRequest, "bad_request", `want {"name": "..."}`)
				return
			}
			var ok bool
			if name, ok = hostName(body.Name); !ok {
				writeError(w, http.StatusBadRequest, "bad_name",
					"a name is 1 to 63 printable characters")
				return
			}
			devs, err := a.store.Devices().List(r.Context())
			if err != nil {
				a.log.ErrorContext(r.Context(), "list devices", "err", err)
				writeError(w, http.StatusInternalServerError, "internal", "cannot adopt the host")
				return
			}
			if deviceMACs(devs)[mac] != "" {
				writeError(w, http.StatusConflict, "enrolled", "this host is an enrolled device")
				return
			}
			detail = map[string]any{"op": "adopt", "name": name}
		}
		err = a.policy.Do(r.Context(), policy.Request{
			ActorKind: policy.ActorWeb, ActorID: remoteHost(r), Action: policy.NetworkHostAdopt, Target: mac,
			Detail: detail,
		}, func(ctx context.Context) error {
			if adopt {
				return a.store.NetworkHosts().Adopt(ctx, mac, name)
			}
			return a.store.NetworkHosts().Unadopt(ctx, mac)
		})
		switch {
		case err == nil:
			w.WriteHeader(http.StatusNoContent)
		case errors.Is(err, policy.ErrDenied):
			writeError(w, http.StatusForbidden, "forbidden", "denied by policy")
		case errors.Is(err, store.ErrNotFound):
			writeError(w, http.StatusNotFound, "not_found", "no such host")
		case errors.Is(err, store.ErrSchemaTooOld):
			writeError(w, http.StatusConflict, "schema_too_old",
				"the hub cluster's database predates adopting hosts: upgrade every hub of the cluster first")
		case errors.Is(err, store.ErrUnavailable):
			writeUnavailable(w)
		default:
			a.log.ErrorContext(r.Context(), "adopt network host", "err", err)
			writeError(w, http.StatusInternalServerError, "internal", "cannot adopt the host")
		}
	}
}
