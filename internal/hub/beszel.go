// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/gvart/hearth/internal/integrations/beszel"
	"github.com/gvart/hearth/internal/store"
)

// BeszelSnapshotter gives what the hub last read from a Beszel hub:
// *beszel.Reader.
type BeszelSnapshotter interface {
	Snapshot() beszel.Snapshot
}

// BeszelSystemJSON is a system Beszel monitors, with the Hearth device or
// network host it is, if any.
type BeszelSystemJSON struct {
	beszel.System
	// DeviceID and DeviceName are the enrolled device the system is; ""
	// if none.
	DeviceID   string `json:"device_id"`
	DeviceName string `json:"device_name"`
	// NetworkMAC is the network host the system is, when it is no enrolled
	// device; "" if none.
	NetworkMAC string `json:"network_mac"`
}

// BeszelSystemsJSON is the body of GET /api/v1/beszel/systems.
type BeszelSystemsJSON struct {
	// Status is "not_configured", "connecting", "ok" or "unavailable".
	Status string `json:"status"`
	// Error is why the last read failed.
	Error string `json:"error,omitempty"`
	// ReadAt is when the last read that succeeded finished.
	ReadAt  *time.Time         `json:"read_at"`
	Systems []BeszelSystemJSON `json:"systems"`
}

// listBeszelSystems serves GET /api/v1/beszel/systems: the systems the hub
// last read from Beszel, each matched to the enrolled device or network
// host it is. It reads nothing from Beszel itself.
func (a *api) listBeszelSystems(w http.ResponseWriter, r *http.Request) {
	out := BeszelSystemsJSON{Status: "not_configured", Systems: []BeszelSystemJSON{}}
	if a.beszel == nil {
		writeJSON(w, http.StatusOK, out)
		return
	}
	ctx := r.Context()
	snap := a.beszel.Snapshot()
	out.Status, out.Error = snap.State, snap.Error
	if !snap.ReadAt.IsZero() {
		out.ReadAt = &snap.ReadAt
	}
	devs, err := a.store.Devices().List(ctx)
	if err != nil {
		a.log.ErrorContext(ctx, "list devices", "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "cannot list beszel systems")
		return
	}
	hosts, err := a.store.NetworkHosts().List(ctx)
	if err != nil {
		a.log.ErrorContext(ctx, "list network hosts", "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "cannot list beszel systems")
		return
	}
	m := newSystemMatcher(devs, hosts)
	for _, s := range snap.Systems {
		out.Systems = append(out.Systems, m.match(s))
	}
	writeJSON(w, http.StatusOK, out)
}

// systemMatcher finds the device or network host a Beszel system is, by the
// address or name Beszel reaches it at, then by its Beszel name.
type systemMatcher struct {
	devByAddr, devByName   map[string]store.Device
	hostByAddr, hostByName map[string]store.NetworkHost
}

func newSystemMatcher(devs []store.Device, hosts []store.NetworkHost) systemMatcher {
	m := systemMatcher{
		devByAddr: map[string]store.Device{}, devByName: map[string]store.Device{},
		hostByAddr: map[string]store.NetworkHost{}, hostByName: map[string]store.NetworkHost{},
	}
	macs := deviceMACs(devs)
	for _, d := range devs {
		pd := promDevice(d)
		for _, n := range nameKeys(pd.Hostname) {
			m.devByName[n] = d
		}
		for _, a := range pd.Addrs {
			if k, ok := addrKey(a); ok {
				m.devByAddr[k] = d
			}
		}
	}
	for _, h := range hosts {
		if macs[h.MAC] != "" {
			continue // an enrolled device: matched as one
		}
		if k, ok := addrKey(h.IP); ok {
			m.hostByAddr[k] = h
		}
		for _, n := range nameKeys(h.Hostname) {
			m.hostByName[n] = h
		}
	}
	return m
}

func (m systemMatcher) match(s beszel.System) BeszelSystemJSON {
	out := BeszelSystemJSON{System: s}
	addr, isAddr := addrKey(s.Host)
	var keys []string
	if !isAddr {
		keys = nameKeys(s.Host)
	}
	keys = append(keys, nameKeys(s.Name)...)
	if d, ok := m.devByAddr[addr]; isAddr && ok {
		out.DeviceID, out.DeviceName = d.ID, d.Name
		return out
	}
	for _, k := range keys {
		if d, ok := m.devByName[k]; ok {
			out.DeviceID, out.DeviceName = d.ID, d.Name
			return out
		}
	}
	if h, ok := m.hostByAddr[addr]; isAddr && ok {
		out.NetworkMAC = h.MAC
		return out
	}
	for _, k := range keys {
		if h, ok := m.hostByName[k]; ok {
			out.NetworkMAC = h.MAC
			return out
		}
	}
	return out
}

// addrKey returns the address a (CIDR suffix ignored) as text if it is an IP
// address a host can be reached at: not loopback, link-local or unspecified.
func addrKey(a string) (string, bool) {
	a, _, _ = strings.Cut(strings.TrimSpace(a), "/")
	ip, err := netip.ParseAddr(a)
	if err != nil {
		return "", false
	}
	ip = ip.Unmap()
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
		return "", false
	}
	return ip.String(), true
}

// nameKeys returns the lower-case name and its first label (pi5.lan: pi5.lan
// and pi5), without a trailing dot or .local; none for "" or an IP address.
func nameKeys(name string) []string {
	n := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	n = strings.TrimSuffix(n, ".local")
	if n == "" || n == "localhost" {
		return nil
	}
	if _, err := netip.ParseAddr(n); err == nil {
		return nil
	}
	short, _, _ := strings.Cut(n, ".")
	if short == n {
		return []string{n}
	}
	return []string{n, short}
}
