// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"net/http"
	"slices"
	"strings"
)

// Tailnet states, in TailnetStatus.State.
const (
	TailnetStarting = "starting"
	TailnetRunning  = "running"
	TailnetError    = "error"
)

// TailnetStatus is the hub's node on a tailnet (`hearth hub --tailscale`,
// docs/tailscale.md): set by flags, read-only in the UI. None of it is
// secret: the auth key never gets here.
type TailnetStatus struct {
	// State is TailnetStarting, TailnetRunning or TailnetError.
	State string `json:"state"`
	// Hostname is --tailscale-hostname, the name the hub asks the tailnet for.
	Hostname string `json:"hostname"`
	// DNSName is the node's MagicDNS name, e.g. hearth.tail1234.ts.net,
	// once it runs.
	DNSName string `json:"dns_name,omitempty"`
	// IPs are the node's tailnet addresses, once it runs.
	IPs []string `json:"ips,omitempty"`
	// URL is the address to open the UI at from the tailnet: HTTPS on 443
	// with a Let's Encrypt certificate when the tailnet has HTTPS
	// certificates on, else the hub CA's HTTPS port.
	URL string `json:"url,omitempty"`
	// AgentURL is the address agents on the tailnet enroll and connect at,
	// with the hub CA.
	AgentURL string `json:"agent_url,omitempty"`
	// Error says why the node is not running (State TailnetError).
	Error string `json:"error,omitempty"`
	// HTTPSNote says why URL is not on 443, if it is not.
	HTTPSNote string `json:"https_note,omitempty"`
}

// Hosts are the names the hub answers at on the tailnet: its MagicDNS name
// and its addresses, while it runs.
func (s TailnetStatus) Hosts() []string {
	if s.State != TailnetRunning {
		return nil
	}
	var hosts []string
	if s.DNSName != "" {
		hosts = append(hosts, s.DNSName)
	}
	return append(hosts, s.IPs...)
}

// Tailnet is the hub's node on a tailnet.
type Tailnet interface {
	Status() TailnetStatus
}

// TailnetJSON is the body of GET /api/v1/tailscale.
type TailnetJSON struct {
	// Enabled is whether the hub runs with --tailscale.
	Enabled bool `json:"enabled"`
	TailnetStatus
}

func (a *api) tailnetInfo(w http.ResponseWriter, _ *http.Request) {
	if a.tailnet == nil {
		writeJSON(w, http.StatusOK, TailnetJSON{})
		return
	}
	writeJSON(w, http.StatusOK, TailnetJSON{Enabled: true, TailnetStatus: a.tailnet.Status()})
}

// certHosts are the names the hub's certificates cover: AgentHosts, then
// the tailnet's while the hub is on one. The tailnet names come last, so
// they are never the preferred name (stableHost) of a hub on a LAN.
func (a *api) certHosts() []string {
	if a.tailnet == nil {
		return a.agentHosts
	}
	extra := a.tailnet.Status().Hosts()
	hosts := slices.Clone(a.agentHosts)
	for _, h := range extra {
		if !slices.ContainsFunc(hosts, func(x string) bool { return strings.EqualFold(x, h) }) {
			hosts = append(hosts, h)
		}
	}
	return hosts
}
