// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gvart/hearth/internal/cluster"
	"github.com/gvart/hearth/internal/discovery"
	"github.com/gvart/hearth/internal/pki"
	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

// memberLister lists an AP cluster's gossip members. *cluster.APNode is one.
type memberLister interface {
	Status() cluster.Status
}

// DeviceHubJSON is whether a device is a hub of the cluster too (#332): the
// member it became, if any, and what it takes to change that.
type DeviceHubJSON struct {
	// NodeID is the member the device became: the hub that joined with a
	// join token minted for it, at its enrollment or on its page, and was not
	// removed since. Empty for an agent only.
	NodeID string `json:"node_id,omitempty"`
	// Roles are its storage and master roles; AllowedRoles its --allow-roles.
	Roles        cluster.RoleSet `json:"roles"`
	AllowedRoles cluster.RoleSet `json:"allowed_roles"`
	// State is the member's gossip state (alive, suspect, dead, left), or
	// unknown while this hub does not see it in the gossip.
	State string `json:"state,omitempty"`
	// Masters and Storage count the cluster's hubs with each role; MaxMasters
	// and MaxStorage are the most devices become.
	Masters    int `json:"masters"`
	Storage    int `json:"storage"`
	MaxMasters int `json:"max_masters"`
	MaxStorage int `json:"max_storage"`
	// AgentOnlyCommand, run on the device, stops and removes its hub service.
	AgentOnlyCommand string `json:"agent_only_command"`
}

// MakeHubJSON is a join token minted for a device on its page: the command
// that makes it a hub. The token in Command is a secret, answered once.
type MakeHubJSON struct {
	Roles     cluster.RoleSet `json:"roles"`
	ExpiresAt time.Time       `json:"expires_at"`
	Command   string          `json:"command"`
}

// deviceHubTTL is how long a device's join token from its page lasts: the
// admin pastes its command on the device right away.
const deviceHubTTL = 15 * time.Minute

// apCluster reports whether this hub can count, list and mint for the hubs
// of an AP cluster, else answers 404.
func (a *api) apCluster(w http.ResponseWriter) bool {
	if a.clusterAdmin == nil || a.hubs == nil || a.members == nil || a.masters == nil {
		writeError(w, http.StatusNotFound, "not_ap_cluster", "this hub is not a member of an AP cluster")
		return false
	}
	return true
}

// device reads the device of the request's path, else answers why not.
func (a *api) device(w http.ResponseWriter, r *http.Request) (store.Device, bool) {
	d, err := a.store.Devices().Get(r.Context(), r.PathValue("id"))
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "no such device")
		return d, false
	case errors.Is(err, store.ErrUnavailable):
		writeUnavailable(w)
		return d, false
	case err != nil:
		a.log.ErrorContext(r.Context(), "get device", "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "cannot get device")
		return d, false
	}
	return d, true
}

// deviceHubOf is device id's hub as DeviceHubJSON, without the command.
func (a *api) deviceHubOf(ctx context.Context, id string) (DeviceHubJSON, error) {
	out := DeviceHubJSON{MaxMasters: cluster.MaxAutoMasters, MaxStorage: cluster.MaxAutoStorage}
	var err error
	if out.Masters, out.Storage, err = a.hubs.HubCounts(ctx, ""); err != nil {
		return out, err
	}
	if out.NodeID, err = a.store.JoinTokens().HubOf(ctx, id); err != nil || out.NodeID == "" {
		return out, err
	}
	out.State = "unknown"
	for _, m := range a.members.Status().Members {
		if m.ID == out.NodeID {
			out.Roles, out.AllowedRoles, out.State = m.Roles&cluster.HubRoles, m.AllowedRoles&cluster.HubRoles, m.State
		}
	}
	return out, nil
}

// deviceHub answers whether a device is a hub too, and with which roles.
func (a *api) deviceHub(w http.ResponseWriter, r *http.Request) {
	if !a.apCluster(w) {
		return
	}
	d, ok := a.device(w, r)
	if !ok {
		return
	}
	httpHost, _, ok := a.commandHosts(r.Host, r.TLS != nil)
	if !ok {
		writeError(w, http.StatusBadRequest, "bad_request", "request Host header is not a valid host name")
		return
	}
	out, err := a.deviceHubOf(r.Context(), d.ID)
	if err != nil {
		a.writeActionError(w, r, "read the device's hub", err)
		return
	}
	out.AgentOnlyCommand = a.installCommandWith(httpHost, "", "--agent-only")
	writeJSON(w, http.StatusOK, out)
}

// hubPlatform reports whether a device of os and arch may run a hub when an
// admin chooses it. os is the agent's platform ("darwin 26.1", "debian
// 12", "Microsoft Windows 11 Pro"), so only Windows and Android are refused
// here: the device checks the rest itself (cluster.HubChosen: Linux or
// macOS, memory and disk). A device whose agent has not reported yet
// (neither known) may.
func hubPlatform(os, arch string) bool {
	os = strings.ToLower(os)
	return (arch == "" || arch == "amd64" || arch == "arm64") && !strings.Contains(os, "windows") && !strings.HasPrefix(os, "android")
}

// makeDeviceHub mints a join token for an enrolled device that is no hub,
// so that it becomes one: the command it answers re-runs the installer on
// the device, which installs the hub service next to the agent (#332). The
// roles follow the caps of the hubs devices become at their enrollment
// (hubJoinRoles), and cluster.Join checks them again. Like Add hub, it is a
// cluster.token.create, dangerous and only with the password entered again.
func (a *api) makeDeviceHub(w http.ResponseWriter, r *http.Request) {
	if !a.apCluster(w) {
		return
	}
	d, ok := a.device(w, r)
	if !ok {
		return
	}
	if !hubPlatform(d.OS, d.Arch) {
		writeError(w, http.StatusConflict, "not_capable", "only a 64-bit Linux or macOS device (amd64 or arm64) runs a hub")
		return
	}
	// The hosts of Add device's command: no loopback address, no
	// hearth.local (commandHosts). Join tokens (hearthj1) name no hub, so
	// the join URL goes in the command.
	httpHost, agentHost, ok := a.commandHosts(r.Host, r.TLS != nil)
	if !ok {
		writeError(w, http.StatusBadRequest, "bad_request", "request Host header is not a valid host name")
		return
	}
	joinURL, ok := shellSafeURL("https://" + net.JoinHostPort(agentHost, a.agentPort))
	if !ok || isLoopback(agentHost) || strings.EqualFold(strings.TrimSuffix(agentHost, "."), discovery.LANName) {
		writeError(w, http.StatusConflict, "no_agent_url", "this hub's certificate names no host a device can use in a command (an IPv6 address needs a name): set --host")
		return
	}
	ctx := r.Context()
	a.hubMintMu.Lock()
	defer a.hubMintMu.Unlock()
	cur, err := a.deviceHubOf(ctx, d.ID)
	if err != nil {
		a.writeActionError(w, r, "read the device's hub", err)
		return
	}
	if cur.NodeID != "" && cur.State != cluster.MemberLeft {
		writeError(w, http.StatusConflict, "already_hub", "this device is a hub already: "+cur.NodeID)
		return
	}
	now := a.now()
	roles, why := hubJoinRoles(ctx, a.hubs, a.store, now, cluster.HubRoles, a.log)
	if why != "" {
		writeError(w, http.StatusConflict, "hubs_full", why)
		return
	}
	tok, err := pki.NewToken(a.ca.Cert())
	if err != nil {
		a.log.ErrorContext(ctx, "create a device's join token", "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "cannot create the join token")
		return
	}
	expires := now.Add(deviceHubTTL).UTC().Truncate(time.Millisecond)
	err = a.policy.Do(ctx, policy.Request{
		ActorKind: policy.ActorWeb, ActorID: remoteHost(r), Action: policy.ClusterTokenCreate, Target: d.ID,
		Detail:   map[string]any{"via": "device", "roles": roles.String(), "device_id": d.ID, "ttl": deviceHubTTL.String()},
		Precheck: a.recentAuth(r),
	}, func(ctx context.Context) error {
		return a.store.JoinTokens().CreateFor(ctx, tok.Secret, expires, roles.String(), d.ID)
	})
	switch {
	case err == nil:
	case !errors.Is(err, errReauthRequired) && errors.Is(err, policy.ErrDenied) &&
		strings.Contains(err.Error(), policy.ErrIsolated):
		writeError(w, http.StatusForbidden, "isolated", policy.ErrIsolated)
		return
	case errors.Is(err, store.ErrSchemaTooOld):
		writeError(w, http.StatusConflict, "schema_too_old", "the hub cluster's database predates device hubs: upgrade every hub of the cluster first")
		return
	default:
		a.writeActionError(w, r, "create the device's join token", err)
		return
	}
	a.log.InfoContext(ctx, "device join token created", "device_id", d.ID, "roles", roles.String())
	// The join URL is checked (shellSafeURL), the host too (commandHosts),
	// and the token is base64url and dots: safe to paste into a shell. The
	// token goes in the environment, not argv.
	writeJSON(w, http.StatusCreated, MakeHubJSON{
		Roles: roles, ExpiresAt: expires,
		Command: a.installCommandWith(httpHost, "HEARTH_JOIN_TOKEN="+tok.EncodeJoin(), "--make-hub", joinURL),
	})
}

// shellSafeURL returns u, an https://host[:port] URL, if every part of it is
// safe to paste into a shell.
func shellSafeURL(u string) (string, bool) {
	p, err := url.Parse(u)
	if err != nil || p.Scheme != "https" || p.User != nil || (p.Path != "" && p.Path != "/") || p.RawQuery != "" || p.Fragment != "" {
		return "", false
	}
	// No IPv6 literal: its brackets are a shell pattern.
	host, port := p.Host, ""
	if h, pt, err := net.SplitHostPort(p.Host); err == nil {
		host, port = h, pt
	}
	if strings.ContainsAny(p.Host, "[]") || !validHost(host) || !validPort(port) {
		return "", false
	}
	return "https://" + p.Host, true
}
