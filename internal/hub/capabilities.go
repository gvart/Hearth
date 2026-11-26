// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/gvart/hearth/internal/policy"
	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
	"github.com/gvart/hearth/internal/store"
)

// Capabilities managed from the hub (#346): what the hub may do on a device,
// set here and pushed to its agent (ceilingpush.go), which adds it to its own
// flags and enforces the union itself. Raising a shell, exec, restart or
// Docker control is device.capabilities.raise, dangerous, and takes the
// password again; anything else is device.capabilities.set.

// What "on" means for a capability with a list: everything of it.
var (
	// AllLogs are the log entries of logs "on": every source.
	AllLogs = []string{"systemd:*", "systemd-user:*", "docker:*"}
	// AllRestart are the restart entries of restart "on": every service.
	AllRestart = []string{"systemd:*", "systemd-user:*", "docker:*"}
	// AllScan are the scan entries of scan "on": the private IPv4 ranges.
	AllScan = []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}
)

// CapabilitiesJSON is a device's capabilities: what the hub sets, what the
// agent's flags grant, and what the agent reports it allows, their union.
type CapabilitiesJSON struct {
	// Hub is the ceiling the hub sets for the device.
	Hub Ceiling `json:"hub"`
	// Local is what the agent's flags grant, which the hub cannot take
	// away; nil until an agent that reports it connected.
	Local *Ceiling `json:"local"`
	// Effective is the ceiling the agent last reported; nil until it did.
	Effective *Ceiling `json:"effective"`
	// Locked is set for an agent started with --local-ceiling: it ignores
	// Hub.
	Locked bool `json:"locked"`
	// Manageable is whether the agent takes a ceiling from the hub
	// (protocol minor 10); an older agent must be upgraded first.
	Manageable bool `json:"manageable"`
	// AgentVersion is the agent's version, as it reported it.
	AgentVersion string `json:"agent_version"`
	// UpdatedAt and UpdatedBy say who set Hub last, if anyone did.
	UpdatedAt *time.Time `json:"updated_at,omitempty"`
	UpdatedBy string     `json:"updated_by,omitempty"`
}

// CapabilitiesRequest is the body of PUT /api/v1/devices/{id}/capabilities:
// the whole ceiling the hub sets.
type CapabilitiesRequest struct {
	Hub Ceiling `json:"hub"`
}

func (a *api) capabilitiesRoutes(mux *http.ServeMux) {
	mux.Handle("GET /api/v1/devices/{id}/capabilities", a.auth(a.getCapabilities))
	mux.Handle("PUT /api/v1/devices/{id}/capabilities", a.auth(a.putCapabilities))
}

// DeviceCapabilities is d's capabilities, as GET
// /api/v1/devices/{id}/capabilities serves them.
func DeviceCapabilities(ctx context.Context, st *store.Store, d store.Device) (CapabilitiesJSON, error) {
	return capabilitiesOf(ctx, st, d)
}

// capabilitiesOf is d's capabilities.
func capabilitiesOf(ctx context.Context, st *store.Store, d store.Device) (CapabilitiesJSON, error) {
	var out CapabilitiesJSON
	var f Facts
	if len(d.Facts) > 0 {
		if err := json.Unmarshal(d.Facts, &f); err != nil {
			return out, fmt.Errorf("decode the facts of device %s: %w", d.ID, err)
		}
	}
	out.Local, out.Effective, out.Locked = f.LocalCeiling, f.Ceiling, f.CeilingLocked
	out.Manageable, out.AgentVersion = f.ProtocolMinor >= minCeilingConfigMinor, f.AgentVersion
	dc, err := st.DeviceCeilings().Get(ctx, d.ID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		out.Hub = *ceilingJSON(&agentv1.Ceiling{})
		return out, nil
	case err != nil:
		return out, err
	}
	c := &agentv1.Ceiling{}
	if err := protojson.Unmarshal(dc.Ceiling, c); err != nil {
		return out, fmt.Errorf("decode the ceiling of device %s: %w", d.ID, err)
	}
	out.Hub = *ceilingJSON(c)
	at := dc.UpdatedAt.UTC()
	out.UpdatedAt, out.UpdatedBy = &at, dc.UpdatedBy
	return out, nil
}

func (a *api) getCapabilities(w http.ResponseWriter, r *http.Request) {
	d, ok := a.device(w, r)
	if !ok {
		return
	}
	out, err := capabilitiesOf(r.Context(), a.store, d)
	if err != nil {
		a.writeActionError(w, r, "read the device's capabilities", err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// CapabilitiesChange is a change of the ceiling the hub sets: the policy
// action it is, and the capabilities it raises and lowers, for the audit
// log.
type CapabilitiesChange struct {
	Action  policy.Action
	Raised  []string
	Lowered []string
}

// Detail is the change as its audit entry's detail.
func (c CapabilitiesChange) Detail(device string) map[string]any {
	return map[string]any{"device_id": device, "raised": nonNil(c.Raised), "lowered": nonNil(c.Lowered)}
}

// ChangeOf is the change from the ceiling old to next: a raise of shell,
// exec, restart or Docker control (an entry or a switch next has and old
// lacks) is device.capabilities.raise, anything else
// device.capabilities.set.
func ChangeOf(old, next *agentv1.Ceiling) CapabilitiesChange {
	var c CapabilitiesChange
	risky := false
	list := func(name string, o, n []string, isRisky bool) {
		if slices.ContainsFunc(n, func(e string) bool { return !slices.Contains(o, e) }) {
			c.Raised = append(c.Raised, name)
			risky = risky || isRisky
		}
		if slices.ContainsFunc(o, func(e string) bool { return !slices.Contains(n, e) }) {
			c.Lowered = append(c.Lowered, name)
		}
	}
	flag := func(name string, o, n, isRisky bool) {
		switch {
		case n && !o:
			c.Raised = append(c.Raised, name)
			risky = risky || isRisky
		case o && !n:
			c.Lowered = append(c.Lowered, name)
		}
	}
	flag("shell", old.GetShell(), next.GetShell(), true)
	list("exec", old.GetExec(), next.GetExec(), true)
	list("restart", old.GetRestart(), next.GetRestart(), true)
	flag("docker", old.GetDocker(), next.GetDocker(), true)
	flag("docker_read", old.GetDockerRead(), next.GetDockerRead(), false)
	list("logs", old.GetLogs(), next.GetLogs(), false)
	flag("probe", old.GetProbe(), next.GetProbe(), false)
	list("scan", old.GetScan(), next.GetScan(), false)
	flag("net_edges", old.GetNetEdges(), next.GetNetEdges(), false)
	c.Action = policy.DeviceCapabilitiesSet
	if risky {
		c.Action = policy.DeviceCapabilitiesRaise
	}
	return c
}

// NormalizeCeiling returns c checked (policy.CheckHubCeiling), with no
// duplicate entries.
func NormalizeCeiling(c Ceiling) (*agentv1.Ceiling, error) {
	dedupe := func(s []string) []string {
		out := []string{}
		for _, e := range s {
			if e = strings.TrimSpace(e); e != "" && !slices.Contains(out, e) {
				out = append(out, e)
			}
		}
		return out
	}
	c.Exec, c.Restart, c.Logs, c.Scan = dedupe(c.Exec), dedupe(c.Restart), dedupe(c.Logs), dedupe(c.Scan)
	p := c.Proto()
	if err := policy.CheckHubCeiling(p); err != nil {
		return nil, err
	}
	return p, nil
}

// putCapabilities sets the ceiling the hub sets for a device, through
// policy, and pushes it to its agent.
func (a *api) putCapabilities(w http.ResponseWriter, r *http.Request) {
	var req CapabilitiesRequest
	if !decodeJSON(w, r, 64<<10, &req, `{"hub": {...}}`) {
		return
	}
	next, err := NormalizeCeiling(req.Hub)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	d, ok := a.device(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	a.capsMu.Lock()
	defer a.capsMu.Unlock()
	cur, err := capabilitiesOf(ctx, a.store, d)
	if err != nil {
		a.writeActionError(w, r, "read the device's capabilities", err)
		return
	}
	change := ChangeOf(cur.Hub.Proto(), next)
	reauth := a.recentAuth(r)
	preq := policy.Request{
		ActorKind: policy.ActorWeb, ActorID: remoteHost(r), Action: change.Action, Target: d.ID,
		Detail: change.Detail(d.ID),
		Precheck: func(ctx context.Context) error {
			if cur.Locked {
				return ErrCeilingLocked
			}
			if change.Action == policy.DeviceCapabilitiesRaise {
				return reauth(ctx)
			}
			return nil
		},
	}
	body, err := protojson.Marshal(next)
	if err != nil {
		a.writeActionError(w, r, "encode the device's capabilities", err)
		return
	}
	err = a.policy.Do(ctx, preq, func(ctx context.Context) error {
		return a.store.DeviceCeilings().Set(ctx, d.ID, body, policy.ActorWeb+"/"+remoteHost(r), a.now())
	})
	switch {
	case err == nil:
	case errors.Is(err, ErrCeilingLocked):
		writeError(w, http.StatusConflict, "locked", ErrCeilingLocked.Error())
		return
	case errors.Is(err, store.ErrSchemaTooOld):
		writeError(w, http.StatusConflict, "schema_too_old", "the hub cluster's database predates managed capabilities: upgrade every hub of the cluster first")
		return
	default:
		a.writeActionError(w, r, "set the device's capabilities", err)
		return
	}
	a.log.InfoContext(ctx, "device capabilities set", "device_id", d.ID, "raised", change.Raised, "lowered", change.Lowered)
	if a.agents != nil {
		if err := a.agents.PushCeiling(d.ID, next); err != nil {
			// The next heartbeat sends it again.
			a.log.WarnContext(ctx, "send the device's capabilities", "device_id", d.ID, "err", err)
		}
	}
	out := cur
	at := a.now().UTC()
	out.Hub, out.UpdatedAt, out.UpdatedBy = *ceilingJSON(next), &at, policy.ActorWeb+"/"+remoteHost(r)
	writeJSON(w, http.StatusOK, out)
}

// ErrCeilingLocked refuses, as an audited denial, a change to the
// capabilities of a device whose agent runs with --local-ceiling.
var ErrCeilingLocked = fmt.Errorf("this device's agent runs with --local-ceiling: its capabilities are set on the device: %w", policy.ErrDenied)

// CapabilityKeys are the capabilities SetCapability takes, in the order the
// web UI and the CLI show them.
var CapabilityKeys = []string{"logs", "docker", "net-edges", "probe", "scan", "restart", "exec", "shell"}

// SetCapability changes capability key of c to value, as `hearth device
// capabilities --set key=value` does: "on" or "off" for shell, probe and
// net-edges; "off", "read" or "on" (read and control) for docker; "on" (all
// of it), "off" or a comma-separated list for logs (manager:name), restart
// (manager:name) and scan (IPv4 subnets); "off" or a comma-separated list of
// absolute paths for exec, which has no "on".
func SetCapability(c *Ceiling, key, value string) error {
	value = strings.TrimSpace(value)
	onOff := func(set *bool) error {
		switch value {
		case "on":
			*set = true
		case "off":
			*set = false
		default:
			return fmt.Errorf("%s: want on or off, not %q", key, value)
		}
		return nil
	}
	list := func(set *[]string, all []string) error {
		switch value {
		case "on":
			if all == nil {
				return fmt.Errorf("%s has no \"on\": list the programs, comma-separated absolute paths", key)
			}
			*set = slices.Clone(all)
		case "off", "":
			*set = []string{}
		default:
			*set = strings.Split(value, ",")
		}
		return nil
	}
	switch key {
	case "shell":
		return onOff(&c.Shell)
	case "probe":
		return onOff(&c.Probe)
	case "net-edges", "net_edges":
		return onOff(&c.NetEdges)
	case "docker":
		switch value {
		case "on":
			c.Docker, c.DockerRead = true, true
		case "read":
			c.Docker, c.DockerRead = false, true
		case "off":
			c.Docker, c.DockerRead = false, false
		default:
			return fmt.Errorf("docker: want on, read or off, not %q", value)
		}
		return nil
	case "logs":
		return list(&c.Logs, AllLogs)
	case "restart":
		return list(&c.Restart, AllRestart)
	case "scan":
		return list(&c.Scan, AllScan)
	case "exec":
		return list(&c.Exec, nil)
	}
	return fmt.Errorf("unknown capability %q: want one of %s", key, strings.Join(CapabilityKeys, ", "))
}
