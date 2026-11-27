// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"encoding/json"
	"fmt"

	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
	"github.com/gvart/hearth/internal/store"
)

// Facts is the JSON shape of a device's facts, as stored and served by the
// API. It mirrors Hello without protocol_version and device_id.
type Facts struct {
	Hostname      string      `json:"hostname"`
	OS            string      `json:"os"`
	Arch          string      `json:"arch"`
	Kernel        string      `json:"kernel"`
	CPUModel      string      `json:"cpu_model"`
	CPUCores      uint32      `json:"cpu_cores"`
	MemTotalBytes uint64      `json:"mem_total_bytes"`
	Disks         []Disk      `json:"disks"`
	Interfaces    []Interface `json:"interfaces"`
	AgentVersion  string      `json:"agent_version"`
	Capabilities  []string    `json:"capabilities"`
	// Ceiling is the capability ceiling the agent reports; nil for an agent
	// too old to report one, to which the hub sends no action.
	Ceiling *Ceiling `json:"ceiling,omitempty"`
	// LocalCeiling is the part of it the agent's flags grant, which the hub
	// cannot take away; nil for an agent too old to report it.
	LocalCeiling *Ceiling `json:"local_ceiling,omitempty"`
	// CeilingLocked is set for an agent started with --local-ceiling: it
	// ignores the ceiling the hub sets.
	CeilingLocked bool `json:"ceiling_locked,omitempty"`
	// ProtocolMinor is the agent's protocol minor version.
	ProtocolMinor uint32 `json:"protocol_minor,omitempty"`
	// ReleaseTarget is the os_arch of the release archive the agent
	// upgrades itself from; empty when it does not, and NoSelfUpgrade then
	// says why, if the agent says.
	ReleaseTarget string `json:"release_target,omitempty"`
	NoSelfUpgrade string `json:"no_self_upgrade,omitempty"`
	// RolledBackFrom is the release an upgrade of the agent went to and was
	// rolled back from, its new binary having reached no hub. The agent
	// says it once; the hub keeps it while the agent reports the same
	// version.
	RolledBackFrom string `json:"rolled_back_from,omitempty"`
}

// Ceiling is what the device's agent lets the hub run.
type Ceiling struct {
	Exec    []string `json:"exec"`
	Restart []string `json:"restart"`
	// Probe is whether the hub may run checks from the device.
	Probe bool `json:"probe"`
	// Logs are the log sources the hub may stream, as manager:pattern.
	Logs []string `json:"logs"`
	// Shell is whether an admin may open a terminal on the device.
	Shell bool `json:"shell"`
	// Scan are the subnets the hub may have the device sweep for network
	// discovery.
	Scan []string `json:"scan"`
	// NetEdges is whether the agent reports its network edges.
	NetEdges bool `json:"net_edges"`
	// Docker is whether the hub may list and act on the device's
	// containers.
	Docker bool `json:"docker"`
	// DockerRead is whether the hub may list the device's containers and
	// read their logs, without acting on them. Docker implies it.
	DockerRead bool `json:"docker_read,omitempty"`
}

// ceilingJSON is c as served, or nil.
func ceilingJSON(c *agentv1.Ceiling) *Ceiling {
	if c == nil {
		return nil
	}
	return &Ceiling{
		Exec: nonNil(c.GetExec()), Restart: nonNil(c.GetRestart()), Probe: c.GetProbe(), Logs: nonNil(c.GetLogs()),
		Shell: c.GetShell(), Scan: nonNil(c.GetScan()), NetEdges: c.GetNetEdges(), Docker: c.GetDocker(), DockerRead: c.GetDockerRead(),
	}
}

// Proto is c as an agentv1.Ceiling.
func (c Ceiling) Proto() *agentv1.Ceiling {
	return &agentv1.Ceiling{
		Exec: c.Exec, Restart: c.Restart, Probe: c.Probe, Logs: c.Logs, Shell: c.Shell, Scan: c.Scan,
		NetEdges: c.NetEdges, Docker: c.Docker, DockerRead: c.DockerRead,
	}
}

// Disk is a mounted filesystem.
type Disk struct {
	Device     string `json:"device"`
	Mountpoint string `json:"mountpoint"`
	FSType     string `json:"fstype"`
	TotalBytes uint64 `json:"total_bytes"`
	// UsedBytes is the space in use when the agent last sent its facts
	// (every ten minutes). Absent from an agent that does not report it.
	UsedBytes uint64 `json:"used_bytes,omitempty"`
}

// Interface is a network interface and its addresses.
type Interface struct {
	Name string   `json:"name"`
	MAC  string   `json:"mac"`
	IPs  []string `json:"ips"`
}

// factsFromHello is the facts h reports. prev, the facts stored before, if
// any, keeps a rollback the agent told of while it reports the same
// version.
func factsFromHello(h *agentv1.Hello, prev json.RawMessage) (store.DeviceFacts, error) {
	f := Facts{
		Hostname:      h.GetHostname(),
		OS:            h.GetOs(),
		Arch:          h.GetArch(),
		Kernel:        h.GetKernel(),
		CPUModel:      h.GetCpuModel(),
		CPUCores:      h.GetCpuCores(),
		MemTotalBytes: h.GetMemTotalBytes(),
		Disks:         []Disk{},
		Interfaces:    []Interface{},
		AgentVersion:  h.GetAgentVersion(),
		Capabilities:  nonNil(h.GetCapabilities()),
		ReleaseTarget: h.GetReleaseTarget(),
		NoSelfUpgrade: h.GetNoSelfUpgrade(),

		RolledBackFrom: h.GetRolledBackFrom(),
	}
	if f.RolledBackFrom == "" && len(prev) > 0 {
		var p Facts
		if json.Unmarshal(prev, &p) == nil && p.AgentVersion == f.AgentVersion {
			f.RolledBackFrom = p.RolledBackFrom
		}
	}
	f.Ceiling, f.LocalCeiling = ceilingJSON(h.GetCeiling()), ceilingJSON(h.GetLocalCeiling())
	f.CeilingLocked, f.ProtocolMinor = h.GetCeilingLocked(), h.GetProtocolVersion().GetMinor()
	for _, d := range h.GetDisks() {
		f.Disks = append(f.Disks, Disk{
			Device: d.GetDevice(), Mountpoint: d.GetMountpoint(), FSType: d.GetFstype(), TotalBytes: d.GetTotalBytes(), UsedBytes: d.GetUsedBytes(),
		})
	}
	for _, i := range h.GetInterfaces() {
		f.Interfaces = append(f.Interfaces, Interface{Name: i.GetName(), MAC: i.GetMac(), IPs: nonNil(i.GetIps())})
	}
	b, err := json.Marshal(f)
	if err != nil {
		return store.DeviceFacts{}, fmt.Errorf("encode facts: %w", err)
	}
	return store.DeviceFacts{Hostname: f.Hostname, OS: f.OS, Arch: f.Arch, Facts: b}, nil
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
