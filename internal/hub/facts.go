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
	// containers (--allow-docker).
	Docker bool `json:"docker"`
}

// Disk is a mounted filesystem.
type Disk struct {
	Device     string `json:"device"`
	Mountpoint string `json:"mountpoint"`
	FSType     string `json:"fstype"`
	TotalBytes uint64 `json:"total_bytes"`
}

// Interface is a network interface and its addresses.
type Interface struct {
	Name string   `json:"name"`
	MAC  string   `json:"mac"`
	IPs  []string `json:"ips"`
}

func factsFromHello(h *agentv1.Hello) (store.DeviceFacts, error) {
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
	}
	if c := h.GetCeiling(); c != nil {
		f.Ceiling = &Ceiling{Exec: nonNil(c.GetExec()), Restart: nonNil(c.GetRestart()), Probe: c.GetProbe(), Logs: nonNil(c.GetLogs()), Shell: c.GetShell(), Scan: nonNil(c.GetScan()), NetEdges: c.GetNetEdges(), Docker: c.GetDocker()}
	}
	for _, d := range h.GetDisks() {
		f.Disks = append(f.Disks, Disk{
			Device: d.GetDevice(), Mountpoint: d.GetMountpoint(), FSType: d.GetFstype(), TotalBytes: d.GetTotalBytes(),
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
