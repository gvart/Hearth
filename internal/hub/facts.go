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
