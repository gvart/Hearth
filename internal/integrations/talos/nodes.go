// SPDX-License-Identifier: AGPL-3.0-only

package talos

import (
	"context"
	"slices"
	"strings"
	"time"

	"google.golang.org/protobuf/encoding/protowire"
)

// Service health, as Node.Services report it.
const (
	HealthHealthy   = "healthy"
	HealthUnhealthy = "unhealthy"
	HealthUnknown   = "unknown"
)

// Node is what the Talos API reports for one node.
type Node struct {
	// Address is the address or name the node is read at, as the talosconfig
	// (or --talos-nodes) names it.
	Address string `json:"address"`
	// Hostname is the node's own hostname.
	Hostname string `json:"hostname"`
	// Error is why the node could not be read; the other fields are then
	// empty.
	Error string `json:"error,omitempty"`
	// Version is the Talos version tag, e.g. v1.12.7.
	Version  string `json:"version"`
	Arch     string `json:"arch"`
	Platform string `json:"platform"`
	// Healthy is true when every service is running and none fails its
	// health check.
	Healthy  bool      `json:"healthy"`
	Services []Service `json:"services"`
	// MemTotal and MemAvailable are in bytes.
	MemTotal     uint64    `json:"mem_total"`
	MemAvailable uint64    `json:"mem_available"`
	Load1        float64   `json:"load1"`
	Load5        float64   `json:"load5"`
	Load15       float64   `json:"load15"`
	BootTime     time.Time `json:"boot_time"`
}

// Service is a Talos system service (machined, apid, etcd, kubelet, ...).
type Service struct {
	ID    string `json:"id"`
	State string `json:"state"`
	// Health is HealthHealthy, HealthUnhealthy or HealthUnknown (a service
	// without a health check).
	Health  string `json:"health"`
	Message string `json:"message,omitempty"`
}

// maxServices caps the services read for one node.
const maxServices = 100

// Read reads every node once: one call per read method, each fanned out to
// all nodes by apid. A node apid cannot reach comes back with its Error
// set; Read fails only when no endpoint answers.
func (c *Client) Read(ctx context.Context) ([]Node, error) {
	byNode := map[string]*Node{}
	var order []string
	get := func(m meta) *Node {
		key := m.hostname
		n, ok := byNode[key]
		if !ok {
			n = &Node{Address: key}
			byNode[key] = n
			order = append(order, key)
		}
		if m.err != "" && n.Error == "" {
			n.Error = m.err
		}
		return n
	}
	for _, step := range []struct {
		method string
		fn     func(*Node, field) error
	}{
		{methodVersion, decodeVersion},
		{methodHostname, decodeHostname},
		{methodServiceList, decodeServices},
		{methodMemory, decodeMemory},
		{methodLoadAvg, decodeLoad},
		{methodSystemStat, decodeStat},
	} {
		b, err := c.call(ctx, step.method, c.cfg.Nodes)
		if err != nil {
			return nil, err
		}
		metas, err := replies(b, func(m meta, f field) error { return step.fn(get(m), f) })
		if err != nil {
			return nil, err
		}
		for _, m := range metas {
			get(m) // a reply with no fields but an error
		}
	}
	out := make([]Node, 0, len(order))
	for _, k := range order {
		n := byNode[k]
		if n.Error != "" {
			*n = Node{Address: n.Address, Hostname: n.Hostname, Error: n.Error}
		} else {
			n.Healthy = healthy(n.Services)
		}
		out = append(out, *n)
	}
	slices.SortFunc(out, func(a, b Node) int { return strings.Compare(a.Address, b.Address) })
	return out, nil
}

func healthy(svcs []Service) bool {
	if len(svcs) == 0 {
		return false
	}
	for _, s := range svcs {
		if s.State != "Running" && s.State != "Finished" || s.Health == HealthUnhealthy {
			return false
		}
	}
	return true
}

func decodeVersion(n *Node, f field) error {
	switch {
	case f.num == fVersionInfo && f.typ == protowire.BytesType:
		return walk(f.bytes, func(v field) error {
			switch v.num {
			case fVersionTag:
				n.Version = v.str()
			case fVersionArch:
				n.Arch = v.str()
			}
			return nil
		})
	case f.num == fPlatformInfo && f.typ == protowire.BytesType:
		return walk(f.bytes, func(v field) error {
			if v.num == fPlatformName {
				n.Platform = v.str()
			}
			return nil
		})
	}
	return nil
}

func decodeHostname(n *Node, f field) error {
	if f.num == fHostname {
		n.Hostname = f.str()
	}
	return nil
}

func decodeServices(n *Node, f field) error {
	if f.num != fServices || f.typ != protowire.BytesType || len(n.Services) >= maxServices {
		return nil
	}
	s := Service{Health: HealthUnknown}
	err := walk(f.bytes, func(v field) error {
		switch v.num {
		case fServiceID:
			s.ID = v.str()
		case fServiceState:
			s.State = v.str()
		case fServiceHealth:
			if v.typ != protowire.BytesType {
				return nil
			}
			var unknown, ok bool
			if err := walk(v.bytes, func(h field) error {
				switch h.num {
				case fHealthUnknown:
					unknown = h.uint() != 0
				case fHealthHealthy:
					ok = h.uint() != 0
				case fHealthMessage:
					s.Message = h.str()
				}
				return nil
			}); err != nil {
				return err
			}
			switch {
			case unknown:
				s.Health = HealthUnknown
			case ok:
				s.Health = HealthHealthy
			default:
				s.Health = HealthUnhealthy
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	n.Services = append(n.Services, s)
	return nil
}

func decodeMemory(n *Node, f field) error {
	if f.num != fMemInfo || f.typ != protowire.BytesType {
		return nil
	}
	// MemInfo carries /proc/meminfo as is, in KiB.
	return walk(f.bytes, func(v field) error {
		switch v.num {
		case fMemTotal:
			n.MemTotal = v.uint() * 1024
		case fMemAvailable:
			n.MemAvailable = v.uint() * 1024
		}
		return nil
	})
}

func decodeLoad(n *Node, f field) error {
	switch f.num {
	case fLoad1:
		n.Load1 = f.double()
	case fLoad5:
		n.Load5 = f.double()
	case fLoad15:
		n.Load15 = f.double()
	}
	return nil
}

func decodeStat(n *Node, f field) error {
	if f.num == fBootTime {
		if s := f.uint(); s > 0 && s < 1<<40 {
			n.BootTime = time.Unix(int64(s), 0).UTC()
		}
	}
	return nil
}
