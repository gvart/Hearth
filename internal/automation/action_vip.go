// SPDX-License-Identifier: AGPL-3.0-only

package automation

import (
	"fmt"
	"time"

	"github.com/gvart/hearth/internal/policy"
	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
)

// buildVIP builds a vip_claim action, or with release a vip_release: a
// device's agent adds a virtual IP to one of its interfaces and announces it
// with gratuitous ARP, or removes it. Both are dangerous, and the agent takes
// only the interface=address pairs its ceiling's vip lists.
func buildVIP(p Params, agents Agents, release bool) (Action, error) {
	var cfg struct {
		Device    string        `yaml:"device"`
		Interface string        `yaml:"interface"`
		Address   string        `yaml:"address"`
		Timeout   time.Duration `yaml:"timeout"`
	}
	if err := p.Decode(&cfg); err != nil {
		return nil, err
	}
	device, err := deviceText(p, cfg.Device)
	if err != nil {
		return nil, err
	}
	if cfg.Interface == "" || cfg.Address == "" {
		return nil, fmt.Errorf("interface and address are required, e.g. interface: eth0, address: 192.168.1.53/24")
	}
	if err := policy.CheckVIP(cfg.Interface, cfg.Address); err != nil {
		return nil, err
	}
	timeout, err := agentTimeout(cfg.Timeout)
	if err != nil {
		return nil, err
	}
	act, verb := policy.AutomationVIPClaim, "claim"
	if release {
		act, verb = policy.AutomationVIPRelease, "release"
	}
	what := fmt.Sprintf("%s virtual IP %s on %s", verb, cfg.Address, cfg.Interface)
	return &agentAction{
		agents: agents, device: device, timeout: timeout, policy: act, desc: what, what: what,
		req: func() *agentv1.ExecRequest {
			return &agentv1.ExecRequest{Action: &agentv1.ExecRequest_Vip{
				Vip: &agentv1.VirtualIP{Interface: cfg.Interface, Address: cfg.Address, Release: release},
			}}
		},
	}, nil
}
