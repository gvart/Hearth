// SPDX-License-Identifier: AGPL-3.0-only

package policy

import (
	"context"
	"errors"
	"testing"

	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
)

func TestCheckVIP(t *testing.T) {
	tests := []struct {
		iface, address string
		ok             bool
	}{
		{"eth0", "192.168.1.53/24", true},
		{"wlan0", "10.0.0.5/8", true},
		{"br-lan.10", "172.16.0.2/32", true},
		{"end0", "192.168.1.3/31", true},
		{"", "192.168.1.53/24", false},
		{"lo", "192.168.1.53/24", false},
		{"-all", "192.168.1.53/24", false},
		{"eth0 up", "192.168.1.53/24", false},
		{"eth0;reboot", "192.168.1.53/24", false},
		{"abcdefghijklmnop", "192.168.1.53/24", false}, // 16 characters
		{"eth0", "192.168.1.53", false},                // no prefix
		{"eth0", "192.168.1.256/24", false},
		{"eth0", "192.168.1.53/33", false},
		{"eth0", "fd00::53/64", false},
		{"eth0", "::ffff:192.168.1.53/120", false},
		{"eth0", "127.0.0.53/8", false},
		{"eth0", "224.0.0.1/4", false},
		{"eth0", "169.254.1.1/16", false},
		{"eth0", "0.0.0.0/0", false},
		{"eth0", "10.0.0.1/7", false},
		{"eth0", "192.168.1.0/24", false},   // network address
		{"eth0", "192.168.1.255/24", false}, // broadcast address
		{"eth0", "255.255.255.255/32", false},
	}
	for _, tt := range tests {
		if err := CheckVIP(tt.iface, tt.address); (err == nil) != tt.ok {
			t.Errorf("CheckVIP(%q, %q) = %v, want ok %v", tt.iface, tt.address, err, tt.ok)
		}
	}
}

func TestCheckHubCeilingVIP(t *testing.T) {
	for _, tt := range []struct {
		entry string
		ok    bool
	}{
		{"eth0=192.168.1.53/24", true},
		{"eth0:192.168.1.53/24", false},
		{"192.168.1.53/24", false},
		{"eth0=192.168.1.53", false},
		{"lo=192.168.1.53/24", false},
		{"eth0=192.168.1.053/24", false},
		{"eth0= 192.168.1.53/24", false},
	} {
		if err := CheckHubCeiling(&agentv1.Ceiling{Vip: []string{tt.entry}}); (err == nil) != tt.ok {
			t.Errorf("vip entry %q: err = %v, want ok %v", tt.entry, err, tt.ok)
		}
	}
}

func TestVIPWithinCeiling(t *testing.T) {
	c := &agentv1.Ceiling{Vip: []string{"eth0=192.168.1.53/24"}, Exec: []string{"/usr/sbin/ip"}}
	req := func(iface, address string, release bool) *agentv1.ExecRequest {
		return &agentv1.ExecRequest{Action: &agentv1.ExecRequest_Vip{
			Vip: &agentv1.VirtualIP{Interface: iface, Address: address, Release: release},
		}}
	}
	tests := []struct {
		name   string
		c      *agentv1.Ceiling
		req    *agentv1.ExecRequest
		beyond bool // else allowed, unless invalid
		bad    bool
	}{
		{name: "claim listed", c: c, req: req("eth0", "192.168.1.53/24", false)},
		{name: "release listed", c: c, req: req("eth0", "192.168.1.53/24", true)},
		{name: "no ceiling", c: nil, req: req("eth0", "192.168.1.53/24", false), beyond: true},
		{name: "exec does not allow it", c: &agentv1.Ceiling{Exec: []string{"/usr/sbin/ip"}}, req: req("eth0", "192.168.1.53/24", false), beyond: true},
		{name: "other address", c: c, req: req("eth0", "192.168.1.1/24", false), beyond: true},
		{name: "other prefix", c: c, req: req("eth0", "192.168.1.53/32", true), beyond: true},
		{name: "other interface", c: c, req: req("wlan0", "192.168.1.53/24", false), beyond: true},
		{name: "invalid interface", c: c, req: req("eth0 dev lo", "192.168.1.53/24", false), bad: true},
		{name: "invalid address", c: c, req: req("eth0", "nope", false), bad: true},
	}
	for _, tt := range tests {
		err := WithinCeiling(tt.c, tt.req)
		switch {
		case tt.beyond && !errors.Is(err, ErrBeyondCeiling):
			t.Errorf("%s: err = %v, want ErrBeyondCeiling", tt.name, err)
		case tt.bad && (err == nil || errors.Is(err, ErrBeyondCeiling) || !errors.Is(err, ErrDenied)):
			t.Errorf("%s: err = %v, want a denial that is not beyond the ceiling", tt.name, err)
		case !tt.beyond && !tt.bad && err != nil:
			t.Errorf("%s: err = %v, want allowed", tt.name, err)
		}
	}
}

// A virtual IP move is dangerous: an automation takes it only when the hub
// grants it by id, and it is audited either way.
func TestVIPActionsNeedAGrant(t *testing.T) {
	for _, act := range []Action{AutomationVIPClaim, AutomationVIPRelease} {
		if c, ok := ClassOf(act); !ok || c != Dangerous {
			t.Errorf("%s class = %s, %v; want dangerous", act, c, ok)
		}
		audit := &memAudit{}
		e := NewWithConfig(audit, nil, Config{})
		err := e.Do(t.Context(), Request{ActorKind: ActorAutomation, ActorID: "pihole-selfheal", Action: act, Target: "pi"},
			func(context.Context) error { t.Fatalf("%s ran without a grant", act); return nil })
		if !errors.Is(err, ErrDenied) {
			t.Errorf("%s without a grant: err = %v, want denied", act, err)
		}
		if all := audit.all(); len(all) != 1 || all[0].Decision != Deny || all[0].Action != string(act) {
			t.Errorf("%s without a grant: audit = %+v, want one denial", act, all)
		}
		g := NewWithConfig(&memAudit{}, nil, Config{DangerousAutomations: []string{"pihole-selfheal"}})
		if got, reason := g.Check(Request{ActorKind: ActorAutomation, ActorID: "pihole-selfheal", Action: act}); got != Allow {
			t.Errorf("%s granted = %s (%s), want allow", act, got, reason)
		}
	}
}
