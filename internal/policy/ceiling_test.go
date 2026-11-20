// SPDX-License-Identifier: AGPL-3.0-only

package policy

import (
	"errors"
	"net/netip"
	"testing"

	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
)

func TestLogsWithinCeiling(t *testing.T) {
	t.Parallel()
	c := &agentv1.Ceiling{Logs: []string{"systemd:nginx.service", "systemd-user:hearth-*", "docker:*", "bad"}}
	for _, tc := range []struct {
		c       *agentv1.Ceiling
		manager string
		name    string
		ok      bool
	}{
		{c, "systemd", "nginx.service", true},
		{c, "systemd", "sshd.service", false},
		{c, "systemd-user", "hearth-i33.service", true},
		{c, "systemd-user", "nginx.service", false},
		// systemd:* would not cover a user's units, nor the reverse.
		{c, "systemd", "hearth-i33.service", false},
		{c, "docker", "anything", true},
		{c, "docker", "a/b", false}, // * does not cross a slash
		{c, "bad", "x", false},
		{nil, "docker", "web", false},
		{&agentv1.Ceiling{}, "docker", "web", false},
	} {
		err := LogsWithinCeiling(tc.c, &agentv1.LogSource{Manager: tc.manager, Name: tc.name})
		if (err == nil) != tc.ok || (err != nil && !errors.Is(err, ErrBeyondCeiling)) {
			t.Errorf("LogsWithinCeiling(%v, %s:%s) = %v, want ok=%v", tc.c.GetLogs(), tc.manager, tc.name, err, tc.ok)
		}
	}
	if err := LogsWithinCeiling(c, &agentv1.LogSource{Manager: "docker"}); err == nil || errors.Is(err, ErrBeyondCeiling) {
		t.Errorf("empty name = %v, want a plain error", err)
	}
	if class, ok := ClassOf(DeviceLogs); !ok || class != Read {
		t.Errorf("class of %s = %s, want read", DeviceLogs, class)
	}
}

func TestScanWithinCeiling(t *testing.T) {
	t.Parallel()
	c := &agentv1.Ceiling{Scan: []string{"192.168.2.0/24", "10.20.0.0/16", "bad", "fd00::/64"}}
	for _, tc := range []struct {
		c       *agentv1.Ceiling
		subnets []string
		ok      bool
	}{
		{c, []string{"192.168.2.0/24"}, true},
		{c, []string{"192.168.2.128/25"}, true},
		{c, []string{"10.20.5.0/24", "192.168.2.0/24"}, true},
		// Overlapping is not enough: a wider subnet sweeps beyond the ceiling.
		{c, []string{"192.168.0.0/16"}, false},
		{c, []string{"192.168.3.0/24"}, false},
		{c, []string{"192.168.2.0/24", "192.168.3.0/24"}, false},
		// Off by default: no ceiling, or one without scan subnets.
		{nil, []string{"192.168.2.0/24"}, false},
		{&agentv1.Ceiling{Probe: true, Shell: true}, []string{"192.168.2.0/24"}, false},
	} {
		var subnets []netip.Prefix
		for _, s := range tc.subnets {
			subnets = append(subnets, netip.MustParsePrefix(s))
		}
		err := ScanWithinCeiling(tc.c, subnets)
		if (err == nil) != tc.ok || (err != nil && !errors.Is(err, ErrBeyondCeiling)) {
			t.Errorf("ScanWithinCeiling(%v, %v) = %v, want ok=%v", tc.c.GetScan(), tc.subnets, err, tc.ok)
		}
		if err != nil && !errors.Is(err, ErrDenied) {
			t.Errorf("ScanWithinCeiling(%v) = %v, want it to wrap ErrDenied", tc.subnets, err)
		}
	}
	if err := ScanWithinCeiling(c, nil); err == nil || errors.Is(err, ErrBeyondCeiling) {
		t.Errorf("no subnet = %v, want a plain error", err)
	}
}
