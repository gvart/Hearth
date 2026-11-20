// SPDX-License-Identifier: AGPL-3.0-only

package discovery

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/policy"
	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
	"github.com/gvart/hearth/internal/store"
)

func TestParseSubnetsFrom(t *testing.T) {
	subnets, auto, from, err := ParseSubnetsFrom([]string{
		"192.168.2.0/24", "auto", "10.0.5.0/24@nas", " 10.0.6.0/24 @ nas ", "10.0.0.0/22@pi",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !auto || !slices.Equal(subnets, []netip.Prefix{netip.MustParsePrefix("192.168.2.0/24")}) {
		t.Errorf("hub subnets = %v, auto %v", subnets, auto)
	}
	want := map[string][]netip.Prefix{
		"nas": {netip.MustParsePrefix("10.0.5.0/24"), netip.MustParsePrefix("10.0.6.0/24")},
		"pi":  {netip.MustParsePrefix("10.0.0.0/22")}, // MaxHosts applies to each scanner
	}
	if len(from) != len(want) || !slices.Equal(from["nas"], want["nas"]) || !slices.Equal(from["pi"], want["pi"]) {
		t.Errorf("from = %v, want %v", from, want)
	}
	for _, bad := range [][]string{
		{"10.0.5.0/24@"},
		{"auto@nas"},
		{"10.0.0.0/8@nas"},
		{"fd00::/64@nas"},
		{"10.0.0.0/22@nas", "10.1.0.0/24@nas"},
	} {
		if _, _, _, err := ParseSubnetsFrom(bad); err == nil {
			t.Errorf("ParseSubnetsFrom(%v) succeeded", bad)
		}
	}
}

func TestAgentHostsDropsWhatTheAgentShouldNotSend(t *testing.T) {
	subnets := []netip.Prefix{netip.MustParsePrefix("10.0.5.0/24")}
	got := agentHosts([]*agentv1.ScannedHost{
		{Mac: "2C:CF:67:00:00:01", Ip: "10.0.5.7", Hostname: " pi5.local "},
		{Mac: "2c:cf:67:00:00:01", Ip: "10.0.5.8"},                   // a repeated MAC
		{Mac: "00:11:32:00:00:02", Ip: "192.168.2.1"},                // outside the subnets
		{Mac: "ff:ff:ff:ff:ff:ff", Ip: "10.0.5.255"},                 // broadcast
		{Mac: "00:00:00:00:00:00", Ip: "10.0.5.9"},                   // incomplete
		{Mac: "nope", Ip: "10.0.5.10"},                               // not a MAC
		{Mac: "00:11:32:00:00:03", Ip: "fd00::1"},                    // not IPv4
		{Mac: "00:11:32:00:00:04", Ip: "10.0.5.4", Hostname: "\xff"}, // not UTF-8
		{Mac: "00:11:32:00:00:05", Ip: "10.0.5.5", Hostname: strings.Repeat("a", 1000)},
	}, subnets, Vendor)
	if len(got) != 3 {
		t.Fatalf("agentHosts = %+v; want the Pi and the two good Synology hosts", got)
	}
	if p := got[0]; p.MAC != "2c:cf:67:00:00:01" || p.IP != "10.0.5.7" || p.Hostname != "pi5.local" || p.Vendor != "Raspberry Pi" {
		t.Errorf("Pi = %+v; want a normalised MAC, a trimmed name and the hub's vendor", got[0])
	}
	if got[1].Hostname != "" || len(got[2].Hostname) != maxTextLen {
		t.Errorf("names = %q, %d bytes; want the bad one dropped, the long one clipped", got[1].Hostname, len(got[2].Hostname))
	}

	many := make([]*agentv1.ScannedHost, 0, MaxHosts+10)
	for i := range MaxHosts + 10 {
		many = append(many, &agentv1.ScannedHost{Mac: fmt.Sprintf("00:11:32:00:%02x:%02x", i>>8, i&0xff), Ip: "10.0.5.1"})
	}
	if n := len(agentHosts(many, subnets, nil)); n != MaxHosts {
		t.Errorf("agentHosts kept %d hosts; want at most %d", n, MaxHosts)
	}
}

// fakeAgents is a device's agent as hub.Agents reaches it.
type fakeAgents struct {
	ceiling []string // the scan subnets the agent reported
	result  *agentv1.ScanResult
	err     error
	sent    []*agentv1.ScanRequest
}

func (f *fakeAgents) CheckScan(_ context.Context, _ string, subnets []netip.Prefix) error {
	return policy.ScanWithinCeiling(&agentv1.Ceiling{Scan: f.ceiling}, subnets)
}

func (f *fakeAgents) Scan(ctx context.Context, device string, subnets []netip.Prefix, _ time.Duration) (string, *agentv1.ScanResult, error) {
	if err := f.CheckScan(ctx, device, subnets); err != nil {
		return "", nil, err
	}
	req := &agentv1.ScanRequest{}
	for _, p := range subnets {
		req.Subnets = append(req.Subnets, p.String())
	}
	f.sent = append(f.sent, req)
	if f.err != nil {
		return "", nil, f.err
	}
	return "dev-" + device, f.result, nil
}

func scannerFrom(t *testing.T, st *store.Store, pol Policy, agents Agents, ev Events) *Scanner {
	t.Helper()
	return New(Config{
		From:   map[string][]netip.Prefix{"pi": {netip.MustParsePrefix("10.0.5.0/24")}},
		Agents: agents, Hosts: st.NetworkHosts(), Policy: pol, Events: ev,
	})
}

func lastAudit(t *testing.T, st *store.Store) (store.AuditEntry, map[string]any) {
	t.Helper()
	entries, err := st.Audit().List(t.Context(), 10)
	if err != nil || len(entries) == 0 {
		t.Fatalf("audit = %v, %v", entries, err)
	}
	var detail map[string]any
	if err := json.Unmarshal(entries[0].Detail, &detail); err != nil {
		t.Fatal(err)
	}
	return entries[0], detail
}

// A subnet only a device is on: its agent sweeps it, and its hosts are
// stored as unmanaged hosts, found by that device.
func TestScanFromRecordsHostsOfTheDevice(t *testing.T) {
	ctx := t.Context()
	st := openStore(t)
	var ev events
	agents := &fakeAgents{ceiling: []string{"10.0.5.0/24"}, result: &agentv1.ScanResult{Hosts: []*agentv1.ScannedHost{
		{Mac: "2c:cf:67:00:00:01", Ip: "10.0.5.7", Hostname: "cam.local"},
		{Mac: "00:11:32:00:00:02", Ip: "10.0.5.1"},
	}}}
	s := scannerFrom(t, st, policy.New(st.Audit()), agents, &ev)
	if err := s.ScanFrom(ctx, "pi"); err != nil {
		t.Fatal(err)
	}
	if len(agents.sent) != 1 || !slices.Equal(agents.sent[0].GetSubnets(), []string{"10.0.5.0/24"}) {
		t.Fatalf("sent %v; want one scan of the device's subnet", agents.sent)
	}
	hosts, err := st.NetworkHosts().List(ctx)
	if err != nil || len(hosts) != 2 {
		t.Fatalf("hosts = %+v, %v; want both", hosts, err)
	}
	for _, h := range hosts {
		if h.ScannedBy != "dev-pi" || !slices.Contains(h.Sources, store.SourceScan) {
			t.Errorf("host %+v; want it scanned by dev-pi", h)
		}
	}
	if len(ev) != 0 {
		t.Errorf("the device's first scan published %v; want it to be its subnet's baseline", ev)
	}
	e, detail := lastAudit(t, st)
	if e.Action != string(policy.NetworkScan) || e.Decision != policy.Allow || e.Result != "ok" || e.Target != "10.0.5.0/24" ||
		detail["from"] != "pi" || detail["device_id"] != "dev-pi" || detail["hosts"] != float64(2) {
		t.Errorf("audit = %+v %v; want the scan from pi, ok, with its counts", e, detail)
	}
}

// Every refusal is audited: by policy, by the ceiling the agent reported
// (before anything is sent), and by the agent itself.
func TestScanFromRefusalsAreAudited(t *testing.T) {
	denyReads := policy.Config{Classes: map[policy.Class]policy.Mode{policy.Read: policy.ModeDeny}}
	if err := denyReads.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		ceiling  []string
		result   *agentv1.ScanResult
		denyRead bool
		sent     bool
		decision string
		result2  string
	}{
		"policy denies":  {ceiling: []string{"10.0.5.0/24"}, denyRead: true, decision: policy.Deny},
		"ceiling off":    {decision: policy.Deny, result2: "beyond the device's capability ceiling"},
		"outside":        {ceiling: []string{"10.0.6.0/24"}, decision: policy.Deny, result2: "scan 10.0.5.0/24"},
		"narrower":       {ceiling: []string{"10.0.5.0/25"}, decision: policy.Deny, result2: "scan 10.0.5.0/24"},
		"agent refuses":  {ceiling: []string{"10.0.5.0/24"}, result: &agentv1.ScanResult{Denied: true, Error: "beyond"}, sent: true, decision: policy.Allow, result2: "refused the scan"},
		"agent fails":    {ceiling: []string{"10.0.5.0/24"}, result: &agentv1.ScanResult{Error: "list interfaces: boom"}, sent: true, decision: policy.Allow, result2: "boom"},
		"agent too slow": {ceiling: []string{"10.0.5.0/24"}, sent: true, decision: policy.Allow, result2: "deadline"},
	} {
		t.Run(name, func(t *testing.T) {
			st := openStore(t)
			pol := policy.New(st.Audit())
			if tc.denyRead {
				pol = policy.NewWithConfig(st.Audit(), nil, denyReads)
			}
			agents := &fakeAgents{ceiling: tc.ceiling, result: tc.result}
			if name == "agent too slow" {
				agents.err = context.DeadlineExceeded
			}
			err := scannerFrom(t, st, pol, agents, nil).ScanFrom(t.Context(), "pi")
			if err == nil {
				t.Fatal("ScanFrom succeeded")
			}
			if tc.decision == policy.Deny && !errors.Is(err, policy.ErrDenied) {
				t.Errorf("ScanFrom = %v, want a denial", err)
			}
			if name == "agent refuses" && !errors.Is(err, policy.ErrBeyondCeiling) {
				t.Errorf("ScanFrom = %v, want beyond the ceiling", err)
			}
			if got := len(agents.sent) > 0; got != tc.sent {
				t.Errorf("scan sent to the agent: %v, want %v", got, tc.sent)
			}
			if hosts, _ := st.NetworkHosts().List(t.Context()); len(hosts) != 0 {
				t.Errorf("a refused scan recorded %v", hosts)
			}
			e, detail := lastAudit(t, st)
			if e.Action != string(policy.NetworkScan) || e.Decision != tc.decision || detail["from"] != "pi" ||
				!strings.Contains(e.Result, tc.result2) {
				t.Errorf("audit = %+v %v; want %s, from pi, with %q", e, detail, tc.decision, tc.result2)
			}
		})
	}
}

// Run sweeps the hub's subnets and each device's in turn; a device whose
// scan fails does not stop the others.
func TestRunScansFromEachDevice(t *testing.T) {
	st := openStore(t)
	agents := &fakeAgents{ceiling: []string{"10.0.5.0/24"}, result: &agentv1.ScanResult{}}
	s := New(Config{
		From: map[string][]netip.Prefix{
			"a": {netip.MustParsePrefix("10.0.6.0/24")}, // beyond the ceiling
			"b": {netip.MustParsePrefix("10.0.5.0/24")},
		},
		Agents: agents, Hosts: st.NetworkHosts(), Policy: policy.New(st.Audit()), Interval: time.Hour,
	})
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		entries, _ := st.Audit().List(t.Context(), 10)
		if len(entries) >= 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("audit = %+v; want a scan from each device", entries)
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if len(agents.sent) != 1 || agents.sent[0].GetSubnets()[0] != "10.0.5.0/24" {
		t.Errorf("sent %v; want only b's scan", agents.sent)
	}
}
