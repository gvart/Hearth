// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"log/slog"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/durationpb"

	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
)

func scanRunner(c Ceiling) *runner {
	return &runner{cfg: Config{Ceiling: c}, log: slog.New(slog.DiscardHandler)}
}

func scanReq(subnets ...string) *agentv1.ScanRequest {
	return &agentv1.ScanRequest{Id: "s1", Subnets: subnets, Timeout: durationpb.New(10 * time.Second)}
}

// TestScanEnforcesTheCeiling checks the agent enforces --allow-scan itself,
// whatever the hub sends: off by default, and only within its subnets.
func TestScanEnforcesTheCeiling(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		ceiling Ceiling
		subnets []string
	}{
		"ceiling off":       {Ceiling{Probe: true, Shell: true}, []string{"192.0.2.0/30"}},
		"outside":           {Ceiling{Scan: []string{"198.51.100.0/24"}}, []string{"192.0.2.0/30"}},
		"wider than":        {Ceiling{Scan: []string{"192.0.2.0/30"}}, []string{"192.0.2.0/24"}},
		"one of two beyond": {Ceiling{Scan: []string{"192.0.2.0/30"}}, []string{"192.0.2.0/30", "198.51.100.0/30"}},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			res := scanRunner(tc.ceiling).scan(t.Context(), scanReq(tc.subnets...))
			if !res.GetDenied() || res.GetId() != "s1" || len(res.GetHosts()) != 0 ||
				!strings.Contains(res.GetError(), "capability ceiling") {
				t.Errorf("scan = %v, want denied", res)
			}
		})
	}
}

// TestScanRefusesBadRequests holds a request to a hub scan's limits, even
// within the ceiling: a malformed one is an error, not a denial.
func TestScanRefusesBadRequests(t *testing.T) {
	t.Parallel()
	r := scanRunner(Ceiling{Scan: []string{"10.0.0.0/8"}})
	for _, subnets := range [][]string{nil, {"auto"}, {"fd00::/64"}, {"10.0.0.0/16"}, {"nope"}} {
		res := r.scan(t.Context(), scanReq(subnets...))
		if res.GetDenied() || res.GetError() == "" {
			t.Errorf("scan of %v = %v, want refused as malformed", subnets, res)
		}
	}
	// One scan at a time.
	r.scanning.Store(true)
	if res := r.scan(t.Context(), scanReq("10.0.0.0/30")); res.GetDenied() || !strings.Contains(res.GetError(), "already running") {
		t.Errorf("second scan = %v, want refused", res)
	}
}

// TestScanWithinTheCeilingRuns sweeps a TEST-NET /30 (two addresses that
// never answer) from a device whose ceiling allows it.
func TestScanWithinTheCeilingRuns(t *testing.T) {
	t.Parallel()
	r := scanRunner(Ceiling{Scan: []string{"192.0.2.0/24"}})
	res := r.scan(t.Context(), scanReq("192.0.2.0/30"))
	if res.GetDenied() || res.GetError() != "" || res.GetId() != "s1" {
		t.Fatalf("scan = %v, want it run", res)
	}
	if r.scanning.Load() {
		t.Error("scan still marked running")
	}
	if got := (Ceiling{Scan: []string{"192.0.2.0/24"}}).proto().GetScan(); len(got) != 1 || got[0] != "192.0.2.0/24" {
		t.Errorf("reported ceiling scan = %v", got)
	}
}

func TestParseScan(t *testing.T) {
	t.Parallel()
	for entry, ok := range map[string]bool{
		"10.0.5.0/24": true, "10.0.0.0/8": true, "10.0.5.7/24": true,
		"10.0.5.0": false, "fd00::/64": false, "": false, "auto": false,
	} {
		if err := ParseScan(entry); (err == nil) != ok {
			t.Errorf("ParseScan(%q) = %v, want ok=%v", entry, err, ok)
		}
	}
}
