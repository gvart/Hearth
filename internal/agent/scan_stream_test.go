// SPDX-License-Identifier: AGPL-3.0-only

package agent_test

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/agent"
	"github.com/gvart/hearth/internal/hub"
	"github.com/gvart/hearth/internal/policy"
	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
)

// TestScanOverStream runs a network scan from a real agent: the hub sends it
// only to an agent whose ceiling allows the subnet, and the agent answers.
func TestScanOverStream(t *testing.T) {
	t.Parallel()
	subnets := []netip.Prefix{netip.MustParsePrefix("192.0.2.0/30")} // TEST-NET: nobody answers

	h := startRestartableHub(t, time.Second)
	id, dataDir := h.join(t)
	startAgentWith(t, agent.Config{DataDir: dataDir, Ceiling: agent.Ceiling{Scan: []string{"192.0.2.0/24"}}})
	var (
		gotID string
		res   *agentv1.ScanResult
		err   error
	)
	waitFor(t, 5*time.Second, "agent connected", func() bool {
		gotID, res, err = h.agents.Scan(t.Context(), id, subnets, 10*time.Second)
		return !errors.Is(err, hub.ErrAgentNotConnected)
	})
	if err != nil || gotID != id || res.GetDenied() || res.GetError() != "" {
		t.Fatalf("scan within the ceiling = %q, %v, %v; want it run by %s", gotID, res, err, id)
	}
	// Wider than the ceiling: refused by the hub before sending.
	if _, _, err := h.agents.Scan(t.Context(), id, []netip.Prefix{netip.MustParsePrefix("192.0.0.0/22")}, time.Second); !errors.Is(err, policy.ErrBeyondCeiling) {
		t.Errorf("scan beyond the ceiling = %v, want refused", err)
	}

	// A device without --allow-scan: the hub refuses before sending.
	h2 := startRestartableHub(t, time.Second)
	id2, dataDir2 := h2.join(t)
	startAgentWith(t, agent.Config{DataDir: dataDir2, Ceiling: agent.Ceiling{Probe: true}})
	waitFor(t, 5*time.Second, "agent connected", func() bool {
		_, _, err = h2.agents.Scan(t.Context(), id2, subnets, time.Second)
		return !errors.Is(err, hub.ErrAgentNotConnected)
	})
	if !errors.Is(err, policy.ErrBeyondCeiling) {
		t.Fatalf("scan without --allow-scan = %v, want beyond the ceiling", err)
	}
	if err := h2.agents.CheckScan(t.Context(), id2, subnets); !errors.Is(err, policy.ErrBeyondCeiling) {
		t.Errorf("CheckScan without --allow-scan = %v, want beyond the ceiling", err)
	}
}
