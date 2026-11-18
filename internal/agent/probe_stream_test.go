// SPDX-License-Identifier: AGPL-3.0-only

package agent_test

import (
	"errors"
	"net"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/gvart/hearth/internal/agent"
	"github.com/gvart/hearth/internal/hub"
	"github.com/gvart/hearth/internal/policy"
	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
)

// TestProbeOverStream runs checks from a real agent: the hub sends them only
// to an agent whose ceiling allows probes, and the agent answers with what
// it saw.
func TestProbeOverStream(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	req := func() *agentv1.ProbeRequest {
		return &agentv1.ProbeRequest{Timeout: durationpb.New(time.Second), Probe: &agentv1.ProbeRequest_Tcp{Tcp: &agentv1.TCPProbe{Address: addr}}}
	}

	h := startRestartableHub(t, time.Second)
	id, dataDir := h.join(t)
	startAgentWith(t, agent.Config{DataDir: dataDir, Ceiling: agent.Ceiling{Probe: true}})
	var res *agentv1.ProbeResult
	waitFor(t, 5*time.Second, "agent connected", func() bool {
		res, err = h.agents.Probe(t.Context(), id, req())
		return !errors.Is(err, hub.ErrAgentNotConnected)
	})
	if err != nil || res.GetDenied() || res.GetError() != "" {
		t.Fatalf("probe of an open port = %v, %v; want passed", res, err)
	}
	_ = ln.Close()
	if res, err = h.agents.Probe(t.Context(), id, req()); err != nil || res.GetError() == "" {
		t.Fatalf("probe of a closed port = %v, %v; want failed", res, err)
	}

	// The same device without --allow-probe: the hub refuses before sending.
	h2 := startRestartableHub(t, time.Second)
	id2, dataDir2 := h2.join(t)
	startAgentWith(t, agent.Config{DataDir: dataDir2})
	waitFor(t, 5*time.Second, "agent connected", func() bool {
		_, err = h2.agents.Probe(t.Context(), id2, req())
		return !errors.Is(err, hub.ErrAgentNotConnected)
	})
	if !errors.Is(err, policy.ErrBeyondCeiling) {
		t.Fatalf("probe without --allow-probe = %v, want beyond the ceiling", err)
	}
}
