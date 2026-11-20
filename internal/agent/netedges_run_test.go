// SPDX-License-Identifier: AGPL-3.0-only

package agent_test

import (
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/agent"
	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
)

// countingReader returns the same edges on every read and counts the reads.
func countingReader(reads *atomic.Int32) func() (*agentv1.NetEdges, error) {
	return func() (*agentv1.NetEdges, error) {
		reads.Add(1)
		return &agentv1.NetEdges{
			Neighbors:   []*agentv1.Neighbor{{Ip: "192.0.2.1", Mac: "aa:bb:cc:00:00:01"}},
			Connections: []*agentv1.Connection{{PeerIp: "192.0.2.10", Port: 7443, Count: 1}},
		}, nil
	}
}

func TestRunSendsNetEdges(t *testing.T) {
	h := startRestartableHub(t, time.Minute)
	id, dataDir := h.join(t)
	var reads atomic.Int32
	cfg := agent.Config{DataDir: dataDir, NetEdgesInterval: 50 * time.Millisecond, Ceiling: agent.Ceiling{NetEdges: true}}
	a := startAgentWith(t, agent.WithNetEdgesReader(cfg, countingReader(&reads)))
	defer a.stop(t)

	waitFor(t, 10*time.Second, "the agent's network edges", func() bool {
		got, _ := h.netEdges.Get(id)
		return len(got) == 2
	})
	waitFor(t, 10*time.Second, "a second report", func() bool { return reads.Load() >= 2 })
}

// Without --allow-net-edges the agent never reads its tables, and sends the
// hub nothing, however long it runs.
func TestRunSendsNoNetEdgesWithoutTheCeiling(t *testing.T) {
	h := startRestartableHub(t, time.Second) // the shortest heartbeat an agent takes
	id, dataDir := h.join(t)
	var reads atomic.Int32
	cfg := agent.Config{DataDir: dataDir, NetEdgesInterval: 20 * time.Millisecond, Ceiling: agent.Ceiling{Probe: true, Shell: true}}
	a := startAgentWith(t, agent.WithNetEdgesReader(cfg, countingReader(&reads)))
	defer a.stop(t)

	// Two heartbeats: a hundred times the edges' interval.
	waitFor(t, 10*time.Second, "two heartbeats", func() bool {
		return strings.Count(h.logs.String(), "msg=heartbeat device_id="+id) >= 2
	})
	a.stop(t)
	if n := reads.Load(); n != 0 {
		t.Errorf("the agent read its network edges %d times, want never", n)
	}
	if logs := h.logs.String(); strings.Contains(logs, "net edges") || strings.Contains(logs, "network edges") {
		t.Errorf("the hub got network edges:\n%s", logs)
	}
	if got, _ := h.netEdges.Get(id); len(got) != 0 {
		t.Errorf("kept edges = %+v; want none", got)
	}
}
