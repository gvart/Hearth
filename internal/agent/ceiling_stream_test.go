// SPDX-License-Identifier: AGPL-3.0-only

package agent_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/gvart/hearth/internal/agent"
	"github.com/gvart/hearth/internal/hub"
	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
)

// reported is the ceiling the hub stored for device id from its agent.
func reported(t *testing.T, h *restartableHub, id string) hub.Facts {
	t.Helper()
	d, err := h.st.Devices().Get(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	var f hub.Facts
	if err := json.Unmarshal(d.Facts, &f); err != nil {
		t.Fatal(err)
	}
	return f
}

// TestCeilingFromHub: an agent started with no flags takes the ceiling the
// hub sets, on connect and on a change, at once, without a restart; it
// saves it, and reports flags and ceiling. A locked agent ignores it.
func TestCeilingFromHub(t *testing.T) {
	h := startRestartableHub(t, 100*time.Millisecond)
	id, dataDir := h.join(t)
	set := func(c *agentv1.Ceiling) {
		b, err := protojson.Marshal(c)
		if err != nil {
			t.Fatal(err)
		}
		if err := h.st.DeviceCeilings().Set(t.Context(), id, b, "test", time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	set(&agentv1.Ceiling{Probe: true})
	startAgentWith(t, agent.Config{DataDir: dataDir, FactsInterval: time.Hour})
	waitFor(t, 10*time.Second, "the ceiling set before the connect", func() bool {
		f := reported(t, h, id)
		return f.Ceiling != nil && f.Ceiling.Probe && f.ProtocolMinor == agent.ProtocolMinor
	})
	// A change reaches the agent from its next heartbeat and is reported
	// at once, not at the next facts tick (an hour away here).
	set(&agentv1.Ceiling{Logs: []string{"systemd:*"}})
	waitFor(t, 10*time.Second, "logs turned on", func() bool {
		f := reported(t, h, id)
		return f.Ceiling != nil && len(f.Ceiling.Logs) == 1 && !f.Ceiling.Probe
	})
	if f := reported(t, h, id); f.LocalCeiling == nil || len(f.LocalCeiling.Logs) != 0 || f.CeilingLocked {
		t.Errorf("reported flags %+v locked %v, want none, unlocked", f.LocalCeiling, f.CeilingLocked)
	}
	if b, err := os.ReadFile(filepath.Join(dataDir, agent.CeilingFile)); err != nil || !json.Valid(b) {
		t.Errorf("saved ceiling: %q, %v", b, err)
	}
}

// TestCeilingFromHubLocked: an agent started with --local-ceiling reports
// it, and only its flags.
func TestCeilingFromHubLocked(t *testing.T) {
	h := startRestartableHub(t, 100*time.Millisecond)
	id, dataDir := h.join(t)
	b, _ := protojson.Marshal(&agentv1.Ceiling{Shell: true, Docker: true})
	if err := h.st.DeviceCeilings().Set(t.Context(), id, b, "test", time.Now()); err != nil {
		t.Fatal(err)
	}
	startAgentWith(t, agent.Config{DataDir: dataDir, Ceiling: agent.Ceiling{Probe: true}, LocalCeiling: true})
	waitFor(t, 10*time.Second, "the locked agent's facts", func() bool {
		return reported(t, h, id).CeilingLocked
	})
	time.Sleep(500 * time.Millisecond) // a few heartbeats, each pushing the ceiling
	if f := reported(t, h, id); f.Ceiling == nil || f.Ceiling.Shell || f.Ceiling.Docker || !f.Ceiling.Probe {
		t.Errorf("locked agent reports %+v, want its flags only", f.Ceiling)
	}
	if _, err := os.Stat(filepath.Join(dataDir, agent.CeilingFile)); !os.IsNotExist(err) {
		t.Errorf("locked agent saved the hub's ceiling: %v", err)
	}
}
