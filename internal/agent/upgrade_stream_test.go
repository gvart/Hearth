// SPDX-License-Identifier: AGPL-3.0-only

package agent_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/agent"
	"github.com/gvart/hearth/internal/hub"
	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
)

// TestUpgradeOverStream upgrades a real agent: it answers with the new
// version, its binary is replaced, and Run ends with ErrUpgraded for the
// service manager to restart it.
func TestUpgradeOverStream(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("the fake release's hearth is a shell script")
	}
	archive, sum := agent.FakeRelease(t, "hearth", "v9.9.9")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(archive) }))
	t.Cleanup(srv.Close)
	exe := filepath.Join(t.TempDir(), "hearth")
	if err := os.WriteFile(exe, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}

	h := startRestartableHub(t, time.Second)
	id, dataDir := h.join(t)
	a := startAgentWith(t, agent.WithSelfUpgrade(agent.Config{DataDir: dataDir}, exe))
	req := &agentv1.UpgradeRequest{Version: "v9.9.9", Url: srv.URL + "/hearth.tar.gz", Sha256: sum}
	var (
		res *agentv1.UpgradeResult
		err error
	)
	waitFor(t, 5*time.Second, "agent connected", func() bool {
		res, err = h.agents.Upgrade(t.Context(), id, req)
		return !errors.Is(err, hub.ErrAgentNotConnected)
	})
	if err != nil || !res.GetOk() || res.GetVersion() != "v9.9.9" {
		t.Fatalf("upgrade = %v, %v; want ok", res, err)
	}
	select {
	case err := <-a.done:
		if !errors.Is(err, agent.ErrUpgraded) {
			t.Fatalf("Run = %v, want ErrUpgraded", err)
		}
		a.done = nil
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after the upgrade")
	}
	if b, _ := os.ReadFile(exe); !strings.Contains(string(b), "hearth v9.9.9") {
		t.Errorf("executable = %q, want the new binary", b)
	}
}
