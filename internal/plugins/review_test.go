// SPDX-License-Identifier: AGPL-3.0-only

package plugins

import (
	"errors"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/policy"
)

// A plugin that handles one message at a time cannot answer a ping while
// it runs a long command: it is not taken for hung.
func TestSequentialPluginSurvivesLongCommand(t *testing.T) {
	t.Parallel()
	o := fastOptions
	o.CommandTimeout = 25 * time.Second
	audit := &memAudit{}
	m, err := New(Config{Manifests: []Manifest{helperManifest(t, "p", "good")}, Policy: policy.New(audit), Options: o})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = m.Run(t.Context()) }()
	waitFor(t, "the plugin's devices", func() bool { return commandsRun(m, "p") == "0" })
	// 15s against a 500ms ping timeout.
	if _, err := m.Command(t.Context(), policy.ActorWeb, "x", "p", CommandRequest{Command: "slow"}); err != nil {
		t.Fatalf("slow command: %v", err)
	}
	if s := status(m, "p"); s.Restarts != 0 || s.State != StateRunning {
		t.Fatalf("plugin restarted during a long command: %+v", s)
	}
	// Pings resume afterwards.
	if _, err := m.Command(t.Context(), policy.ActorWeb, "x", "p", CommandRequest{Command: "toggle"}); err != nil {
		t.Fatal(err)
	}
}

// Commands beyond the cap are refused as busy; the plugin is not killed.
func TestTooManyCommandsAreRefusedNotKilled(t *testing.T) {
	m, _ := startManager(t, policy.Config{}, helperManifest(t, "p", "good"))
	waitFor(t, "the plugin's devices", func() bool { return commandsRun(m, "p") == "0" })
	var wg sync.WaitGroup
	var mu sync.Mutex
	ok, busy := 0, 0
	for range maxInFlight + 20 {
		wg.Go(func() {
			_, err := m.Command(t.Context(), policy.ActorWeb, "x", "p", CommandRequest{Command: "async"})
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				ok++
			case errors.Is(err, ErrBusy) && errors.Is(err, ErrUnavailable):
				busy++
			default:
				t.Errorf("err = %v", err)
			}
		})
	}
	wg.Wait()
	if ok < maxInFlight || busy == 0 || ok+busy != maxInFlight+20 {
		t.Errorf("ok %d, busy %d", ok, busy)
	}
	if s := status(m, "p"); s.Restarts != 0 {
		t.Errorf("plugin restarted: %+v", s)
	}
}

func TestStartAuditsProgramDigest(t *testing.T) {
	m, audit := startManager(t, policy.Config{}, helperManifest(t, "p", "good"))
	waitFor(t, "the plugin", func() bool { return status(m, "p").State == StateRunning })
	starts := audit.find(string(policy.PluginStart), policy.Allow)
	if len(starts) == 0 || !regexp.MustCompile(`"sha256":"[0-9a-f]{64}"`).Match(starts[0].Detail) {
		t.Fatalf("plugin.start detail = %+v", starts)
	}
	if !strings.Contains(string(starts[0].Detail), `"command":"/`) {
		t.Errorf("detail = %s", starts[0].Detail)
	}
}
