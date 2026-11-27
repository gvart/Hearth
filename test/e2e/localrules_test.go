// SPDX-License-Identifier: AGPL-3.0-only

//go:build e2e

package e2e

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	// LocalRuleFiresWithin bounds how long after the hub stops a local rule
	// checking the hub has restarted the service: a check every second,
	// with a 2 s timeout, fires on its first failure.
	LocalRuleFiresWithin = 15 * time.Second
	// LocalRunSyncedWithin bounds how long after the hub is back the run is
	// in its audit log: the agent reconnects and sends its runs at once.
	LocalRunSyncedWithin = 20 * time.Second
	// e2eRestarts is where the systemctl stand-in of the e2e image writes
	// its arguments (Dockerfile).
	e2eRestarts = "/tmp/hearth-e2e-restarts"
)

// localWatchdog is a local rule of agent-1 that checks the hub's agent port
// from the device and restarts a service when it fails: it fires only while
// the hub is down.
const localWatchdog = `id: e2e-watchdog
local: true
triggers:
  - id: hub-down
    type: tcp
    address: hub:7443
    from: agent-1
    every: 1s
    timeout: 2s
actions:
  - id: restart-it
    type: restart
    device: agent-1
    service: systemd:e2e-dns.service
`

// localRuleWithHubDown is #70's "done when": a local rule fires with the hub
// stopped, and its run is in the hub's audit log and run history once the
// hub is back. It returns the API client of the restarted hub.
func (s *stack) localRuleWithHubDown(ctx context.Context, c *apiClient, id string) *apiClient {
	s.t.Helper()
	if err := c.put(ctx, "/api/v1/devices/"+id+"/capabilities", map[string]any{"hub": map[string]any{
		"logs": []string{"systemd:*"}, "probe": true, "restart": []string{"systemd:e2e-dns.service"},
	}}); err != nil {
		s.t.Fatalf("allow probes and the restart: %v", err)
	}
	if err := c.post(ctx, "/api/v1/automations", map[string]string{"yaml": localWatchdog}, nil); err != nil {
		s.t.Fatalf("save the local rule: %v", err)
	}
	at := time.Now()
	waitFor(ctx, s.t, at.Add(LocalRunSyncedWithin), "the local rule on agent-1", func() (bool, string) {
		logs := s.compose(ctx, "logs", "--no-color", "agent-1")
		return strings.Contains(logs, "local rule started"), "not started"
	})
	s.t.Logf("local rule running on agent-1 %v after the save", since(at))

	stopAt := time.Now()
	s.compose(ctx, "stop", "hub")
	waitFor(ctx, s.t, stopAt.Add(LocalRuleFiresWithin), "the restart with the hub stopped", func() (bool, string) {
		out, err := s.run(ctx, "exec", "-T", "agent-1", "cat", e2eRestarts)
		if err != nil {
			return false, "no restart yet"
		}
		return strings.Contains(out, "e2e-dns.service"), out
	})
	s.t.Logf("hub stopped → agent-1 restarted the service in %v", since(stopAt))

	startAt := time.Now()
	s.compose(ctx, "start", "hub")
	c = s.login(ctx)
	q := url.Values{"actor_kind": {"automation"}, "actor": {"e2e-watchdog"}, "action": {"automation.restart"}}
	waitFor(ctx, s.t, startAt.Add(LocalRunSyncedWithin), "the run in the audit log", func() (bool, string) {
		var page struct {
			Entries []struct {
				Result string `json:"result"`
				Detail struct {
					Local string `json:"local"`
				} `json:"detail"`
			} `json:"entries"`
		}
		if err := c.get(ctx, "/api/v1/audit?"+q.Encode(), &page); err != nil {
			return false, err.Error()
		}
		for _, e := range page.Entries {
			if e.Detail.Local == "ran on the device while the hub was unreachable" && e.Result == "ok" {
				return true, ""
			}
		}
		return false, fmt.Sprintf("%d entries, none run while the hub was unreachable", len(page.Entries))
	})
	var runs struct {
		Runs []struct {
			Status string `json:"status"`
			Steps  []struct {
				RanOn          string `json:"ran_on"`
				HubUnreachable bool   `json:"hub_unreachable"`
			} `json:"steps"`
		} `json:"runs"`
	}
	if err := c.get(ctx, "/api/v1/automations/e2e-watchdog/runs", &runs); err != nil {
		s.t.Fatalf("runs: %v", err)
	}
	found := false
	for _, r := range runs.Runs {
		found = found || r.Status == "succeeded" && len(r.Steps) > 0 && r.Steps[0].RanOn == id && r.Steps[0].HubUnreachable
	}
	if !found {
		s.t.Fatalf("run history has no run on %s while the hub was unreachable: %+v", id, runs.Runs)
	}
	s.t.Logf("hub back → the local run audited and in run history in %v", since(startAt))
	return c
}
