// SPDX-License-Identifier: AGPL-3.0-only

package automation

import (
	"log/slog"
	"maps"
	"strings"
	"testing"
)

// The examples in docs/automations.md load and plan with the kinds the hub
// uses, even without Prometheus or a registry.
func TestTriggersLoadAndPlan(t *testing.T) {
	kinds := Builtin(slog.New(slog.DiscardHandler))
	maps.Copy(kinds.Triggers, Triggers(TriggerDeps{}))
	a, err := Parse("lab.yaml", []byte(`id: lab-watch
triggers:
  - id: nas-hot
    type: metric
    device: nas
    metric: cpu
    above: 90
    for: 5m
  - id: pihole-up
    type: metric
    query: 'up{job="pihole"}'
    below: 1
    every: 1m
  - id: nas-gone
    type: device
    device: nas
    to: offline
  - id: pihole-dns
    type: dns
    name: example.com
    server: 192.168.1.2
  - id: grafana
    type: http
    url: http://grafana.lan:3000/api/health
    status: 200
    for: 1m
  - id: ssh
    type: tcp
    address: nas.lan:22
    every: 30s
    timeout: 3s
  - id: nightly
    type: schedule
    cron: "0 3 * * *"
actions:
  - type: log
    message: something happened
`), kinds)
	if err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	if err := Plan(&out, a); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"- nas-hot (metric): fires when cpu of device nas is above 90 for 5m0s (checked every 30s)",
		`- pihole-up (metric): fires when query "up{job=\"pihole\"}" is below 1 (checked every 1m0s)`,
		"- nas-gone (device): fires when device nas goes offline",
		"- pihole-dns (dns): fires when DNS lookup of example.com A at 192.168.1.2:53 fails (checked every 10s from the hub)",
		"- grafana (http): fires when HTTP GET http://grafana.lan:3000/api/health (expecting status 200) fails for 1m0s",
		"- ssh (tcp): fires when TCP connect to nas.lan:22 fails (checked every 30s from the hub)",
		`- nightly (schedule): fires on schedule "0 3 * * *"`,
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("plan does not contain %q:\n%s", want, out.String())
		}
	}
}

// A trigger error points at the trigger's line.
func TestTriggerErrorHasLine(t *testing.T) {
	kinds := Builtin(slog.New(slog.DiscardHandler))
	maps.Copy(kinds.Triggers, Triggers(TriggerDeps{}))
	_, err := Parse("bad.yaml", []byte(`id: bad
triggers:
  - type: tcp
    address: nas
actions:
  - type: log
    message: x
`), kinds)
	wantErrContains(t, err, "bad.yaml:3: trigger tcp-1: address must be host:port")
}
