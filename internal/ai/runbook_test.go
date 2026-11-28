// SPDX-License-Identifier: AGPL-3.0-only

package ai_test

import (
	"fmt"
	"log/slog"
	"maps"
	"strings"
	"testing"

	"github.com/gvart/hearth/internal/ai"
	"github.com/gvart/hearth/internal/automation"
)

func runbookKinds() automation.Kinds {
	kinds := automation.Builtin(slog.New(slog.DiscardHandler))
	maps.Copy(kinds.Triggers, automation.Triggers(automation.TriggerDeps{}))
	maps.Copy(kinds.Actions, automation.Actions(automation.ActionDeps{}))
	return kinds
}

// The example the model is shown is a runbook the hub loads.
func TestRunbookExampleParses(t *testing.T) {
	if _, err := automation.ParseRunbook("example.yaml", []byte(ai.RunbookExample), runbookKinds()); err != nil {
		t.Fatal(err)
	}
}

// Every check type and field the model is told of is one a runbook's check
// step takes.
func TestRunbookChecksParse(t *testing.T) {
	values := map[string]string{
		"url": "http://pi.lan/health", "status": "200", "address": "pi.lan:22", "name": "example.com",
		"server": "192.0.2.1", "from": "pi4", "timeout": "5s", "cluster": "homelab", "node": "pi-3",
		"version": "v1.12.8", "healthy": "true",
	}
	for _, c := range ai.RunbookChecks {
		var b strings.Builder
		fmt.Fprintf(&b, "id: c\nsteps:\n  - id: s\n    type: check\n    check:\n      type: %s\n", c.Type)
		for _, f := range c.Fields {
			v := values[f.Key]
			if c.Type == "talos_node" && f.Key == "node" {
				v = "192.0.2.50"
			}
			fmt.Fprintf(&b, "      %s: %s\n", f.Key, v)
		}
		if _, err := automation.ParseRunbook("c.yaml", []byte(b.String()), runbookKinds()); err != nil {
			t.Errorf("%s: %v\n%s", c.Type, err, b.String())
		}
	}
}

func TestPrepareRunbook(t *testing.T) {
	transcript := "pi@pi5:~ $ export API_TOKEN=s3cretSENTINEL\npi@pi5:~ $ curl -H 'Authorization: Bearer abcdefghijklmnopSENTINEL' x\n" +
		"pi@pi5:~ $ sudo apt-get install -y docker.io\n"
	p := ai.PrepareRunbook(ai.RunbookDraft{
		Device: "pi5", Notes: "installed docker", Transcript: transcript,
		Inventory: []ai.Section{{ID: "devices", Title: "Devices", Body: "pi5 (may run /usr/bin/apt-get)\n"}},
	}, 0)
	if p.Request.System != ai.RunbookSystem() || !strings.Contains(p.Request.System, "talos_node") ||
		!strings.Contains(p.Request.System, "kube_drain") {
		t.Fatal("the system prompt lacks the reference")
	}
	user := p.Request.Messages[0].Content
	if strings.Contains(user, "SENTINEL") || p.Redactions != 2 {
		t.Fatalf("not redacted (%d): %s", p.Redactions, user)
	}
	for _, want := range []string{"device pi5", "installed docker", "## Devices\npi5", "apt-get install -y docker.io"} {
		if !strings.Contains(user, want) {
			t.Errorf("the request lacks %q:\n%s", want, user)
		}
	}

	// A long transcript is cut to fit, and says so; the inventory keeps its share.
	long := ai.PrepareRunbook(ai.RunbookDraft{
		Device: "pi5", Transcript: strings.Repeat("$ ls\n", 2000),
		Inventory: []ai.Section{{ID: "devices", Title: "Devices", Body: "pi5\n"}},
	}, 1000)
	if len(long.Truncated) != 1 || long.Truncated[0] != "transcript" || len(long.Request.Messages[0].Content) > 1400 {
		t.Fatalf("truncated = %v, %d bytes", long.Truncated, len(long.Request.Messages[0].Content))
	}
	if !strings.Contains(long.Request.Messages[0].Content, "## Devices\npi5") {
		t.Fatal("the inventory was cut for the transcript")
	}
}
