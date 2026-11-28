// SPDX-License-Identifier: AGPL-3.0-only

package ai_test

import (
	"encoding/json"
	"log/slog"
	"maps"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/gvart/hearth/internal/ai"
	"github.com/gvart/hearth/internal/automation"
)

// TestDraftReferenceMatchesTheEditor keeps what the model is told the same
// as the web editor's forms: every type and field of one is in the other.
func TestDraftReferenceMatchesTheEditor(t *testing.T) {
	b, err := os.ReadFile("../../web/src/automations/schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]map[string]struct {
		Fields []struct {
			Key string `json:"key"`
		} `json:"fields"`
	}
	if err := json.Unmarshal(b, &schema); err != nil {
		t.Fatal(err)
	}
	for section, refs := range map[string][]ai.StepRef{"triggers": ai.DraftTriggers, "actions": ai.DraftActions} {
		told := map[string][]string{}
		for _, r := range refs {
			for _, f := range r.Fields {
				told[r.Type] = append(told[r.Type], f.Key)
			}
			if _, ok := told[r.Type]; !ok {
				told[r.Type] = nil
			}
		}
		for typ, spec := range schema[section] {
			keys, ok := told[typ]
			if !ok {
				t.Errorf("%s %s: in the editor, not in the draft reference", section, typ)
				continue
			}
			var want []string
			for _, f := range spec.Fields {
				want = append(want, f.Key)
			}
			if !slices.Equal(slices.Sorted(slices.Values(keys)), slices.Sorted(slices.Values(want))) {
				t.Errorf("%s %s: the reference has %v, the editor %v", section, typ, keys, want)
			}
			delete(told, typ)
		}
		for typ := range told {
			t.Errorf("%s %s: in the draft reference, not in the editor", section, typ)
		}
	}
	if len(schema["conditions"]) != 0 {
		t.Error("the editor offers conditions: tell the model about them")
	}
}

// The example the model is shown is a file the hub saves.
func TestDraftExampleParses(t *testing.T) {
	kinds := automation.Builtin(slog.New(slog.DiscardHandler))
	maps.Copy(kinds.Triggers, automation.Triggers(automation.TriggerDeps{}))
	maps.Copy(kinds.Actions, automation.Actions(automation.ActionDeps{}))
	if _, err := automation.ParseForSave("example.yaml", []byte(ai.DraftExample), kinds); err != nil {
		t.Fatal(err)
	}
}

func TestPrepareDraft(t *testing.T) {
	p := ai.PrepareDraft(ai.Draft{
		Request: "restart pihole when DNS fails, password=hunter2SENTINEL",
		Inventory: []ai.Section{
			{ID: "devices", Title: "Devices", Body: "pi4 (hostname raspberrypi)\n"},
			{ID: "channels", Title: "Notification channels", Body: ""},
		},
	}, 0)
	if p.Request.System != ai.DraftSystem() || !strings.Contains(p.Request.System, "kube_drain") {
		t.Fatal("the system prompt lacks the reference")
	}
	user := p.Request.Messages[0].Content
	if strings.Contains(user, "hunter2SENTINEL") || p.Redactions != 1 {
		t.Fatalf("not redacted (%d): %s", p.Redactions, user)
	}
	for _, want := range []string{"restart pihole", "## Devices\npi4", "## Notification channels\n(none)"} {
		if !strings.Contains(user, want) {
			t.Errorf("the request lacks %q:\n%s", want, user)
		}
	}

	// A long inventory is cut to fit, and says so.
	long := ai.PrepareDraft(ai.Draft{Request: "x", Inventory: []ai.Section{{ID: "devices", Title: "Devices", Body: strings.Repeat("pi\n", 1000)}}}, 200)
	if len(long.Truncated) != 1 || len(long.Request.Messages[0].Content) > 400 {
		t.Fatalf("truncated = %v, %d bytes", long.Truncated, len(long.Request.Messages[0].Content))
	}
}

func TestRetryDraft(t *testing.T) {
	first := ai.PrepareDraft(ai.Draft{Request: "x"}, 0)
	next, n := ai.RetryDraft(first.Request, "id: x\ntoken: ghp_0123456789abcdefghijABCDEFGHIJ012345\n", []string{"line 2: unknown field \"token\""})
	if len(next.Messages) != 3 || next.Messages[1].Role != ai.RoleAssistant || next.Messages[2].Role != ai.RoleUser {
		t.Fatalf("messages = %+v", next.Messages)
	}
	if !strings.Contains(next.Messages[2].Content, `line 2: unknown field`) {
		t.Fatalf("the problems are not fed back: %s", next.Messages[2].Content)
	}
	if strings.Contains(next.Messages[1].Content, "ghp_") || n == 0 {
		t.Fatalf("the answer was not redacted: %s", next.Messages[1].Content)
	}
	if len(first.Request.Messages) != 1 {
		t.Fatal("the first request changed")
	}
}

func TestExtractYAML(t *testing.T) {
	const want = "id: a\ntriggers: []\n"
	for _, in := range []string{
		"id: a\ntriggers: []",
		"```yaml\nid: a\ntriggers: []\n```",
		"Here it is:\n\n```\nid: a\ntriggers: []\n```\nEnjoy.",
		"Sure! Here is the file:\nid: a\ntriggers: []\n",
		"\r\nid: a\r\ntriggers: []\r\n",
	} {
		if got := ai.ExtractYAML(in); got != want {
			t.Errorf("ExtractYAML(%q) = %q", in, got)
		}
	}
}
