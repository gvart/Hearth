// SPDX-License-Identifier: AGPL-3.0-only

package automation

import (
	"encoding/json"
	"log/slog"
	"maps"
	"os"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// editorSchema is the web UI's description of the step forms.
type editorSchema map[string]map[string]struct {
	Fields []struct {
		Key     string   `json:"key"`
		Kind    string   `json:"kind"`
		Options []string `json:"options"`
	} `json:"fields"`
}

// sampleValue is a YAML value of the kind the form writes for a field.
func sampleValue(kind string, options []string) string {
	switch kind {
	case "number":
		return "1"
	case "bool":
		return "true"
	case "duration":
		return "5s"
	case "list":
		return "[a]"
	case "map":
		return "{a: b}"
	case "select":
		return options[0]
	}
	return "x"
}

// TestEditorSchemaMatchesTheHub keeps the visual editor's forms honest: every
// type and field it offers is one the hub accepts. A type or field the forms
// lack is safe, and shown read-only.
func TestEditorSchemaMatchesTheHub(t *testing.T) {
	b, err := os.ReadFile("../../web/src/automations/schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var schema editorSchema
	if err := json.Unmarshal(b, &schema); err != nil {
		t.Fatal(err)
	}
	kinds := Builtin(slog.New(slog.DiscardHandler))
	maps.Copy(kinds.Triggers, Triggers(TriggerDeps{}))
	maps.Copy(kinds.Actions, Actions(ActionDeps{}))

	build := func(section, typ string, p Params) error {
		if section == "triggers" {
			_, err := kinds.Triggers[typ](p)
			return err
		}
		_, err := kinds.Actions[typ](p)
		return err
	}
	known := func(section, typ string) bool {
		if section == "triggers" {
			return kinds.Triggers[typ] != nil
		}
		return kinds.Actions[typ] != nil
	}
	params := func(t *testing.T, field, value string) Params {
		t.Helper()
		var doc yaml.Node
		if err := yaml.Unmarshal([]byte(field+": "+value+"\n"), &doc); err != nil {
			t.Fatal(err)
		}
		return Params{node: doc.Content[0]}
	}

	if len(schema["conditions"]) != 0 && len(kinds.Conditions) == 0 {
		t.Error("the editor offers conditions, and the hub has none")
	}
	for _, section := range []string{"triggers", "actions"} {
		if len(schema[section]) == 0 {
			t.Fatalf("the schema has no %s", section)
		}
		for typ, spec := range schema[section] {
			if !known(section, typ) {
				t.Errorf("%s: the hub has no type %q", section, typ)
				continue
			}
			if err := build(section, typ, params(t, "not_a_field", "x")); err == nil || !strings.Contains(err.Error(), "unknown field") {
				t.Errorf("%s %s: an unknown field was not refused: %v", section, typ, err)
			}
			for _, f := range spec.Fields {
				err := build(section, typ, params(t, f.Key, sampleValue(f.Kind, f.Options)))
				if err != nil && strings.Contains(err.Error(), "unknown field") {
					t.Errorf("%s %s: the hub does not know the field %q: %v", section, typ, f.Key, err)
				}
				if err != nil && strings.Contains(err.Error(), "cannot unmarshal") {
					t.Errorf("%s %s: the field %q is not a %s: %v", section, typ, f.Key, f.Kind, err)
				}
			}
		}
	}
}
