// SPDX-License-Identifier: AGPL-3.0-only

package automation

import (
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func builtinKinds() Kinds { return Builtin(slog.New(slog.DiscardHandler)) }

const validYAML = `id: hello
description: Say hello by hand.
mode: queued
triggers:
  - id: by-hand
    type: manual
actions:
  - id: greet
    type: log
    description: the greeting
    message: hello
  - type: log
    message: again
`

func TestDirDigest(t *testing.T) {
	write := func(t *testing.T, dir, name, content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	digest := func(t *testing.T, dir string) string {
		t.Helper()
		d, err := DirDigest(dir)
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	base := t.TempDir()
	write(t, base, "a.yaml", "id: a\n")
	want := digest(t, base)

	tests := []struct {
		name  string
		setup func(t *testing.T, dir string)
		same  bool
	}{
		{"same files elsewhere", func(t *testing.T, dir string) { write(t, dir, "a.yaml", "id: a\n") }, true},
		{"files automations ignore", func(t *testing.T, dir string) {
			write(t, dir, "a.yaml", "id: a\n")
			write(t, dir, ".apply-123", "partial")
			write(t, dir, "notes.txt", "notes")
		}, true},
		{"edited file", func(t *testing.T, dir string) { write(t, dir, "a.yaml", "id: b\n") }, false},
		{"renamed file", func(t *testing.T, dir string) { write(t, dir, "b.yaml", "id: a\n") }, false},
		{"extra file", func(t *testing.T, dir string) {
			write(t, dir, "a.yaml", "id: a\n")
			write(t, dir, "b.yml", "id: b\n")
		}, false},
		{"no files", func(*testing.T, string) {}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			tt.setup(t, dir)
			if got := digest(t, dir) == want; got != tt.same {
				t.Errorf("same digest = %v, want %v", got, tt.same)
			}
		})
	}
	if digest(t, filepath.Join(base, "missing")) != digest(t, t.TempDir()) {
		t.Error("a missing directory digests unlike an empty one")
	}
}

func TestParseValid(t *testing.T) {
	a, err := Parse("hello.yaml", []byte(validYAML), builtinKinds())
	if err != nil {
		t.Fatal(err)
	}
	if a.ID != "hello" || a.Mode != ModeQueued || a.Description != "Say hello by hand." {
		t.Errorf("automation = %+v", a)
	}
	if len(a.Triggers) != 1 || a.Triggers[0].ID != "by-hand" || a.Triggers[0].Line != 5 {
		t.Errorf("triggers = %+v", a.Triggers)
	}
	if len(a.Actions) != 2 || a.Actions[0].ID != "greet" || a.Actions[0].Description != "the greeting" {
		t.Fatalf("actions = %+v", a.Actions)
	}
	// A step without an id is named after its type and position.
	if a.Actions[1].ID != "log-2" || a.Actions[1].Line != 12 {
		t.Errorf("second action = %+v", a.Actions[1])
	}
	if a.Actions[0].Impl.Describe() != `log "hello"` {
		t.Errorf("describe = %q", a.Actions[0].Impl.Describe())
	}
}

func TestParseDefaultsToSingle(t *testing.T) {
	a, err := Parse("a.yaml", []byte("id: a\ntriggers: [{type: manual}]\nactions: [{type: log, message: hi}]\n"), builtinKinds())
	if err != nil {
		t.Fatal(err)
	}
	if a.Mode != ModeSingle {
		t.Errorf("mode = %s, want single", a.Mode)
	}
}

// Every rejection names the file and the line of the problem.
func TestParseRejectsWithLineNumbers(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want []string
	}{
		{
			name: "syntax error",
			yaml: "id: a\nmode: single\ndescription: x: y\n",
			want: []string{"a.yaml: yaml: line 3: mapping values are not allowed"},
		},
		{
			name: "duplicate key",
			yaml: "id: a\nid: b\ntriggers: [{type: manual}]\nactions: [{type: log, message: hi, message: ho}]\n",
			want: []string{`a.yaml:2: field "id" is already set on line 1`, `a.yaml:4: field "message" is already set on line 4`},
		},
		{name: "empty file", yaml: "", want: []string{"a.yaml: empty file"}},
		{name: "not a mapping", yaml: "- a\n- b\n", want: []string{"a.yaml:1: an automation must be a mapping"}},
		{
			name: "unknown top-level field",
			yaml: "id: a\ntrigers: []\ntriggers: [{type: manual}]\nactions: [{type: log, message: hi}]\n",
			want: []string{`a.yaml:2: unknown field "trigers"`},
		},
		{
			name: "bad id and mode",
			yaml: "id: Not Valid\nmode: parallel\ntriggers: [{type: manual}]\nactions: [{type: log, message: hi}]\n",
			want: []string{`a.yaml:1: id "Not Valid"`, `a.yaml:2: mode "parallel" must be single, queued or restart`},
		},
		{
			name: "missing id, triggers and actions",
			yaml: "description: nothing\n",
			want: []string{
				`a.yaml:1: id ""`, "a.yaml:1: an automation needs at least one trigger",
				"a.yaml:1: an automation needs at least one action",
			},
		},
		{
			name: "unknown step type",
			yaml: "id: a\ntriggers:\n  - type: manual\nactions:\n  - id: x\n    type: reboot\n",
			want: []string{`a.yaml:6: unknown action type "reboot"`},
		},
		{
			name: "missing step type",
			yaml: "id: a\ntriggers:\n  - type: manual\nactions:\n  - id: x\n    message: hi\n",
			want: []string{"a.yaml:5: action type is required"},
		},
		{
			name: "unknown step field",
			yaml: "id: a\ntriggers:\n  - type: manual\nactions:\n  - type: log\n    message: hi\n    mesage: typo\n",
			want: []string{`a.yaml:7: unknown field "mesage"`},
		},
		{
			name: "step field of the wrong type",
			yaml: "id: a\ntriggers:\n  - type: manual\nactions:\n  - type: log\n    message: [a, b]\n",
			want: []string{"a.yaml:5: action log-1:", "line 6"},
		},
		{
			name: "step validation error",
			yaml: "id: a\ntriggers:\n  - type: manual\nactions:\n  - id: say\n    type: log\n",
			want: []string{"a.yaml:5: action say: message is required"},
		},
		{
			name: "section not a list",
			yaml: "id: a\ntriggers:\n  type: manual\nactions: [{type: log, message: hi}]\n",
			want: []string{"a.yaml:3: triggers must be a list"},
		},
		{
			name: "duplicate step id",
			yaml: "id: a\ntriggers:\n  - id: go\n    type: manual\nactions:\n  - id: go\n    type: log\n    message: hi\n",
			want: []string{`a.yaml:6: step id "go" is already used on line 3`},
		},
		{
			name: "bad step id",
			yaml: "id: a\ntriggers:\n  - id: Go Now\n    type: manual\nactions: [{type: log, message: hi}]\n",
			want: []string{`a.yaml:3: step id "Go Now"`},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, err := Parse("a.yaml", []byte(tt.yaml), builtinKinds())
			if err == nil {
				t.Fatalf("Parse = %+v, want an error", a)
			}
			for _, w := range tt.want {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("error %q\ndoes not contain %q", err, w)
				}
			}
		})
	}
}

func TestParseRejectsActionWithoutPolicyClass(t *testing.T) {
	kinds := builtinKinds()
	kinds.Actions["rogue"] = func(Params) (Action, error) { return &fakeAction{policy: "rogue.thing"}, nil }
	_, err := Parse("a.yaml", []byte("id: a\ntriggers: [{type: manual}]\nactions:\n  - type: rogue\n"), kinds)
	if err == nil || !strings.Contains(err.Error(), `a.yaml:4: action type "rogue" has no policy class`) {
		t.Fatalf("err = %v, want the action rejected for lacking a policy class", err)
	}
}

func TestLoadDir(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("a.yaml", "id: a\ntriggers: [{type: manual}]\nactions: [{type: log, message: hi}]\n")
	write("b.yml", "id: b\ntriggers: [{type: manual}]\nactions: [{type: log, message: hi}]\n")
	write("notes.txt", "not an automation")
	write(".hidden.yaml", "not: valid")
	if err := os.Mkdir(filepath.Join(dir, "sub.yaml"), 0o700); err != nil {
		t.Fatal(err)
	}
	set, err := LoadDir(dir, builtinKinds())
	if err != nil {
		t.Fatal(err)
	}
	if len(set) != 2 || set[0].ID != "a" || set[1].ID != "b" {
		t.Fatalf("set = %+v", set)
	}

	write("c.yaml", "id: a\ntriggers: [{type: manual}]\nactions: [{type: log, message: hi}]\n")
	write("d.yaml", "id: d\n")
	_, err = LoadDir(dir, builtinKinds())
	if err == nil || !strings.Contains(err.Error(), `automation id "a" is already used by`) ||
		!strings.Contains(err.Error(), "d.yaml:1: an automation needs at least one trigger") {
		t.Fatalf("err = %v, want both the duplicate id and the invalid file", err)
	}

	set, err = LoadDir(filepath.Join(dir, "missing"), builtinKinds())
	if err != nil || len(set) != 0 {
		t.Fatalf("missing dir = %v, %v; want no automations", set, err)
	}
}
