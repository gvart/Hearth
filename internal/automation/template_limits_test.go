// SPDX-License-Identifier: AGPL-3.0-only

package automation

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestTemplatesThatCannotBeBoundedAreRefused(t *testing.T) {
	for name, raw := range map[string]string{
		"range over a number":     `{{range 2000000}}x{{end}}`,
		"range over a call":       `{{range len "abc"}}x{{end}}`,
		"variable":                `{{$a := "x"}}{{$a}}`,
		"assignment":              `{{range .Trigger.L}}{{$a = "x"}}{{end}}`,
		"define":                  `{{define "a"}}x{{end}}{{template "a"}}`,
		"block":                   `{{block "a" .}}x{{end}}`,
		"wide printf":             `{{printf "%999999d" 1}}`,
		"precise printf":          `{{printf "%.999999f" 1.0}}`,
		"starred printf":          `{{printf "%*d" 999999 1}}`,
		"computed printf format":  `{{printf .Trigger.ID 1}}`,
		"printf format in a pipe": `{{"%999999d" | printf}}`,
		"nested wide printf":      `{{print (printf "%999999d" 1)}}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseTestText(raw); err == nil {
				t.Errorf("%s was accepted", raw)
			}
		})
	}
}

func TestBoundedTemplatesStillWork(t *testing.T) {
	for raw, want := range map[string]string{
		`{{printf "%.1f" .Trigger.Value}}`:                         "1.5",
		`{{printf "%-8s|" .Trigger.ID}}`:                           "t       |",
		`{{range .Trigger.L}}{{.}},{{end}}`:                        "a,b,",
		`{{range $i, $v := .Trigger.L}}{{$i}}={{$v}} {{end}}`:      "0=a 1=b ",
		`{{with .Trigger.ID}}{{.}}{{end}}`:                         "t",
		`{{if eq .Trigger.ID "t"}}yes{{else}}no{{end}}`:            "yes",
		`{{range .Trigger.L}}{{range $.Trigger.L}}x{{end}}{{end}}`: "xxxx",
	} {
		text, err := parseTestText(raw)
		if err != nil {
			t.Errorf("%s: %v", raw, err)
			continue
		}
		ev := Event{TriggerID: "t", Data: map[string]any{"Value": 1.5, "L": []string{"a", "b"}}}
		got, err := text.Render(t.Context(), ev)
		if err != nil || got != want {
			t.Errorf("%s rendered %q, %v, want %q", raw, got, err, want)
		}
	}
}

func TestRenderBoundsOutput(t *testing.T) {
	text, err := parseTestText(`{{range .Trigger.L}}{{.}}{{end}}`)
	if err != nil {
		t.Fatal(err)
	}
	item := strings.Repeat("x", 64<<10)
	items := make([]string, 64)
	for i := range items {
		items[i] = item
	}
	_, err = text.Render(t.Context(), Event{Data: map[string]any{"L": items}})
	if !errors.Is(err, errRenderLimit) {
		t.Errorf("rendered with %v, want the output limit", err)
	}
}

func TestRenderBoundsSteps(t *testing.T) {
	text, err := parseTestText(`{{range .Trigger.L}}{{end}}`)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	_, err = text.Render(t.Context(), Event{Data: map[string]any{"L": make([]struct{}, 1<<32)}})
	if !errors.Is(err, errRenderLimit) {
		t.Errorf("rendered with %v, want the step limit", err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("took %s", d)
	}
}

func TestRenderRespectsCancellation(t *testing.T) {
	text, err := parseTestText(`{{range .Trigger.L}}{{end}}`)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err = text.Render(ctx, Event{Data: map[string]any{"L": make([]struct{}, 8)}})
	if !errors.Is(err, context.Canceled) {
		t.Errorf("rendered with %v, want context.Canceled", err)
	}
}
