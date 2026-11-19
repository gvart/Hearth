// SPDX-License-Identifier: AGPL-3.0-only

package automation

import (
	"context"
	"errors"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestTemplatesCallingEachOtherAreRefused(t *testing.T) {
	for name, raw := range map[string]string{
		"define": `{{define "a"}}x{{end}}{{template "a"}}`,
		"block":  `{{block "a" .}}x{{end}}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseTestText(raw); err == nil {
				t.Errorf("%s was accepted", raw)
			}
		})
	}
}

func TestRenderStopsWhatItCannotBound(t *testing.T) {
	for name, raw := range map[string]string{
		"range over a number":  `{{range 2000000000}}{{end}}`,
		"output in a loop":     `{{range 2000000}}xxxxxxxxxx{{end}}`,
		"wide printf":          `{{printf "%999999d" 1}}`,
		"precise printf":       `{{printf "%.999999f" 1.0}}`,
		"starred printf":       `{{printf "%*d" 999999 1}}`,
		"printf format piped":  `{{"%999999d" | printf}}`,
		"nested wide printf":   `{{print (printf "%999999d" 1)}}`,
		"computed wide printf": `{{printf (print "%" "999999d") 1}}`,
	} {
		t.Run(name, func(t *testing.T) {
			text, err := parseTestText(raw)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := text.Render(t.Context(), Event{Data: map[string]any{}}); !errors.Is(err, errRenderLimit) {
				t.Errorf("rendered with %v, want the render limit", err)
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
		`{{$a := "x"}}{{$a = print $a $a}}{{$a}}`:                  "xx",
		`{{range 2}}y{{end}}`:                                      "yy",
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

// TestRenderBoundsIntermediateValues: these double a value at every level and
// write nothing until the end, so a limit on the output alone comes too late.
func TestRenderBoundsIntermediateValues(t *testing.T) {
	const depth = 26 // about 64 MB without a limit
	for name, raw := range map[string]string{
		"nested with": strings.Repeat(`{{with print . .}}`, depth) + `x` + strings.Repeat(`{{end}}`, depth),
		"js chain":    `{{"\\"` + strings.Repeat(` | js`, depth) + `}}`,
		"quote chain": `{{"\""` + strings.Repeat(` | printf "%q"`, depth) + `}}`,
		"variables":   `{{$a := "xx"}}` + strings.Repeat(`{{$a = print $a $a}}`, depth) + `{{len $a}}`,
	} {
		t.Run(name, func(t *testing.T) {
			text, err := parseTestText(raw)
			if err != nil {
				t.Fatal(err)
			}
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			_, err = text.Render(t.Context(), Event{TriggerID: "t", Data: map[string]any{}})
			runtime.ReadMemStats(&after)
			if !errors.Is(err, errRenderLimit) {
				t.Errorf("rendered with %v, want the render limit", err)
			}
			// Everything allocated along the way, freed or not: without a
			// limit these reach gigabytes.
			if used := after.TotalAlloc - before.TotalAlloc; used > 128<<20 {
				t.Errorf("allocated %d MiB before stopping", used>>20)
			}
		})
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
