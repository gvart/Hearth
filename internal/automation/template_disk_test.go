// SPDX-License-Identifier: AGPL-3.0-only

package automation

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

const namedTemplatesYAML = `id: named
triggers:
  - id: go
    type: manual
actions:
  - id: say
    type: log
    message: '{{define "who"}}the pi{{end}}hello {{template "who"}} {{block "how" .}}again{{end}}'
`

const overBudgetYAML = `id: over
triggers:
  - id: go
    type: manual
actions:
  - id: say
    type: log
    message: '{{range 2000000}}xxxxxxxxxx{{end}}'
`

const neighbourYAML = `id: neighbour
triggers:
  - id: go
    type: manual
actions:
  - id: say
    type: log
    message: neighbour ran
`

// lockedBuffer is a log destination the runtime's goroutines can share.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// runDir runs the automations of a directory holding files, as the hub does.
func runDir(t *testing.T, files map[string]string) (*Runtime, *recorder, *lockedBuffer) {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	logs := &lockedBuffer{}
	log := slog.New(slog.NewTextHandler(logs, nil))
	rec := &recorder{}
	rt := New(Config{Dir: dir, Kinds: Builtin(log), Policy: policy.New(&auditLog{}), Runs: rec, Log: log})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- rt.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
	return rt, rec, logs
}

// fireAndWait fires the automation's trigger once it runs, and returns the run.
func fireAndWait(t *testing.T, rt *Runtime, rec *recorder, id string) store.AutomationRun {
	t.Helper()
	eventually(t, id+" to start", func() bool { return rt.Fire(id, "go") == nil })
	var run store.AutomationRun
	eventually(t, id+" to finish", func() bool {
		for _, r := range rec.all() {
			if r.AutomationID == id {
				run = r
				return true
			}
		}
		return false
	})
	return run
}

// TestDiskFileWithNamedTemplatesRuns: files that work today keep working.
func TestDiskFileWithNamedTemplatesRuns(t *testing.T) {
	rt, rec, logs := runDir(t, map[string]string{"named.yaml": namedTemplatesYAML})
	run := fireAndWait(t, rt, rec, "named")
	if run.Status != StatusSucceeded {
		t.Fatalf("run = %+v\nlogs:\n%s", run, logs)
	}
	if !strings.Contains(logs.String(), "hello the pi again") {
		t.Errorf("rendered message not logged:\n%s", logs)
	}
}

// TestDiskFileOverBudgetLoadsWithWarning: one file over the budget costs its
// own runs, never the directory.
func TestDiskFileOverBudgetLoadsWithWarning(t *testing.T) {
	rt, rec, logs := runDir(t, map[string]string{"neighbour.yaml": neighbourYAML, "over.yaml": overBudgetYAML})

	if run := fireAndWait(t, rt, rec, "neighbour"); run.Status != StatusSucceeded {
		t.Errorf("neighbour run = %+v\nlogs:\n%s", run, logs)
	}
	run := fireAndWait(t, rt, rec, "over")
	if run.Status != StatusFailed || !strings.Contains(run.Error, "render limit") {
		t.Errorf("over budget run = %+v, want failed naming the render limit", run)
	}
	var warning string
	for line := range strings.SplitSeq(logs.String(), "\n") {
		if strings.Contains(line, "level=WARN") && strings.Contains(line, "over.yaml") {
			warning = line
		}
	}
	if warning == "" {
		t.Errorf("no warning names over.yaml:\n%s", logs)
	}
	if strings.Contains(logs.String(), "automations not reloaded") {
		t.Errorf("the directory did not load:\n%s", logs)
	}
}

// TestNamedTemplatesAreBounded: templates calling each other get the same
// budget as any other, though they may write nothing at all.
func TestNamedTemplatesAreBounded(t *testing.T) {
	const levels = 40
	doubling := `{{define "t0"}}{{end}}`
	for i := 1; i <= levels; i++ {
		doubling += fmt.Sprintf(`{{define "t%d"}}{{template "t%d"}}{{template "t%d"}}{{end}}`, i, i-1, i-1)
	}
	for name, raw := range map[string]string{
		"calls doubling at every level": doubling + fmt.Sprintf(`{{template "t%d"}}`, levels),
		"a template calling itself":     `{{define "a"}}{{template "a"}}{{end}}{{template "a"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			text, err := parseTestText(raw)
			if err != nil {
				t.Fatal(err)
			}
			start := time.Now()
			_, err = text.Render(t.Context(), Event{Data: map[string]any{}})
			if !errors.Is(err, errRenderLimit) {
				t.Errorf("rendered with %v, want the render limit", err)
			}
			if d := time.Since(start); d > 10*time.Second {
				t.Errorf("took %s", d)
			}
		})
	}
}
