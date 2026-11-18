// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/store"
)

func TestAutomationPlan(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good.yaml")
	bad := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(good, []byte("id: hello\ntriggers: [{id: go, type: manual}]\nactions:\n  - type: log\n    message: hi\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bad, []byte("id: hello\ntriggers: [{type: manual}]\nactions:\n  - type: log\n    mesage: hi\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	out, err := execute(t, "automation", "plan", good)
	if err != nil {
		t.Fatalf("plan: %v\n%s", err, out)
	}
	for _, want := range []string{"Automation hello (mode single)", `1. log-1 (log): log "hi"`, "Dry run: nothing was executed."} {
		if !strings.Contains(out, want) {
			t.Errorf("plan output does not contain %q:\n%s", want, out)
		}
	}

	_, err = execute(t, "automation", "plan", bad)
	if err == nil || !strings.Contains(err.Error(), bad+`:5: unknown field "mesage"`) {
		t.Errorf("plan of an invalid file = %v, want the error with its line", err)
	}
}

func TestAutomationRuns(t *testing.T) {
	dir, _ := initHub(t)
	st := openStore(t, dir)
	at := time.Now()
	for _, r := range []store.AutomationRun{
		{ID: "1", AutomationID: "hello", TriggerID: "go", StartedAt: at, FinishedAt: at, Status: "succeeded"},
		{
			ID: "2", AutomationID: "other", TriggerID: "go", StartedAt: at.Add(time.Second), FinishedAt: at.Add(time.Second),
			Status: "denied", Error: "act: denied by policy",
		},
	} {
		if err := st.AutomationRuns().Record(t.Context(), r); err != nil {
			t.Fatal(err)
		}
	}

	out, err := execute(t, "automation", "runs", "--data-dir", dir)
	if err != nil {
		t.Fatalf("runs: %v\n%s", err, out)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 3 || !strings.Contains(lines[1], "other") || !strings.Contains(lines[1], "denied by policy") ||
		!strings.Contains(lines[2], "hello") {
		t.Errorf("runs output:\n%s", out)
	}

	out, err = execute(t, "automation", "runs", "hello", "--data-dir", dir)
	if err != nil || strings.Contains(out, "other") || !strings.Contains(out, "hello") {
		t.Errorf("runs hello = %v:\n%s", err, out)
	}

	if _, err := execute(t, "automation", "runs", "--data-dir", t.TempDir()); err == nil ||
		!strings.Contains(err.Error(), "has `hearth hub` been started") {
		t.Errorf("runs on a wrong data dir = %v", err)
	}
}
