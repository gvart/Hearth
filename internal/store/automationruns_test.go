// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

func TestAutomationRunsRecordListPrune(t *testing.T) {
	s := openTest(t)
	ctx := t.Context()
	runs := s.AutomationRuns()
	base := time.UnixMilli(1_700_000_000_000).UTC()
	for i := range RunsKept + 5 {
		at := base.Add(time.Duration(i) * time.Second)
		if err := runs.Record(ctx, AutomationRun{
			ID: fmt.Sprintf("a-%03d", i), AutomationID: "a", TriggerID: "manual",
			StartedAt: at, FinishedAt: at, Status: "succeeded",
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := runs.Record(ctx, AutomationRun{
		ID: "b-1", AutomationID: "b", TriggerID: "manual", StartedAt: base, FinishedAt: base,
		Status: "failed", Error: "boom", Steps: []byte(`[{"id":"x","status":"failed"}]`),
	}); err != nil {
		t.Fatal(err)
	}

	got, err := runs.List(ctx, "a", 1000)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != RunsKept {
		t.Fatalf("a kept %d runs, want %d", len(got), RunsKept)
	}
	if got[0].ID != fmt.Sprintf("a-%03d", RunsKept+4) || got[len(got)-1].ID != "a-005" {
		t.Errorf("a runs from %s to %s, want newest first, oldest pruned", got[0].ID, got[len(got)-1].ID)
	}
	if string(got[0].Steps) != "[]" {
		t.Errorf("steps = %s, want []", got[0].Steps)
	}

	b, err := runs.List(ctx, "b", 10)
	if err != nil || len(b) != 1 || b[0].Error != "boom" || b[0].Status != "failed" || !b[0].StartedAt.Equal(base) {
		t.Fatalf("List(b) = %+v, %v", b, err)
	}
	all, err := runs.List(ctx, "", 3)
	if err != nil || len(all) != 3 {
		t.Fatalf("List(all, 3) = %d runs, %v", len(all), err)
	}

	for name, run := range map[string]AutomationRun{
		"no id":     {AutomationID: "a", Status: "succeeded"},
		"no status": {ID: "x", AutomationID: "a"},
		"bad steps": {ID: "x", AutomationID: "a", Status: "succeeded", Steps: []byte("{")},
	} {
		if err := runs.Record(ctx, run); err == nil {
			t.Errorf("Record(%s) = nil, want an error", name)
		}
	}
}

// A newer binary on a cluster database before schema 7: no history to read,
// and recording is refused the same way on every node until the migrate.
func TestAutomationRunsBeforeTheirSchema(t *testing.T) {
	ctx := t.Context()
	path := filepath.Join(t.TempDir(), "hearth.db")
	s, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	p, err := s.newMigrator()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.DownTo(ctx, automationRunsSchema-1); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	s, err = Open(ctx, path, WithoutUpgrade())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })

	if got, err := s.AutomationRuns().List(ctx, "", 10); err != nil || len(got) != 0 {
		t.Errorf("List before the schema = %v, %v; want none", got, err)
	}
	now := time.Now()
	err = s.AutomationRuns().Record(ctx, AutomationRun{
		ID: "r", AutomationID: "a", StartedAt: now, FinishedAt: now, Status: "succeeded",
	})
	if !errors.Is(err, ErrSchemaTooOld) || !IsDomainError(err) {
		t.Errorf("Record before the schema = %v, want a domain ErrSchemaTooOld", err)
	}
}
