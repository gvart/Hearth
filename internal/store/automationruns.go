// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// automationRunsSchema is the schema version whose migration (00007) added
// the automation_runs table. A newer binary runs on an older cluster
// database until `hearth cluster migrate`; until then no run is recorded.
const automationRunsSchema = 7

// RunsKept is how many runs each automation keeps in its history.
const RunsKept = 100

// AutomationRun is one finished run of an automation.
type AutomationRun struct {
	ID           string
	AutomationID string
	// TriggerID is the id of the trigger that started the run.
	TriggerID  string
	StartedAt  time.Time
	FinishedAt time.Time
	// Status is the run's outcome, as the automation package names it.
	Status string
	Error  string
	// Steps is a JSON array of step results; nil is stored as [].
	Steps json.RawMessage
}

// AutomationRuns is the repository for automation run history.
type AutomationRuns struct{ s *Store }

// AutomationRuns returns the automation run history repository.
func (s *Store) AutomationRuns() AutomationRuns { return AutomationRuns{s: s} }

// Record writes a finished run and prunes the automation's history to its
// newest RunsKept runs. Before schema 7 it fails with ErrSchemaTooOld.
func (r AutomationRuns) Record(ctx context.Context, run AutomationRun) error {
	if run.ID == "" || run.AutomationID == "" || run.Status == "" {
		return errors.New("record automation run: id, automation id and status are required")
	}
	steps := []byte(run.Steps)
	if len(steps) == 0 {
		steps = []byte("[]")
	}
	if !json.Valid(steps) {
		return errors.New("record automation run: steps are not valid JSON")
	}
	if _, err := r.s.apply(ctx, RecordAutomationRun{
		ID: run.ID, AutomationID: run.AutomationID, TriggerID: run.TriggerID,
		StartedAt: toMillis(run.StartedAt), FinishedAt: toMillis(run.FinishedAt),
		Status: run.Status, Error: run.Error, Steps: string(steps), Keep: RunsKept,
	}); err != nil {
		return fmt.Errorf("record run %s of automation %s: %w", run.ID, run.AutomationID, err)
	}
	return nil
}

// List returns up to limit runs, newest first: of automationID, or of every
// automation when it is empty. Before schema 7 there are none.
func (r AutomationRuns) List(ctx context.Context, automationID string, limit int) ([]AutomationRun, error) {
	if limit <= 0 {
		return nil, errors.New("list automation runs: limit must be positive")
	}
	v, err := schemaVersion(ctx, r.s.db)
	if err != nil {
		return nil, fmt.Errorf("list automation runs: %w", err)
	}
	if v < automationRunsSchema {
		return nil, nil
	}
	// liveOnly is a constant clause; values are bound.
	rest := ` FROM automation_runs WHERE (? = '' OR automation_id = ?)` + liveOnly(v >= VersionedSchema) +
		` ORDER BY started_at DESC, rowid DESC LIMIT ?`
	rows, err := r.s.list(ctx, automationID,
		gather{table: "automation_runs", order: then(desc(byInt(3)), desc(byText(0))), limit: limit},
		`SELECT id, automation_id, trigger_id, started_at, finished_at, status, error, steps`, rest,
		automationID, automationID, limit)
	if err != nil {
		return nil, fmt.Errorf("list automation runs: %w", err)
	}
	defer rows.Close()
	var out []AutomationRun
	for rows.Next() {
		var (
			run            AutomationRun
			started, ended int64
			steps          string
		)
		if err := rows.Scan(&run.ID, &run.AutomationID, &run.TriggerID, &started, &ended,
			&run.Status, &run.Error, &steps); err != nil {
			return nil, fmt.Errorf("list automation runs: %w", err)
		}
		run.StartedAt, run.FinishedAt = fromMillis(started), fromMillis(ended)
		run.Steps = json.RawMessage(steps)
		out = append(out, run)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list automation runs: %w", err)
	}
	return out, nil
}

// RecordAutomationRun inserts a finished automation run, then deletes all
// but the newest Keep runs of that automation.
type RecordAutomationRun struct {
	Stamp
	ID           string `json:"id"`
	AutomationID string `json:"automation_id"`
	TriggerID    string `json:"trigger_id"`
	StartedAt    int64  `json:"started_at"`
	FinishedAt   int64  `json:"finished_at"`
	Status       string `json:"status"`
	Error        string `json:"error"`
	Steps        string `json:"steps"`
	Keep         int    `json:"keep"`
}

// Op implements Command.
func (RecordAutomationRun) Op() string { return "record_automation_run" }

func (RecordAutomationRun) minSchema() int64 { return automationRunsSchema }

func (c RecordAutomationRun) apply(ctx context.Context, w *writer) (Result, error) {
	if err := w.insert(ctx, "automation_runs", row{
		"id": c.ID, "automation_id": c.AutomationID, "trigger_id": c.TriggerID, "started_at": c.StartedAt,
		"finished_at": c.FinishedAt, "status": c.Status, "error": c.Error, "steps": c.Steps,
	}); err != nil {
		return Result{}, err
	}
	return Result{}, pruneRuns(ctx, w, "automation_runs", `automation_id = ?`, c.Keep, c.AutomationID)
}
