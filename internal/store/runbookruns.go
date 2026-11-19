// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// runbookRunsSchema is the schema version whose migration (00016) added the
// runbook_runs table. A newer binary runs on an older cluster database until
// `hearth cluster migrate`; until then no run can start.
const runbookRunsSchema = 16

// RunbookRunsKept is how many finished runs each runbook keeps. Runs that
// have not finished are never pruned.
const RunbookRunsKept = 100

// ErrRunbookRunConflict is returned when saving a runbook run that changed
// since it was read: another hub or operator got there first.
var ErrRunbookRunConflict = errors.New("runbook run changed since it was read")

// RunbookRun is one run of a runbook.
type RunbookRun struct {
	ID        string
	RunbookID string
	// Status is the run's state, as the automation package names it.
	Status string
	// Version counts the writes to the run: Save succeeds only from the
	// version the run was read at.
	Version   int64
	StartedBy string
	StartedAt time.Time
	UpdatedAt time.Time
	// FinishedAt is zero until the run has finished.
	FinishedAt time.Time
	// Source is the sealed runbook file the run started from. List and Open
	// leave it out.
	Source []byte
	// State is the run's JSON document.
	State json.RawMessage
}

// RunbookRuns is the repository for runbook runs.
type RunbookRuns struct{ s *Store }

// RunbookRuns returns the runbook runs repository.
func (s *Store) RunbookRuns() RunbookRuns { return RunbookRuns{s: s} }

// requireSchema refuses a write before the schema that added the table. It
// runs before the proposal: a hub still on an older binary halts on a command
// it cannot decode.
func (r RunbookRuns) requireSchema(ctx context.Context) error {
	v, err := schemaVersion(ctx, r.s.db)
	if err != nil {
		return err
	}
	if v < runbookRunsSchema {
		return fmt.Errorf("%w: it needs %d, the database is at %d; run `hearth cluster migrate` first",
			ErrSchemaTooOld, runbookRunsSchema, v)
	}
	return nil
}

// Create stores a new run at version 1 and prunes the runbook's finished runs
// to the newest RunbookRunsKept. Before schema 16 it fails with
// ErrSchemaTooOld.
func (r RunbookRuns) Create(ctx context.Context, run RunbookRun) error {
	if run.ID == "" || run.RunbookID == "" || run.Status == "" || run.StartedBy == "" {
		return errors.New("create runbook run: id, runbook id, status and starter are required")
	}
	if !json.Valid(run.State) {
		return errors.New("create runbook run: state is not valid JSON")
	}
	if err := r.requireSchema(ctx); err != nil {
		return fmt.Errorf("create run %s of runbook %s: %w", run.ID, run.RunbookID, err)
	}
	if _, err := r.s.apply(ctx, CreateRunbookRun{
		ID: run.ID, RunbookID: run.RunbookID, Status: run.Status, StartedBy: run.StartedBy,
		StartedAt: toMillis(run.StartedAt), Source: run.Source, State: string(run.State), Keep: RunbookRunsKept,
	}); err != nil {
		return fmt.Errorf("create run %s of runbook %s: %w", run.ID, run.RunbookID, err)
	}
	return nil
}

// Save writes run's status and state if the stored run is still at
// run.Version, and returns the new version. It fails with
// ErrRunbookRunConflict when the run has moved on and ErrNotFound when it is
// gone.
func (r RunbookRuns) Save(ctx context.Context, run RunbookRun) (int64, error) {
	if !json.Valid(run.State) {
		return 0, errors.New("save runbook run: state is not valid JSON")
	}
	if err := r.requireSchema(ctx); err != nil {
		return 0, fmt.Errorf("save runbook run %s: %w", run.ID, err)
	}
	var finished int64
	if !run.FinishedAt.IsZero() {
		finished = toMillis(run.FinishedAt)
	}
	if _, err := r.s.apply(ctx, SaveRunbookRun{
		ID: run.ID, Version: run.Version, Status: run.Status,
		UpdatedAt: toMillis(run.UpdatedAt), FinishedAt: finished, State: string(run.State),
	}); err != nil {
		return 0, fmt.Errorf("save runbook run %s: %w", run.ID, err)
	}
	return run.Version + 1, nil
}

// Get returns one run with its source, or ErrNotFound.
func (r RunbookRuns) Get(ctx context.Context, id string) (RunbookRun, error) {
	out, err := r.query(ctx, `SELECT `+runbookRunColumns+`, source FROM runbook_runs WHERE id = ?`, id)
	if err != nil {
		return RunbookRun{}, fmt.Errorf("get runbook run %s: %w", id, err)
	}
	if len(out) == 0 {
		return RunbookRun{}, fmt.Errorf("get runbook run %s: %w", id, ErrNotFound)
	}
	return out[0], nil
}

// List returns up to limit runs, newest first: of runbookID, or of every
// runbook when it is empty. Before schema 16 there are none.
func (r RunbookRuns) List(ctx context.Context, runbookID string, limit int) ([]RunbookRun, error) {
	if limit <= 0 {
		return nil, errors.New("list runbook runs: limit must be positive")
	}
	out, err := r.query(ctx, `SELECT `+runbookRunColumns+`, x'' FROM runbook_runs
		WHERE ? = '' OR runbook_id = ? ORDER BY started_at DESC, rowid DESC LIMIT ?`, runbookID, runbookID, limit)
	if err != nil {
		return nil, fmt.Errorf("list runbook runs: %w", err)
	}
	return out, nil
}

// Open returns every run that has not finished, oldest first. Before schema
// 15 there are none.
func (r RunbookRuns) Open(ctx context.Context) ([]RunbookRun, error) {
	out, err := r.query(ctx, `SELECT `+runbookRunColumns+`, x'' FROM runbook_runs
		WHERE finished_at = 0 ORDER BY started_at, rowid`)
	if err != nil {
		return nil, fmt.Errorf("list open runbook runs: %w", err)
	}
	return out, nil
}

const runbookRunColumns = `id, runbook_id, status, version, started_by, started_at, updated_at, finished_at, state`

// query runs q, which selects runbookRunColumns and the source; before schema
// 15 it finds none.
func (r RunbookRuns) query(ctx context.Context, q string, args ...any) ([]RunbookRun, error) {
	v, err := schemaVersion(ctx, r.s.db)
	if err != nil {
		return nil, err
	}
	if v < runbookRunsSchema {
		return nil, nil
	}
	rows, err := r.s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RunbookRun
	for rows.Next() {
		var (
			run                        RunbookRun
			started, updated, finished int64
			state                      string
		)
		if err := rows.Scan(&run.ID, &run.RunbookID, &run.Status, &run.Version, &run.StartedBy,
			&started, &updated, &finished, &state, &run.Source); err != nil {
			return nil, err
		}
		run.StartedAt, run.UpdatedAt = fromMillis(started), fromMillis(updated)
		if finished != 0 {
			run.FinishedAt = fromMillis(finished)
		}
		run.State = json.RawMessage(state)
		out = append(out, run)
	}
	return out, rows.Err()
}

// CreateRunbookRun inserts a run at version 1, then deletes all but the newest
// Keep finished runs of that runbook.
type CreateRunbookRun struct {
	ID        string `json:"id"`
	RunbookID string `json:"runbook_id"`
	Status    string `json:"status"`
	StartedBy string `json:"started_by"`
	StartedAt int64  `json:"started_at"`
	Source    []byte `json:"source"`
	State     string `json:"state"`
	Keep      int    `json:"keep"`
}

// Op implements Command.
func (CreateRunbookRun) Op() string { return "create_runbook_run" }

func (CreateRunbookRun) minSchema() int64 { return runbookRunsSchema }

func (c CreateRunbookRun) apply(ctx context.Context, tx *sql.Tx) (Result, error) {
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO runbook_runs (id, runbook_id, status, version, started_by, started_at, updated_at, source, state)
		VALUES (?, ?, ?, 1, ?, ?, ?, ?, ?)`,
		c.ID, c.RunbookID, c.Status, c.StartedBy, c.StartedAt, c.StartedAt, c.Source, c.State); err != nil {
		return Result{}, err
	}
	_, err := tx.ExecContext(ctx, `
		DELETE FROM runbook_runs WHERE runbook_id = ? AND finished_at != 0 AND rowid NOT IN (
			SELECT rowid FROM runbook_runs WHERE runbook_id = ? AND finished_at != 0
			ORDER BY started_at DESC, rowid DESC LIMIT ?)`, c.RunbookID, c.RunbookID, c.Keep)
	return Result{}, err
}

// SaveRunbookRun replaces a run's status and state if it is still at Version.
// The check is made inside apply, so of two hubs saving from one version
// exactly one wins, in log order, on every node. It fails with
// ErrRunbookRunConflict or ErrNotFound.
type SaveRunbookRun struct {
	ID         string `json:"id"`
	Version    int64  `json:"version"`
	Status     string `json:"status"`
	UpdatedAt  int64  `json:"updated_at"`
	FinishedAt int64  `json:"finished_at"`
	State      string `json:"state"`
}

// Op implements Command.
func (SaveRunbookRun) Op() string { return "save_runbook_run" }

func (SaveRunbookRun) minSchema() int64 { return runbookRunsSchema }

func (c SaveRunbookRun) apply(ctx context.Context, tx *sql.Tx) (Result, error) {
	res, err := tx.ExecContext(ctx, `
		UPDATE runbook_runs SET status = ?, version = version + 1, updated_at = ?, finished_at = ?, state = ?
		WHERE id = ? AND version = ?`, c.Status, c.UpdatedAt, c.FinishedAt, c.State, c.ID, c.Version)
	if err != nil {
		return Result{}, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return Result{}, err
	}
	if n == 1 {
		return Result{}, nil
	}
	var exists bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM runbook_runs WHERE id = ?)`, c.ID).Scan(&exists); err != nil {
		return Result{}, err
	}
	if !exists {
		return Result{}, ErrNotFound
	}
	return Result{}, ErrRunbookRunConflict
}
