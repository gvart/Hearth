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

// approvalsSchema is the schema version whose migration (00009) added the
// approvals table. Until a cluster migrates to it, nothing can be held for
// approval, so policy denies an action that needs one.
const approvalsSchema = 9

// approvalPlanSchema is the schema version whose migration (00017) cleared
// the plan of the approvals decided before it. DecideApproval clears the plan
// at any schema, so no command is gated on it.
const approvalPlanSchema = 17

// planKey is the key of a held request's plan in an approval's detail; it is
// policy.DetailPlan, which the store cannot import.
const planKey = "plan"

// Approval statuses.
const (
	ApprovalPending  = "pending"
	ApprovalApproved = "approved"
	ApprovalDenied   = "denied"
	ApprovalExpired  = "expired"
)

// ErrApprovalClosed is returned when deciding an approval that is no longer
// pending: already decided, or expired.
var ErrApprovalClosed = errors.New("approval is no longer pending")

// Approval is an action held by policy until an operator decides on it.
type Approval struct {
	ID        string
	CreatedAt time.Time
	ExpiresAt time.Time
	ActorKind string
	ActorID   string
	Action    string
	Class     string
	Target    string
	// Detail is the request's audit detail, as JSON; nil is stored as {}.
	Detail json.RawMessage
	Status string
	// DecidedBy is who approved or denied it, as kind/id, or "timeout".
	DecidedBy string
	DecidedAt time.Time
}

// Approvals is the repository for pending approvals.
type Approvals struct{ s *Store }

// Approvals returns the pending approvals repository.
func (s *Store) Approvals() Approvals { return Approvals{s: s} }

// Create stores a new pending approval. Before schema 9 it fails with
// ErrSchemaTooOld.
func (r Approvals) Create(ctx context.Context, a Approval) error {
	if a.ID == "" || a.ActorKind == "" || a.ActorID == "" || a.Action == "" || a.Class == "" {
		return errors.New("create approval: id, actor, action and class are required")
	}
	detail := []byte(a.Detail)
	if len(detail) == 0 {
		detail = []byte("{}")
	}
	if !json.Valid(detail) {
		return errors.New("create approval: detail is not valid JSON")
	}
	if _, err := r.s.apply(ctx, CreateApproval{
		ID: a.ID, CreatedAt: toMillis(a.CreatedAt), ExpiresAt: toMillis(a.ExpiresAt),
		ActorKind: a.ActorKind, ActorID: a.ActorID, Action: a.Action, Class: a.Class,
		Target: a.Target, Detail: string(detail),
	}); err != nil {
		return fmt.Errorf("create approval %s: %w", a.ID, err)
	}
	return nil
}

// Decide closes a pending approval with status (approved, denied or
// expired) at time at, by decider. It fails with ErrNotFound for an unknown
// id, and with ErrApprovalClosed when the approval is no longer pending or,
// for an approve or deny, has expired by at.
func (r Approvals) Decide(ctx context.Context, id, status, decider string, at time.Time) error {
	switch status {
	case ApprovalApproved, ApprovalDenied, ApprovalExpired:
	default:
		return fmt.Errorf("decide approval %s: invalid status %q", id, status)
	}
	if decider == "" {
		return fmt.Errorf("decide approval %s: decider is required", id)
	}
	if _, err := r.s.apply(ctx, DecideApproval{ID: id, Status: status, By: decider, At: toMillis(at)}); err != nil {
		return fmt.Errorf("decide approval %s: %w", id, err)
	}
	return nil
}

// Get returns one approval, or ErrNotFound.
func (r Approvals) Get(ctx context.Context, id string) (Approval, error) {
	out, err := r.query(ctx, approvalSelect+` WHERE id = ?`, id)
	if err != nil {
		return Approval{}, fmt.Errorf("get approval %s: %w", id, err)
	}
	if len(out) == 0 {
		return Approval{}, fmt.Errorf("get approval %s: %w", id, ErrNotFound)
	}
	return out[0], nil
}

// List returns up to limit approvals, newest first: those with status, or
// all of them when status is empty. Before schema 9 there are none.
func (r Approvals) List(ctx context.Context, status string, limit int) ([]Approval, error) {
	if limit <= 0 {
		return nil, errors.New("list approvals: limit must be positive")
	}
	out, err := r.query(ctx, approvalSelect+` WHERE ? = '' OR status = ? ORDER BY created_at DESC, rowid DESC LIMIT ?`,
		status, status, limit)
	if err != nil {
		return nil, fmt.Errorf("list approvals: %w", err)
	}
	return out, nil
}

const approvalSelect = `SELECT id, created_at, expires_at, actor_kind, actor_id, action, class, target,
	detail, status, decided_by, decided_at FROM approvals`

// query runs q, an approvalSelect query; before schema 9 it finds none.
func (r Approvals) query(ctx context.Context, q string, args ...any) ([]Approval, error) {
	v, err := schemaVersion(ctx, r.s.db)
	if err != nil {
		return nil, err
	}
	if v < approvalsSchema {
		return nil, nil
	}
	rows, err := r.s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Approval
	for rows.Next() {
		var (
			a                Approval
			created, expires int64
			detail           string
			decided          sql.NullInt64
		)
		if err := rows.Scan(&a.ID, &created, &expires, &a.ActorKind, &a.ActorID, &a.Action, &a.Class,
			&a.Target, &detail, &a.Status, &a.DecidedBy, &decided); err != nil {
			return nil, err
		}
		a.CreatedAt, a.ExpiresAt = fromMillis(created), fromMillis(expires)
		a.Detail = json.RawMessage(detail)
		if decided.Valid {
			a.DecidedAt = fromMillis(decided.Int64)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// CreateApproval inserts a pending approval.
type CreateApproval struct {
	ID        string `json:"id"`
	CreatedAt int64  `json:"created_at"`
	ExpiresAt int64  `json:"expires_at"`
	ActorKind string `json:"actor_kind"`
	ActorID   string `json:"actor_id"`
	Action    string `json:"action"`
	Class     string `json:"class"`
	Target    string `json:"target"`
	Detail    string `json:"detail"`
}

// Op implements Command.
func (CreateApproval) Op() string { return "create_approval" }

func (CreateApproval) minSchema() int64 { return approvalsSchema }

func (c CreateApproval) apply(ctx context.Context, tx *sql.Tx) (Result, error) {
	_, err := tx.ExecContext(ctx, `
		INSERT INTO approvals (id, created_at, expires_at, actor_kind, actor_id, action, class, target, detail)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		c.ID, c.CreatedAt, c.ExpiresAt, c.ActorKind, c.ActorID, c.Action, c.Class, c.Target, c.Detail)
	return Result{}, err
}

// DecideApproval closes a pending approval. Approving or denying one that
// expired by At fails with ErrApprovalClosed, as does deciding one that is
// not pending; an unknown id fails with ErrNotFound.
type DecideApproval struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	By     string `json:"by"`
	At     int64  `json:"at"`
}

// Op implements Command.
func (DecideApproval) Op() string { return "decide_approval" }

func (DecideApproval) minSchema() int64 { return approvalsSchema }

func (c DecideApproval) apply(ctx context.Context, tx *sql.Tx) (Result, error) {
	var (
		status  string
		expires int64
	)
	err := tx.QueryRowContext(ctx, `SELECT status, expires_at FROM approvals WHERE id = ?`, c.ID).Scan(&status, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return Result{}, ErrNotFound
	}
	if err != nil {
		return Result{}, err
	}
	if status != ApprovalPending {
		return Result{}, fmt.Errorf("%w: it is %s", ErrApprovalClosed, status)
	}
	if c.Status != ApprovalExpired && c.At >= expires {
		return Result{}, fmt.Errorf("%w: it has expired", ErrApprovalClosed)
	}
	// The plan can hold secrets from command arguments and a decided approval
	// has no use for it, so it goes in the write that records the decision.
	_, err = tx.ExecContext(ctx, `UPDATE approvals SET status = ?, decided_by = ?, decided_at = ?,
		detail = json_remove(detail, '$.`+planKey+`') WHERE id = ?`,
		c.Status, c.By, c.At, c.ID)
	return Result{}, err
}
