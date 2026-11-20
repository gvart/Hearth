// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// dashboardTokensSchema is the schema version whose migration added
// the dashboard_tokens table. Until a cluster migrates to it, no dashboard
// token can be created, and none is valid.
const dashboardTokensSchema = 23

// DashboardToken is a dashboard's read-only token, without its secret.
type DashboardToken struct {
	// ID identifies the token in policy and the audit log (token/<id>).
	ID string
	// Name is the admin's label for it, as "homepage".
	Name      string
	CreatedAt time.Time
	// ExpiresAt is zero for a token that never expires.
	ExpiresAt time.Time
	// RevokedAt is zero for a token not revoked.
	RevokedAt time.Time
}

// DashboardTokens is the repository for dashboard tokens. Callers pass the
// token's secret; only its SHA-256 hash is ever stored. They are kept apart
// from MCP tokens and panel links, so no secret of one kind is ever valid as
// another.
type DashboardTokens struct{ s *Store }

// DashboardTokens returns the dashboard token repository.
func (s *Store) DashboardTokens() DashboardTokens { return DashboardTokens{s: s} }

// requireSchema refuses a write before dashboardTokensSchema, before the proposal: a hub
// still on an older binary halts on a command it cannot decode.
func (r DashboardTokens) requireSchema(ctx context.Context) error {
	v, err := schemaVersion(ctx, r.s.db)
	if err != nil {
		return err
	}
	if v < dashboardTokensSchema {
		return fmt.Errorf("%w: it needs %d, the database is at %d; run `hearth cluster migrate` first",
			ErrSchemaTooOld, dashboardTokensSchema, v)
	}
	return nil
}

// Create stores token t by the hash of secret. Before dashboardTokensSchema it fails
// with ErrSchemaTooOld.
func (r DashboardTokens) Create(ctx context.Context, t DashboardToken, secret string) error {
	if t.ID == "" || t.Name == "" || secret == "" {
		return errors.New("create dashboard token: id, name and secret are required")
	}
	if err := r.requireSchema(ctx); err != nil {
		return fmt.Errorf("create dashboard token: %w", err)
	}
	h := hashSecret(secret)
	cmd := CreateDashboardToken{ID: t.ID, Name: t.Name, Hash: h[:], CreatedAt: toMillis(t.CreatedAt)}
	if !t.ExpiresAt.IsZero() {
		exp := toMillis(t.ExpiresAt)
		cmd.ExpiresAt = &exp
	}
	if _, err := r.s.apply(ctx, cmd); err != nil {
		return fmt.Errorf("create dashboard token %s: %w", t.ID, err)
	}
	return nil
}

// Revoke revokes token id at time at. It fails with ErrNotFound when there
// is no such token in use.
func (r DashboardTokens) Revoke(ctx context.Context, id string, at time.Time) error {
	if err := r.requireSchema(ctx); err != nil {
		return fmt.Errorf("revoke dashboard token: %w", err)
	}
	if _, err := r.s.apply(ctx, RevokeDashboardToken{ID: id, At: toMillis(at)}); err != nil {
		return fmt.Errorf("revoke dashboard token %s: %w", id, err)
	}
	return nil
}

// List returns every token, revoked and expired ones included, oldest
// first. Before dashboardTokensSchema there are none.
func (r DashboardTokens) List(ctx context.Context) ([]DashboardToken, error) {
	out, err := r.query(ctx, dashboardTokenSelect+` ORDER BY created_at, id`)
	if err != nil {
		return nil, fmt.Errorf("list dashboard tokens: %w", err)
	}
	return out, nil
}

// Check returns the token whose secret is secret, if it is usable at now.
// It fails with ErrNotFound for an unknown secret (and before dashboardTokensSchema),
// and with ErrTokenRevoked or ErrTokenExpired together with the token, so
// that a refusal can name it.
func (r DashboardTokens) Check(ctx context.Context, secret string, now time.Time) (DashboardToken, error) {
	h := hashSecret(secret)
	out, err := r.query(ctx, dashboardTokenSelect+` WHERE hash = ?`, h[:])
	if err != nil {
		return DashboardToken{}, fmt.Errorf("check dashboard token: %w", err)
	}
	if len(out) == 0 {
		return DashboardToken{}, fmt.Errorf("check dashboard token: %w", ErrNotFound)
	}
	t := out[0]
	switch {
	case !t.RevokedAt.IsZero():
		return t, fmt.Errorf("check dashboard token %s: %w", t.ID, ErrTokenRevoked)
	case !t.ExpiresAt.IsZero() && !now.Before(t.ExpiresAt):
		return t, fmt.Errorf("check dashboard token %s: %w", t.ID, ErrTokenExpired)
	}
	return t, nil
}

const dashboardTokenSelect = `SELECT id, name, created_at, expires_at, revoked_at FROM dashboard_tokens` //nolint:gosec // a query

// query runs q, a dashboardTokenSelect query; before dashboardTokensSchema it finds none.
func (r DashboardTokens) query(ctx context.Context, q string, args ...any) ([]DashboardToken, error) {
	v, err := schemaVersion(ctx, r.s.db)
	if err != nil || v < dashboardTokensSchema {
		return nil, err
	}
	rows, err := r.s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DashboardToken
	for rows.Next() {
		var (
			t                DashboardToken
			created          int64
			expires, revoked sql.NullInt64
		)
		if err := rows.Scan(&t.ID, &t.Name, &created, &expires, &revoked); err != nil {
			return nil, err
		}
		t.CreatedAt = fromMillis(created)
		if expires.Valid {
			t.ExpiresAt = fromMillis(expires.Int64)
		}
		if revoked.Valid {
			t.RevokedAt = fromMillis(revoked.Int64)
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// CreateDashboardToken inserts a dashboard token by its hash.
type CreateDashboardToken struct {
	Stamp
	ID        string `json:"id"`
	Name      string `json:"name"`
	Hash      []byte `json:"hash"`
	CreatedAt int64  `json:"created_at"`
	// ExpiresAt is nil for a token that never expires.
	ExpiresAt *int64 `json:"expires_at,omitempty"`
}

// Op implements Command.
func (CreateDashboardToken) Op() string { return "create_dashboard_token" }

func (CreateDashboardToken) minSchema() int64 { return dashboardTokensSchema }

func (c CreateDashboardToken) apply(ctx context.Context, w *writer) (Result, error) {
	return Result{}, w.insert(ctx, "dashboard_tokens", row{
		"id": c.ID, "name": c.Name, "hash": c.Hash, "created_at": c.CreatedAt,
		"expires_at": optInt(c.ExpiresAt), "revoked_at": nil,
	})
}

// RevokeDashboardToken revokes a dashboard token in use; ErrNotFound if
// there is none by that ID.
type RevokeDashboardToken struct {
	Stamp
	ID string `json:"id"`
	At int64  `json:"at"`
}

// Op implements Command.
func (RevokeDashboardToken) Op() string { return "revoke_dashboard_token" }

func (RevokeDashboardToken) minSchema() int64 { return dashboardTokensSchema }

func (c RevokeDashboardToken) apply(ctx context.Context, w *writer) (Result, error) {
	return revokeOne(ctx, w, "dashboard_tokens", `id = ?`, c.At, c.ID)
}
