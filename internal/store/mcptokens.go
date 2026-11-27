// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// mcpTokensSchema is the schema version whose migration (00011) added the
// mcp_tokens table. Until a cluster migrates to it, no MCP token can be
// created, and none is valid.
const mcpTokensSchema = 11

// ErrTokenRevoked is returned for an MCP token that has been revoked.
var ErrTokenRevoked = errors.New("token revoked")

// MCPToken is an MCP client's bearer token, without its secret.
type MCPToken struct {
	// Name identifies the client in policy and the audit log.
	Name string
	// Scope is the highest policy class the token may request.
	Scope     string
	CreatedAt time.Time
	// RevokedAt is zero for a token in use.
	RevokedAt time.Time
}

// MCPTokens is the repository for MCP client tokens. Callers pass the token
// secret; only its SHA-256 hash is ever stored.
type MCPTokens struct{ s *Store }

// MCPTokens returns the MCP token repository.
func (s *Store) MCPTokens() MCPTokens { return MCPTokens{s: s} }

// Create stores a token named name with scope. A name already taken, even
// by a revoked token, is a constraint violation. Before schema 11 it fails
// with ErrSchemaTooOld.
func (r MCPTokens) Create(ctx context.Context, name, secret, scope string, now time.Time) error {
	if name == "" || secret == "" || scope == "" {
		return errors.New("create mcp token: name, secret and scope are required")
	}
	h := hashSecret(secret)
	if _, err := r.s.apply(ctx, CreateMCPToken{Name: name, Hash: h[:], Scope: scope, CreatedAt: toMillis(now)}); err != nil {
		return fmt.Errorf("create mcp token %s: %w", name, err)
	}
	return nil
}

// Check returns the token whose secret is secret, ErrNotFound for none and
// ErrTokenRevoked for a revoked one.
func (r MCPTokens) Check(ctx context.Context, secret string) (MCPToken, error) {
	h := hashSecret(secret)
	out, err := r.query(ctx, gather{}, ` WHERE hash = ?`, h[:])
	if err != nil {
		return MCPToken{}, fmt.Errorf("check mcp token: %w", err)
	}
	if len(out) == 0 {
		return MCPToken{}, fmt.Errorf("check mcp token: %w", ErrNotFound)
	}
	if !out[0].RevokedAt.IsZero() {
		return MCPToken{}, fmt.Errorf("check mcp token %s: %w", out[0].Name, ErrTokenRevoked)
	}
	return out[0], nil
}

// List returns every token, revoked ones included, by name.
func (r MCPTokens) List(ctx context.Context) ([]MCPToken, error) {
	out, err := r.query(ctx, gather{order: byText(0)}, ` ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("list mcp tokens: %w", err)
	}
	return out, nil
}

// Revoke revokes the token named name at time at. It fails with ErrNotFound
// when there is no such token in use.
func (r MCPTokens) Revoke(ctx context.Context, name string, at time.Time) error {
	if _, err := r.s.apply(ctx, RevokeMCPToken{Name: name, At: toMillis(at)}); err != nil {
		return fmt.Errorf("revoke mcp token %s: %w", name, err)
	}
	return nil
}

const mcpTokenColumns = `SELECT name, scope, created_at, revoked_at` //nolint:gosec // G101: column names, no credential

// query selects mcpTokenColumns of the tokens matching rest (WHERE and
// ORDER BY clauses), on every member merged by g; before schema 11 it
// finds none.
func (r MCPTokens) query(ctx context.Context, g gather, rest string, args ...any) ([]MCPToken, error) {
	v, err := schemaVersion(ctx, r.s.db)
	if err != nil {
		return nil, err
	}
	if v < mcpTokensSchema {
		return nil, nil
	}
	g.table = "mcp_tokens"
	rows, err := r.s.list(ctx, "", g, mcpTokenColumns, ` FROM mcp_tokens`+rest, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []MCPToken
	for rows.Next() {
		var (
			t       MCPToken
			created int64
			revoked sql.NullInt64
		)
		if err := rows.Scan(&t.Name, &t.Scope, &created, &revoked); err != nil {
			return nil, err
		}
		t.CreatedAt = fromMillis(created)
		if revoked.Valid {
			t.RevokedAt = fromMillis(revoked.Int64)
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// CreateMCPToken inserts an MCP token by its hash.
type CreateMCPToken struct {
	Stamp
	Name      string `json:"name"`
	Hash      []byte `json:"hash"`
	Scope     string `json:"scope"`
	CreatedAt int64  `json:"created_at"`
}

// Op implements Command.
func (CreateMCPToken) Op() string { return "create_mcp_token" }

func (CreateMCPToken) minSchema() int64 { return mcpTokensSchema }

func (c CreateMCPToken) apply(ctx context.Context, w *writer) (Result, error) {
	return Result{}, w.insert(ctx, "mcp_tokens", row{
		"name": c.Name, "hash": c.Hash, "scope": c.Scope, "created_at": c.CreatedAt, "revoked_at": nil,
	})
}

// RevokeMCPToken revokes an MCP token in use; ErrNotFound if there is none
// by that name.
type RevokeMCPToken struct {
	Stamp
	Name string `json:"name"`
	At   int64  `json:"at"`
}

// Op implements Command.
func (RevokeMCPToken) Op() string { return "revoke_mcp_token" }

func (RevokeMCPToken) minSchema() int64 { return mcpTokensSchema }

func (c RevokeMCPToken) apply(ctx context.Context, w *writer) (Result, error) {
	return revokeOrStub(ctx, w, "mcp_tokens", `name = ?`, c.At, row{
		"name": c.Name, "scope": "read", "created_at": c.At,
	}, c.Name)
}
