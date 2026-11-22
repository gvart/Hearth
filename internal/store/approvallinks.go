// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// approvalLinksSchema is the schema version whose migration (00010) added
// the approval_links table.
const approvalLinksSchema = 10

// ApprovalLinks is the repository for approval links: single-use secrets
// that decide one pending approval. Callers pass the secret; only its
// SHA-256 hash is ever stored.
type ApprovalLinks struct{ s *Store }

// ApprovalLinks returns the approval links repository.
func (s *Store) ApprovalLinks() ApprovalLinks { return ApprovalLinks{s: s} }

// Create stores a link for approval approvalID, valid until expiresAt.
// Before schema 10 it fails with ErrSchemaTooOld.
func (r ApprovalLinks) Create(ctx context.Context, secret, approvalID string, expiresAt time.Time) error {
	if secret == "" || approvalID == "" {
		return errors.New("create approval link: secret and approval id are required")
	}
	h := hashSecret(secret)
	if _, err := r.s.apply(ctx, CreateApprovalLink{
		Hash: h[:], ApprovalID: approvalID, ExpiresAt: toMillis(expiresAt),
	}); err != nil {
		return fmt.Errorf("create approval link: %w", err)
	}
	return nil
}

// Peek returns the approval id of a link that is still usable at now,
// without using it. It fails with ErrNotFound, ErrTokenUsed or
// ErrTokenExpired.
func (r ApprovalLinks) Peek(ctx context.Context, secret string, now time.Time) (string, error) {
	v, err := schemaVersion(ctx, r.s.db)
	if err != nil {
		return "", fmt.Errorf("peek approval link: %w", err)
	}
	if v < approvalLinksSchema {
		return "", fmt.Errorf("peek approval link: %w", ErrNotFound)
	}
	h := hashSecret(secret)
	var (
		id      string
		expires int64
		used    sql.NullInt64
	)
	err = r.s.queryRowLive(ctx, "approval_links", keyString(h[:]), `SELECT approval_id, expires_at, used_at`, ` FROM approval_links WHERE hash = ?`, h[:]).
		Scan(&id, &expires, &used)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return "", fmt.Errorf("peek approval link: %w", ErrNotFound)
	case err != nil:
		return "", fmt.Errorf("peek approval link: %w", err)
	case used.Valid:
		return "", fmt.Errorf("peek approval link: %w", ErrTokenUsed)
	case expires <= toMillis(now):
		return "", fmt.Errorf("peek approval link: %w", ErrTokenExpired)
	}
	return id, nil
}

// Use atomically spends the link at now and returns its approval id. It
// succeeds at most once per link, even under concurrent calls, and fails
// with ErrNotFound, ErrTokenUsed or ErrTokenExpired otherwise.
func (r ApprovalLinks) Use(ctx context.Context, secret string, now time.Time) (string, error) {
	h := hashSecret(secret)
	res, err := r.s.apply(ctx, UseApprovalLink{Hash: h[:], Now: toMillis(now)})
	if err != nil {
		return "", fmt.Errorf("use approval link: %w", err)
	}
	return res.ApprovalID, nil
}

// CreateApprovalLink stores an approval link by its SHA-256 hash.
type CreateApprovalLink struct {
	Stamp
	Hash       []byte `json:"hash"`
	ApprovalID string `json:"approval_id"`
	ExpiresAt  int64  `json:"expires_at"`
	// Owner is the master that owns the link in an AP cluster (OwnedBy).
	Owner string `json:"owner,omitempty"`
}

// Op implements Command.
func (CreateApprovalLink) Op() string { return "create_approval_link" }

func (c CreateApprovalLink) minSchema() int64 { return ownedSchema(c.Owner, approvalLinksSchema) }

func (c CreateApprovalLink) apply(ctx context.Context, w *writer) (Result, error) {
	return Result{}, w.insert(ctx, "approval_links", withOwner(row{
		"hash": c.Hash, "approval_id": c.ApprovalID, "expires_at": c.ExpiresAt, "used_at": nil,
	}, c.Owner))
}

// UseApprovalLink spends an approval link. Result: ApprovalID.
type UseApprovalLink struct {
	Stamp
	Hash []byte `json:"hash"`
	Now  int64  `json:"now"`
	// Master is the master using it in an AP cluster (OwnedBy).
	Master string `json:"master,omitempty"`
}

// Op implements Command.
func (UseApprovalLink) Op() string { return "use_approval_link" }

func (c UseApprovalLink) minSchema() int64 { return ownedSchema(c.Master, approvalLinksSchema) }

func (c UseApprovalLink) apply(ctx context.Context, w *writer) (Result, error) {
	r, err := consume(ctx, w, "approval_links", "approval link", c.Hash, c.Now, c.Master, nil)
	if err != nil {
		return Result{}, err
	}
	return Result{ApprovalID: r.str("approval_id")}, nil
}
