// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Token consumption errors. Unknown tokens yield ErrNotFound.
var (
	ErrTokenUsed    = errors.New("token already used")
	ErrTokenExpired = errors.New("token expired")
)

// Tokens is the repository for single-use enrollment tokens. Callers pass the
// token secret; only its SHA-256 hash is ever stored.
type Tokens struct{ db *sql.DB }

// Tokens returns the token repository.
func (s *Store) Tokens() Tokens { return Tokens{db: s.db} }

// Create stores a new token that is valid until expiresAt.
func (r Tokens) Create(ctx context.Context, secret string, labels map[string]string, expiresAt time.Time) error {
	if secret == "" {
		return errors.New("create token: empty secret")
	}
	l, err := marshalLabels(labels)
	if err != nil {
		return fmt.Errorf("create token: %w", err)
	}
	h := hashSecret(secret)
	if _, err := r.db.ExecContext(ctx,
		`INSERT INTO tokens (hash, labels, expires_at) VALUES (?, ?, ?)`,
		h[:], l, toMillis(expiresAt)); err != nil {
		return fmt.Errorf("create token: %w", err)
	}
	return nil
}

// Consume atomically marks the token as used at now and returns its labels.
// It succeeds at most once per token, even under concurrent calls. It returns
// ErrNotFound, ErrTokenUsed or ErrTokenExpired when the token cannot be used.
func (r Tokens) Consume(ctx context.Context, secret string, now time.Time) (map[string]string, error) {
	h := hashSecret(secret)
	nowMs := toMillis(now)
	var labels string
	err := r.db.QueryRowContext(ctx, `
		UPDATE tokens SET used_at = ?
		WHERE hash = ? AND used_at IS NULL AND expires_at > ?
		RETURNING labels`, nowMs, h[:], nowMs).Scan(&labels)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("consume token: %w", r.whyUnusable(ctx, h[:], nowMs))
	}
	if err != nil {
		return nil, fmt.Errorf("consume token: %w", err)
	}
	var out map[string]string
	if err := json.Unmarshal([]byte(labels), &out); err != nil {
		return nil, fmt.Errorf("consume token: decode labels: %w", err)
	}
	return out, nil
}

// whyUnusable explains a failed Consume. It only classifies the error; the
// atomic decision has already been made by the UPDATE.
func (r Tokens) whyUnusable(ctx context.Context, hash []byte, nowMs int64) error {
	var (
		expiresAt int64
		usedAt    sql.NullInt64
	)
	err := r.db.QueryRowContext(ctx, `SELECT expires_at, used_at FROM tokens WHERE hash = ?`, hash).
		Scan(&expiresAt, &usedAt)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return ErrNotFound
	case err != nil:
		return err
	case usedAt.Valid:
		return ErrTokenUsed
	case expiresAt <= nowMs:
		return ErrTokenExpired
	default:
		return errors.New("token not consumed") // unreachable unless the row changed in between
	}
}

func hashSecret(secret string) [sha256.Size]byte {
	return sha256.Sum256([]byte(secret))
}
