// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"crypto/sha256"
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
type Tokens struct{ s *Store }

// Tokens returns the token repository.
func (s *Store) Tokens() Tokens { return Tokens{s: s} }

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
	if _, err := r.s.apply(ctx, CreateToken{Hash: h[:], Labels: l, ExpiresAt: toMillis(expiresAt)}); err != nil {
		return fmt.Errorf("create token: %w", err)
	}
	return nil
}

// Consume atomically marks the token as used at now and returns its labels.
// It succeeds at most once per token, even under concurrent calls. It returns
// ErrNotFound, ErrTokenUsed or ErrTokenExpired when the token cannot be used.
func (r Tokens) Consume(ctx context.Context, secret string, now time.Time) (map[string]string, error) {
	h := hashSecret(secret)
	res, err := r.s.apply(ctx, ConsumeToken{Hash: h[:], Now: toMillis(now)})
	if err != nil {
		return nil, fmt.Errorf("consume token: %w", err)
	}
	return res.Labels, nil
}

func hashSecret(secret string) [sha256.Size]byte {
	return sha256.Sum256([]byte(secret))
}
