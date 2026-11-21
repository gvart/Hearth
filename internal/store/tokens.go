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

// tokenNameSchema is the schema version whose migration (00032) added the
// device name of an enrollment token.
const tokenNameSchema = 32

// Tokens is the repository for single-use enrollment tokens. Callers pass the
// token secret; only its SHA-256 hash is ever stored.
type Tokens struct{ s *Store }

// Tokens returns the token repository.
func (s *Store) Tokens() Tokens { return Tokens{s: s} }

// EnrollToken is what a consumed enrollment token gives the device that
// enrolls with it.
type EnrollToken struct {
	Labels map[string]string
	// Name is the device name, or "" for the agent's hostname.
	Name string
}

// Create stores a new token that is valid until expiresAt.
func (r Tokens) Create(ctx context.Context, secret string, labels map[string]string, expiresAt time.Time) error {
	return r.CreateNamed(ctx, secret, "", labels, expiresAt)
}

// CreateNamed stores a new token that is valid until expiresAt and names the
// device that enrolls with it ("" leaves it its hostname). A named token
// needs schema 32, and fails with ErrSchemaTooOld below it.
func (r Tokens) CreateNamed(ctx context.Context, secret, name string, labels map[string]string, expiresAt time.Time) error {
	if secret == "" {
		return errors.New("create token: empty secret")
	}
	l, err := marshalLabels(labels)
	if err != nil {
		return fmt.Errorf("create token: %w", err)
	}
	h := hashSecret(secret)
	if _, err := r.s.apply(ctx, CreateToken{Hash: h[:], Labels: l, Name: name, ExpiresAt: toMillis(expiresAt)}); err != nil {
		return fmt.Errorf("create token: %w", err)
	}
	return nil
}

// Consume atomically marks the token as used at now and returns its labels
// and device name. It succeeds at most once per token, even under concurrent
// calls. It returns ErrNotFound, ErrTokenUsed or ErrTokenExpired when the
// token cannot be used.
func (r Tokens) Consume(ctx context.Context, secret string, now time.Time) (EnrollToken, error) {
	h := hashSecret(secret)
	res, err := r.s.apply(ctx, ConsumeToken{Hash: h[:], Now: toMillis(now)})
	if err != nil {
		return EnrollToken{}, fmt.Errorf("consume token: %w", err)
	}
	return EnrollToken{Labels: res.Labels, Name: res.Name}, nil
}

func hashSecret(secret string) [sha256.Size]byte {
	return sha256.Sum256([]byte(secret))
}
