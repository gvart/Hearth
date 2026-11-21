// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// JoinTokens is the repository for single-use cluster join tokens. Callers
// pass the token secret; only its SHA-256 hash is ever stored.
type JoinTokens struct{ s *Store }

// JoinTokens returns the join token repository.
func (s *Store) JoinTokens() JoinTokens { return JoinTokens{s: s} }

// joinTokenRolesSchema is the schema version whose migration (00030) added
// the roles of a join token.
const joinTokenRolesSchema = 30

// Create stores a new join token that is valid until expiresAt and grants
// roles, the cluster roles comma-separated (cluster.RoleSet.String).
func (r JoinTokens) Create(ctx context.Context, secret string, expiresAt time.Time, roles string) error {
	if secret == "" {
		return errors.New("create join token: empty secret")
	}
	if roles == "" {
		return errors.New("create join token: no roles")
	}
	h := hashSecret(secret)
	if _, err := r.s.apply(ctx, CreateJoinToken{Hash: h[:], ExpiresAt: toMillis(expiresAt), Roles: roles}); err != nil {
		return fmt.Errorf("create join token: %w", err)
	}
	return nil
}

// Consume atomically marks the join token as used at now and returns the
// roles it grants. It succeeds at most once per token and returns
// ErrNotFound, ErrTokenUsed or ErrTokenExpired when the token cannot be used.
func (r JoinTokens) Consume(ctx context.Context, secret string, now time.Time) (string, error) {
	h := hashSecret(secret)
	res, err := r.s.apply(ctx, ConsumeJoinToken{Hash: h[:], Now: toMillis(now)})
	if err != nil {
		return "", fmt.Errorf("consume join token: %w", err)
	}
	return res.Roles, nil
}
