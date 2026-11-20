// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// ErrSessionExpired is returned for a session that exists but has expired.
var ErrSessionExpired = errors.New("session expired")

// Admin is the repository for the single admin credential and its web
// sessions. Callers pass session secrets; only their SHA-256 hashes are stored.
type Admin struct{ s *Store }

// Admin returns the admin repository.
func (s *Store) Admin() Admin { return Admin{s: s} }

// PasswordHash returns the stored admin password hash, or ErrNotFound if no
// password has been set.
func (r Admin) PasswordHash(ctx context.Context) (string, error) {
	var h string
	err := r.s.db.QueryRowContext(ctx, `SELECT password_hash FROM admin WHERE id = 1`).Scan(&h)
	if errors.Is(err, sql.ErrNoRows) {
		return "", fmt.Errorf("get admin password: %w", ErrNotFound)
	}
	if err != nil {
		return "", fmt.Errorf("get admin password: %w", err)
	}
	return h, nil
}

// SetPasswordHash sets or replaces the admin password hash and ends every
// session, so a reset locks out whoever held the old password.
func (r Admin) SetPasswordHash(ctx context.Context, hash string) error {
	if hash == "" {
		return errors.New("set admin password: empty hash")
	}
	if _, err := r.s.apply(ctx, SetPasswordHash{Hash: hash}); err != nil {
		return fmt.Errorf("set admin password: %w", err)
	}
	return nil
}

// CreateSession stores a session valid until expiresAt and prunes expired ones.
func (r Admin) CreateSession(ctx context.Context, secret string, now, expiresAt time.Time) error {
	if secret == "" {
		return errors.New("create session: empty secret")
	}
	h := hashSecret(secret)
	if _, err := r.s.apply(ctx, CreateSession{Hash: h[:], Now: toMillis(now), ExpiresAt: toMillis(expiresAt)}); err != nil {
		return fmt.Errorf("create session: %w", err)
	}
	return nil
}

// CheckSession returns the session's expiry if it is valid at now, and
// ErrNotFound or ErrSessionExpired otherwise.
func (r Admin) CheckSession(ctx context.Context, secret string, now time.Time) (time.Time, error) {
	h := hashSecret(secret)
	versioned, err := isVersioned(ctx, r.s.db)
	if err != nil {
		return time.Time{}, fmt.Errorf("check session: %w", err)
	}
	var expiresAt int64
	err = r.s.queryRowKey(ctx, keyString(h[:]), `SELECT expires_at FROM sessions WHERE hash = ?`+liveOnly(versioned), h[:]).Scan(&expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return time.Time{}, fmt.Errorf("check session: %w", ErrNotFound)
	}
	if err != nil {
		return time.Time{}, fmt.Errorf("check session: %w", err)
	}
	if expiresAt <= toMillis(now) {
		return time.Time{}, fmt.Errorf("check session: %w", ErrSessionExpired)
	}
	return fromMillis(expiresAt), nil
}

// DeleteSession ends a session. Deleting an unknown session is not an error.
func (r Admin) DeleteSession(ctx context.Context, secret string) error {
	h := hashSecret(secret)
	if _, err := r.s.apply(ctx, DeleteSession{Hash: h[:]}); err != nil {
		return fmt.Errorf("delete session: %w", err)
	}
	return nil
}
