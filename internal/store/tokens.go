// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"cmp"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
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

// hubTokenSchema is the schema version whose migration (00034) added the hub
// roles of an enrollment token and the device of a join token (#328).
const hubTokenSchema = 34

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
	// HubRoles are the cluster roles the device may be offered,
	// comma-separated, or "" for none: the admin let it become a hub.
	HubRoles string
}

// Create stores a new token that is valid until expiresAt.
func (r Tokens) Create(ctx context.Context, secret string, labels map[string]string, expiresAt time.Time) error {
	return r.CreateNamed(ctx, secret, "", labels, expiresAt)
}

// CreateNamed stores a new token that is valid until expiresAt and names the
// device that enrolls with it ("" leaves it its hostname). A named token
// needs schema 32, and fails with ErrSchemaTooOld below it.
func (r Tokens) CreateNamed(ctx context.Context, secret, name string, labels map[string]string, expiresAt time.Time) error {
	return r.CreateHub(ctx, secret, name, "", labels, expiresAt)
}

// CreateHub is CreateNamed for a token that also lets the device become a
// hub with at most hubRoles (comma-separated; "" for none). A token with hub
// roles needs schema 34, and fails with ErrSchemaTooOld below it.
func (r Tokens) CreateHub(ctx context.Context, secret, name, hubRoles string, labels map[string]string, expiresAt time.Time) error {
	if secret == "" {
		return errors.New("create token: empty secret")
	}
	l, err := marshalLabels(labels)
	if err != nil {
		return fmt.Errorf("create token: %w", err)
	}
	h := hashSecret(secret)
	if _, err := r.s.apply(ctx, CreateToken{Hash: h[:], Labels: l, Name: name, HubRoles: hubRoles, ExpiresAt: toMillis(expiresAt)}); err != nil {
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
	return EnrollToken{Labels: res.Labels, Name: res.Name, HubRoles: res.HubRoles}, nil
}

// TokenIDLen is the length of an enrollment token's ID: the hex of the
// first 6 bytes of its hash, the handle the audit log names it by.
const TokenIDLen = 12

// PendingToken is an enrollment token not used yet, without its secret.
type PendingToken struct {
	// ID is the hex of the first 6 bytes of the token's hash: the actor ID
	// of the device.enroll entry that redeems it.
	ID     string
	Name   string
	Labels map[string]string
	// HubEligible is set when the token lets a capable device become a hub.
	HubEligible bool
	ExpiresAt   time.Time
}

// tokenRow is an enrollment token as the tokens table holds it.
type tokenRow struct {
	PendingToken
	hash []byte
	used bool
}

// ListUnused returns the enrollment tokens neither used nor expired at now,
// the soonest to expire first.
func (r Tokens) ListUnused(ctx context.Context, now time.Time) ([]PendingToken, error) {
	rows, err := r.query(ctx, ` WHERE used_at IS NULL AND expires_at > ? AND _deleted = 0`, toMillis(now))
	if err != nil {
		return nil, fmt.Errorf("list enrollment tokens: %w", err)
	}
	slices.SortFunc(rows, func(a, b tokenRow) int {
		return cmp.Or(a.ExpiresAt.Compare(b.ExpiresAt), strings.Compare(a.ID, b.ID))
	})
	out := make([]PendingToken, len(rows))
	for i, t := range rows {
		out[i] = t.PendingToken
	}
	return out, nil
}

// Unused returns the unused enrollment token whose ID is id. It fails with
// ErrNotFound for an unknown or malformed ID, and with ErrTokenUsed or
// ErrTokenExpired for a token that cannot be used any more.
func (r Tokens) Unused(ctx context.Context, id string, now time.Time) (PendingToken, error) {
	t, err := r.find(ctx, id, now)
	return t.PendingToken, err
}

// Revoke spends the unused enrollment token whose ID is id at now, as a
// master spends its tokens when it stops being one (CloseOwned): no device
// can enroll with it, and an enrollment and a revocation at once cannot
// both win. It fails as Unused does, and with a *NotOwnerError when another
// master of an AP cluster owns the token.
func (r Tokens) Revoke(ctx context.Context, id string, now time.Time) error {
	t, err := r.find(ctx, id, now)
	if err == nil {
		_, err = r.s.apply(ctx, ConsumeToken{Hash: t.hash, Now: toMillis(now)})
	}
	if err != nil {
		return fmt.Errorf("revoke enrollment token %s: %w", id, err)
	}
	return nil
}

// find returns the token whose ID is id, with ErrTokenUsed or
// ErrTokenExpired when it cannot be used at now.
func (r Tokens) find(ctx context.Context, id string, now time.Time) (tokenRow, error) {
	id = strings.ToLower(id)
	prefix, err := hex.DecodeString(id)
	if err != nil || len(id) != TokenIDLen {
		return tokenRow{}, ErrNotFound
	}
	rows, err := r.query(ctx, ` WHERE substr(hash, 1, ?) = ? AND _deleted = 0`, len(prefix), prefix)
	switch {
	case err != nil:
		return tokenRow{}, fmt.Errorf("find enrollment token %s: %w", id, err)
	case len(rows) == 0:
		return tokenRow{}, ErrNotFound
	case len(rows) > 1:
		return tokenRow{}, fmt.Errorf("enrollment token ID %s names %d tokens", id, len(rows))
	case rows[0].used:
		return rows[0], ErrTokenUsed
	case !rows[0].ExpiresAt.After(now):
		return rows[0], ErrTokenExpired
	}
	return rows[0], nil
}

// query selects the enrollment tokens matching where, on every member. The
// device name needs schema 32 and the hub roles schema 34; below them,
// tokens have none.
func (r Tokens) query(ctx context.Context, where string, args ...any) ([]tokenRow, error) {
	v, err := schemaVersion(ctx, r.s.db)
	if err != nil {
		return nil, err
	}
	cols := `SELECT hash, labels, expires_at, used_at, ''`
	if v >= tokenNameSchema {
		cols = `SELECT hash, labels, expires_at, used_at, name`
	}
	if v >= hubTokenSchema {
		cols += `, hub_roles`
	} else {
		cols += `, ''`
	}
	rows, err := r.s.list(ctx, "", gather{table: "tokens"}, cols, ` FROM tokens`+where, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []tokenRow
	for rows.Next() {
		var (
			t        tokenRow
			labels   string
			expires  int64
			used     sql.NullInt64
			hubRoles string
		)
		if err := rows.Scan(&t.hash, &labels, &expires, &used, &t.Name, &hubRoles); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(labels), &t.Labels); err != nil {
			return nil, fmt.Errorf("decode labels: %w", err)
		}
		t.ID = hex.EncodeToString(t.hash[:min(len(t.hash), TokenIDLen/2)])
		t.ExpiresAt, t.used, t.HubEligible = fromMillis(expires), used.Valid, hubRoles != ""
		out = append(out, t)
	}
	return out, rows.Err()
}

func hashSecret(secret string) [sha256.Size]byte {
	return sha256.Sum256([]byte(secret))
}
