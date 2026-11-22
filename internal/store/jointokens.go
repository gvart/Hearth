// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
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
	return r.CreateFor(ctx, secret, expiresAt, roles, "")
}

// CreateFor is Create for a token minted for deviceID as it enrolled (#328);
// "" names none. Naming a device needs schema 34, and fails with
// ErrSchemaTooOld below it.
func (r JoinTokens) CreateFor(ctx context.Context, secret string, expiresAt time.Time, roles, deviceID string) error {
	if secret == "" {
		return errors.New("create join token: empty secret")
	}
	if roles == "" {
		return errors.New("create join token: no roles")
	}
	h := hashSecret(secret)
	if _, err := r.s.apply(ctx, CreateJoinToken{Hash: h[:], ExpiresAt: toMillis(expiresAt), Roles: roles, DeviceID: deviceID}); err != nil {
		return fmt.Errorf("create join token: %w", err)
	}
	return nil
}

// Consume atomically marks the join token as used at now and returns the
// roles it grants. It succeeds at most once per token and returns
// ErrNotFound, ErrTokenUsed or ErrTokenExpired when the token cannot be used.
func (r JoinTokens) Consume(ctx context.Context, secret string, now time.Time) (string, error) {
	t, err := r.Use(ctx, secret, "", now)
	return t.Roles, err
}

// JoinToken is what a consumed join token grants.
type JoinToken struct {
	// Roles are the cluster roles it grants, comma-separated.
	Roles string
	// DeviceID is the device it was minted for at its enrollment, or "" for
	// a token an admin created.
	DeviceID string
}

// Use is Consume by the hub nodeID, returning the device the token was
// minted for too.
func (r JoinTokens) Use(ctx context.Context, secret, nodeID string, now time.Time) (JoinToken, error) {
	h := hashSecret(secret)
	res, err := r.s.apply(ctx, ConsumeJoinToken{Hash: h[:], Now: toMillis(now), NodeID: nodeID})
	if err != nil {
		return JoinToken{}, fmt.Errorf("consume join token: %w", err)
	}
	return JoinToken{Roles: res.Roles, DeviceID: res.DeviceID}, nil
}

// PendingMinted counts the join tokens minted for enrolling devices (#328)
// that are neither spent nor expired at now: all of them, and those that
// grant master. A hub counts them as members to come, so two enrollments in
// a row cannot both take the last master or storage place. Below schema 34
// there are none.
func (r JoinTokens) PendingMinted(ctx context.Context, now time.Time) (all, masters int, err error) {
	if ok, err := atSchema(ctx, r.s.db, hubTokenSchema); err != nil || !ok {
		return 0, 0, err
	}
	roles, err := listCol[string](ctx, r.s, "join_tokens", `SELECT roles`,
		` FROM join_tokens WHERE device_id != '' AND used_at IS NULL AND expires_at > ? AND _deleted = 0`, toMillis(now))
	if err != nil {
		return 0, 0, fmt.Errorf("count minted join tokens: %w", err)
	}
	for _, rs := range roles {
		if slices.Contains(strings.Split(rs, ","), "master") {
			masters++
		}
	}
	return len(roles), masters, nil
}

// JoinedSince returns the hubs that joined with a token minted for a device
// (#328) after since, by node ID, with the roles the token granted (a join
// capped to storage only still shows master): the caps count such a hub
// until it shows in the gossip, as it may hold the CA key already. Only a
// hub with an unrevoked hub certificate counts: a refused join got none,
// and a removed hub's are revoked. Below schema 34 there are none.
func (r JoinTokens) JoinedSince(ctx context.Context, since time.Time) (map[string]string, error) {
	if ok, err := atSchema(ctx, r.s.db, hubTokenSchema); err != nil || !ok {
		return nil, err
	}
	rows, err := listCol[string](ctx, r.s, "join_tokens", `SELECT joined_node || ' ' || roles`,
		` FROM join_tokens WHERE device_id != '' AND joined_node != '' AND used_at > ? AND _deleted = 0`+
			` AND joined_node IN (SELECT node_id FROM hub_certs WHERE revoked_at IS NULL)`, toMillis(since))
	if err != nil {
		return nil, fmt.Errorf("list joined hubs: %w", err)
	}
	out := map[string]string{}
	for _, row := range rows {
		node, roles, _ := strings.Cut(row, " ")
		out[node] = roles
	}
	return out, nil
}
