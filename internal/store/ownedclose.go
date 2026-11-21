// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// OwnedClosed counts what CloseOwned closed.
type OwnedClosed struct {
	Tokens     int `json:"tokens"`
	JoinTokens int `json:"join_tokens"`
	Approvals  int `json:"approvals"`
}

// CloseOwned closes the open rows master owner owns, as when it stops being
// a master of an AP cluster: its unused enrollment and join tokens are
// spent, and its pending approvals expire, decided by by. Run it on owner
// itself, which alone may spend its tokens. A row closed meanwhile is
// skipped.
func (s *Store) CloseOwned(ctx context.Context, owner, by string, now time.Time) (OwnedClosed, error) {
	var out OwnedClosed
	if ok, err := atSchema(ctx, s.db, mastersSchema); err != nil || !ok {
		return out, err
	}
	at := toMillis(now)
	spent := func(err error) bool {
		return err == nil || errors.Is(err, ErrTokenUsed) || errors.Is(err, ErrTokenExpired) || errors.Is(err, ErrNotFound)
	}
	for _, t := range []struct {
		table string
		n     *int
		use   func(hash []byte) Command
	}{
		{"tokens", &out.Tokens, func(h []byte) Command { return ConsumeToken{Hash: h, Now: at, Master: owner} }},
		{"join_tokens", &out.JoinTokens, func(h []byte) Command { return ConsumeJoinToken{Hash: h, Now: at, Master: owner} }},
	} {
		hashes, err := listCol[[]byte](ctx, s, t.table, `SELECT hash`,
			` FROM `+t.table+` WHERE owner = ? AND used_at IS NULL AND expires_at > ? AND _deleted = 0`, owner, at)
		if err != nil {
			return out, fmt.Errorf("close %s of %s: %w", t.table, owner, err)
		}
		for _, h := range hashes {
			_, err := s.apply(ctx, t.use(h))
			if !spent(err) {
				return out, fmt.Errorf("close one of the %s of %s: %w", t.table, owner, err)
			}
			if err == nil {
				*t.n++
			}
		}
	}
	ids, err := listCol[string](ctx, s, "approvals", `SELECT id`,
		` FROM approvals WHERE owner = ? AND status = ? AND _deleted = 0`, owner, ApprovalPending)
	if err != nil {
		return out, fmt.Errorf("close approvals of %s: %w", owner, err)
	}
	for _, id := range ids {
		_, err := s.apply(ctx, DecideApproval{ID: id, Status: ApprovalExpired, By: by, At: at})
		switch {
		case err == nil:
			out.Approvals++
		case errors.Is(err, ErrApprovalClosed), errors.Is(err, ErrNotFound):
		default:
			return out, fmt.Errorf("close approval %s of %s: %w", id, owner, err)
		}
	}
	return out, nil
}

// listCol returns the one column sel selects from table's rows matching
// rest, on every member.
func listCol[T any](ctx context.Context, s *Store, table, sel, rest string, args ...any) ([]T, error) {
	rows, err := s.list(ctx, "", gather{table: table}, sel, rest, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []T
	for rows.Next() {
		var v T
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
