// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"crypto/rand"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestDashboardTokensLifecycle(t *testing.T) {
	s := openTest(t)
	ctx := t.Context()
	tok := s.DashboardTokens()
	now := time.UnixMilli(1_700_000_000_000).UTC()
	live, expiring, revoked := rand.Text(), rand.Text(), rand.Text()
	for _, c := range []struct {
		t      DashboardToken
		secret string
	}{
		{DashboardToken{ID: "live", Name: "homepage", CreatedAt: now}, live},
		{DashboardToken{ID: "expiring", Name: "wall", CreatedAt: now, ExpiresAt: now.Add(time.Hour)}, expiring},
		{DashboardToken{ID: "revoked", Name: "old", CreatedAt: now}, revoked},
	} {
		if err := tok.Create(ctx, c.t, c.secret); err != nil {
			t.Fatal(err)
		}
	}
	if err := tok.Create(ctx, DashboardToken{ID: "live", Name: "again", CreatedAt: now}, rand.Text()); err == nil || !IsDomainError(err) {
		t.Errorf("Create(duplicate id) = %v, want a constraint violation", err)
	}
	if err := tok.Create(ctx, DashboardToken{ID: "x", CreatedAt: now}, rand.Text()); err == nil {
		t.Error("Create without a name succeeded")
	}
	if err := tok.Revoke(ctx, "revoked", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"revoked", "nobody"} {
		if err := tok.Revoke(ctx, id, now); !errors.Is(err, ErrNotFound) {
			t.Errorf("Revoke(%s) = %v, want ErrNotFound", id, err)
		}
	}

	got, err := tok.Check(ctx, live, now)
	if err != nil || got.ID != "live" || got.Name != "homepage" || !got.CreatedAt.Equal(now) {
		t.Fatalf("Check(live) = %+v, %v", got, err)
	}
	if got, err := tok.Check(ctx, expiring, now.Add(time.Hour)); !errors.Is(err, ErrTokenExpired) || got.ID != "expiring" {
		t.Errorf("Check(expired) = %+v, %v; want ErrTokenExpired naming the token", got, err)
	}
	if got, err := tok.Check(ctx, revoked, now); !errors.Is(err, ErrTokenRevoked) || got.ID != "revoked" {
		t.Errorf("Check(revoked) = %+v, %v; want ErrTokenRevoked naming the token", got, err)
	}
	if _, err := tok.Check(ctx, rand.Text(), now); !errors.Is(err, ErrNotFound) {
		t.Errorf("Check(unknown) = %v, want ErrNotFound", err)
	}
	list, err := tok.List(ctx)
	if err != nil || len(list) != 3 || !list[2].RevokedAt.Equal(now.Add(time.Minute)) || !list[0].ExpiresAt.Equal(now.Add(time.Hour)) {
		t.Errorf("List = %+v, %v", list, err)
	}

	// Only the hash is stored, and no other kind of credential is a
	// dashboard token: an MCP token's secret is not one, nor the reverse.
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM dashboard_tokens WHERE hash = ?`, []byte(live)).Scan(&n); err != nil || n != 0 {
		t.Errorf("the secret is stored in the clear (%d, %v)", n, err)
	}
	mcp := rand.Text()
	if err := s.MCPTokens().Create(ctx, "claude", mcp, "read", now); err != nil {
		t.Fatal(err)
	}
	if _, err := tok.Check(ctx, mcp, now); !errors.Is(err, ErrNotFound) {
		t.Errorf("Check(mcp token) = %v, want ErrNotFound", err)
	}
	if _, err := s.MCPTokens().Check(ctx, live); !errors.Is(err, ErrNotFound) {
		t.Errorf("MCP Check(dashboard token) = %v, want ErrNotFound", err)
	}
}

// A newer binary on a cluster database before the schema has no dashboard
// tokens: none is valid, and nothing is proposed.
func TestDashboardTokensBeforeTheirSchema(t *testing.T) {
	ctx := t.Context()
	path := filepath.Join(t.TempDir(), "hearth.db")
	s, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	p, err := s.newMigrator()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.DownTo(ctx, dashboardTokensSchema-1); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	var proposed []string
	s, err = Open(ctx, path, WithoutUpgrade(), WithApplier(func(s *Store) Applier {
		return ApplierFunc(func(ctx context.Context, cmd Command) (Result, error) {
			proposed = append(proposed, cmd.Op())
			return s.ApplyLocal(ctx, cmd)
		})
	}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })

	tok := s.DashboardTokens()
	if got, err := tok.List(ctx); err != nil || len(got) != 0 {
		t.Errorf("List before the schema = %v, %v; want none", got, err)
	}
	if _, err := tok.Check(ctx, "x", time.Now()); !errors.Is(err, ErrNotFound) {
		t.Errorf("Check before the schema = %v, want ErrNotFound", err)
	}
	if err := tok.Create(ctx, DashboardToken{ID: "d", Name: "n"}, "x"); !errors.Is(err, ErrSchemaTooOld) {
		t.Errorf("Create before the schema = %v, want ErrSchemaTooOld", err)
	}
	if err := tok.Revoke(ctx, "d", time.Now()); !errors.Is(err, ErrSchemaTooOld) {
		t.Errorf("Revoke before the schema = %v, want ErrSchemaTooOld", err)
	}
	if len(proposed) != 0 {
		t.Errorf("proposed %v before the schema, want nothing", proposed)
	}
	for _, cmd := range []Command{CreateDashboardToken{ID: "d", Name: "n", Hash: []byte{1}}, RevokeDashboardToken{ID: "d"}} {
		if _, err := s.ApplyLocal(ctx, cmd); !errors.Is(err, ErrSchemaTooOld) {
			t.Errorf("ApplyLocal(%s) before the schema = %v, want ErrSchemaTooOld", cmd.Op(), err)
		}
	}
}
