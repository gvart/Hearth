// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestMCPTokensLifecycle(t *testing.T) {
	s := openTest(t)
	ctx := t.Context()
	tok := s.MCPTokens()
	now := time.UnixMilli(1_700_000_000_000).UTC()
	if err := tok.Create(ctx, "claude", "secret-1", "safe", now); err != nil {
		t.Fatal(err)
	}
	got, err := tok.Check(ctx, "secret-1")
	if err != nil || got.Name != "claude" || got.Scope != "safe" || !got.CreatedAt.Equal(now) || !got.RevokedAt.IsZero() {
		t.Fatalf("Check = %+v, %v", got, err)
	}
	if _, err := tok.Check(ctx, "wrong"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Check(wrong) = %v, want ErrNotFound", err)
	}
	// A name is never reused.
	if err := tok.Create(ctx, "claude", "secret-2", "read", now); err == nil || !IsDomainError(err) {
		t.Errorf("Create(duplicate name) = %v, want a constraint violation", err)
	}
	if err := tok.Create(ctx, "", "secret-3", "read", now); err == nil {
		t.Error("Create without a name succeeded")
	}

	if err := tok.Revoke(ctx, "claude", now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := tok.Check(ctx, "secret-1"); !errors.Is(err, ErrTokenRevoked) {
		t.Errorf("Check(revoked) = %v, want ErrTokenRevoked", err)
	}
	for _, name := range []string{"claude", "nobody"} {
		if err := tok.Revoke(ctx, name, now); !errors.Is(err, ErrNotFound) {
			t.Errorf("Revoke(%s) = %v, want ErrNotFound", name, err)
		}
	}
	list, err := tok.List(ctx)
	if err != nil || len(list) != 1 || !list[0].RevokedAt.Equal(now.Add(time.Second)) {
		t.Errorf("List = %+v, %v", list, err)
	}

	// Only the hash is stored.
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM mcp_tokens WHERE hash = ?`, []byte("secret-1")).Scan(&n); err != nil && !errors.Is(err, sql.ErrNoRows) {
		t.Fatal(err)
	}
	if n != 0 {
		t.Error("the token secret is stored in the clear")
	}
}

// A newer binary on a cluster database before schema 11 has no MCP tokens:
// none is valid and creating one is refused the same way on every node.
func TestMCPTokensBeforeTheirSchema(t *testing.T) {
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
	if _, err := p.DownTo(ctx, mcpTokensSchema-1); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	s, err = Open(ctx, path, WithoutUpgrade())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })

	if got, err := s.MCPTokens().List(ctx); err != nil || len(got) != 0 {
		t.Errorf("List before the schema = %v, %v; want none", got, err)
	}
	if _, err := s.MCPTokens().Check(ctx, "x"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Check before the schema = %v, want ErrNotFound", err)
	}
	if err := s.MCPTokens().Create(ctx, "claude", "x", "safe", time.Now()); !errors.Is(err, ErrSchemaTooOld) || !IsDomainError(err) {
		t.Errorf("Create before the schema = %v, want a domain ErrSchemaTooOld", err)
	}
}
