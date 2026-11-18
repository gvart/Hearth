// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"crypto/sha256"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestApprovalLinks(t *testing.T) {
	s := openTest(t)
	ctx := t.Context()
	links := s.ApprovalLinks()
	base := time.UnixMilli(1_700_000_000_000).UTC()
	exp := base.Add(time.Minute)
	for secret, id := range map[string]string{"s-use": "a", "s-reuse": "b", "s-expired": "c"} {
		if err := links.Create(ctx, secret, id, exp); err != nil {
			t.Fatal(err)
		}
	}
	if err := links.Create(ctx, "", "a", exp); err == nil {
		t.Error("Create with an empty secret succeeded")
	}
	if err := links.Create(ctx, "s-x", "", exp); err == nil {
		t.Error("Create without an approval id succeeded")
	}
	if _, err := links.Use(ctx, "s-reuse", base); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		secret  string
		at      time.Time
		wantID  string
		wantErr error
	}{
		{"valid", "s-use", base.Add(time.Second), "a", nil},
		{"reused", "s-reuse", base.Add(time.Second), "", ErrTokenUsed},
		{"expired", "s-expired", exp, "", ErrTokenExpired},
		{"wrong", "s-nope", base, "", ErrNotFound},
		{"empty", "", base, "", ErrNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id, err := links.Peek(ctx, tt.secret, tt.at)
			if !errors.Is(err, tt.wantErr) || id != tt.wantID {
				t.Fatalf("Peek = %q, %v; want %q, %v", id, err, tt.wantID, tt.wantErr)
			}
			id, err = links.Use(ctx, tt.secret, tt.at)
			if !errors.Is(err, tt.wantErr) || id != tt.wantID {
				t.Fatalf("Use = %q, %v; want %q, %v", id, err, tt.wantID, tt.wantErr)
			}
			if err != nil && !IsDomainError(err) {
				t.Errorf("%v is not a domain error", err)
			}
			// Whatever happened, the link cannot be used (again) now.
			if _, err := links.Use(ctx, tt.secret, tt.at); err == nil {
				t.Error("second Use succeeded")
			}
			if _, err := links.Peek(ctx, tt.secret, tt.at); err == nil {
				t.Error("Peek after Use succeeded")
			}
		})
	}

	// Only the hash is stored.
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM approval_links WHERE hash = ? OR hash = ?`,
		[]byte("s-use"), "s-use").Scan(&n); err != nil || n != 0 {
		t.Errorf("secret stored in the clear: %d rows, %v", n, err)
	}
	h := sha256.Sum256([]byte("s-use"))
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM approval_links WHERE hash = ?`, h[:]).Scan(&n); err != nil || n != 1 {
		t.Errorf("hashed secret: %d rows, %v", n, err)
	}
}

func TestApprovalLinkUsedOnceConcurrently(t *testing.T) {
	s := openTest(t)
	ctx := t.Context()
	now := time.Now()
	if err := s.ApprovalLinks().Create(ctx, "secret", "a", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	var (
		wg sync.WaitGroup
		mu sync.Mutex
		ok int
	)
	for range 8 {
		wg.Go(func() {
			if _, err := s.ApprovalLinks().Use(ctx, "secret", now); err == nil {
				mu.Lock()
				ok++
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	if ok != 1 {
		t.Errorf("%d uses succeeded, want 1", ok)
	}
}

// Before schema 10 no link can be made, and none is found.
func TestApprovalLinksBeforeTheirSchema(t *testing.T) {
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
	if _, err := p.DownTo(ctx, approvalLinksSchema-1); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	s, err = Open(ctx, path, WithoutUpgrade())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })

	now := time.Now()
	if err := s.ApprovalLinks().Create(ctx, "secret", "a", now.Add(time.Minute)); !errors.Is(err, ErrSchemaTooOld) {
		t.Errorf("Create before the schema = %v, want ErrSchemaTooOld", err)
	}
	if _, err := s.ApprovalLinks().Peek(ctx, "secret", now); !errors.Is(err, ErrNotFound) {
		t.Errorf("Peek before the schema = %v, want ErrNotFound", err)
	}
}
