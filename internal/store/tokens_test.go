// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"errors"
	"testing"
	"time"
)

// A member not migrated to schema 32 still creates and spends unnamed
// enrollment tokens, and refuses a named one.
func TestTokenNameBelowSchema(t *testing.T) {
	ctx := t.Context()
	s := openAtSchema(t, tokenNameSchema-1)
	exp := time.Now().Add(time.Minute)
	if err := s.Tokens().CreateNamed(ctx, "named", "garage-pi", nil, exp); !errors.Is(err, ErrSchemaTooOld) {
		t.Fatalf("CreateNamed = %v, want ErrSchemaTooOld", err)
	}
	if err := s.Tokens().Create(ctx, "plain", map[string]string{"room": "attic"}, exp); err != nil {
		t.Fatal(err)
	}
	got, err := s.Tokens().Consume(ctx, "plain", time.Now())
	if err != nil || got.Name != "" || got.Labels["room"] != "attic" {
		t.Fatalf("Consume = %+v, %v", got, err)
	}
}

// A member not migrated to schema 34 refuses an enrollment token with hub
// roles and a join token minted for a device, and still writes plain ones.
func TestHubTokensBelowSchema(t *testing.T) {
	ctx := t.Context()
	s := openAtSchema(t, hubTokenSchema-1)
	exp := time.Now().Add(time.Minute)
	if err := s.Tokens().CreateHub(ctx, "hub", "", "storage,master", nil, exp); !errors.Is(err, ErrSchemaTooOld) {
		t.Fatalf("CreateHub = %v, want ErrSchemaTooOld", err)
	}
	if err := s.JoinTokens().CreateFor(ctx, "minted", exp, "storage", "dev-1"); !errors.Is(err, ErrSchemaTooOld) {
		t.Fatalf("CreateFor = %v, want ErrSchemaTooOld", err)
	}
	if err := s.Tokens().CreateNamed(ctx, "named", "pi", nil, exp); err != nil {
		t.Fatal(err)
	}
	if err := s.JoinTokens().Create(ctx, "plain", exp, "storage"); err != nil {
		t.Fatal(err)
	}
	if all, masters, err := s.JoinTokens().PendingMinted(ctx, time.Now()); err != nil || all != 0 || masters != 0 {
		t.Fatalf("PendingMinted = %d, %d, %v", all, masters, err)
	}
}

// An enrollment token keeps its hub roles and a minted join token its
// device; PendingMinted counts the minted ones not yet spent nor expired.
func TestHubTokens(t *testing.T) {
	ctx := t.Context()
	s := openAtSchema(t, hubTokenSchema)
	now := time.Now()
	if err := s.Tokens().CreateHub(ctx, "hub", "garage", "storage,master", map[string]string{"a": "b"}, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	got, err := s.Tokens().Consume(ctx, "hub", now)
	if err != nil || got.HubRoles != "storage,master" || got.Name != "garage" || got.Labels["a"] != "b" {
		t.Fatalf("Consume = %+v, %v", got, err)
	}
	for _, j := range []struct{ secret, roles, device string }{
		{"m1", "storage,master", "dev-1"},
		{"s1", "storage", "dev-2"},
		{"admin", "storage,master", ""},
		{"old", "storage,master", "dev-3"},
	} {
		exp := now.Add(time.Minute)
		if j.secret == "old" {
			exp = now.Add(-time.Minute)
		}
		if err := s.JoinTokens().CreateFor(ctx, j.secret, exp, j.roles, j.device); err != nil {
			t.Fatal(err)
		}
	}
	if all, masters, err := s.JoinTokens().PendingMinted(ctx, now); err != nil || all != 2 || masters != 1 {
		t.Fatalf("PendingMinted = %d, %d, %v; want 2, 1", all, masters, err)
	}
	jt, err := s.JoinTokens().Use(ctx, "m1", now)
	if err != nil || jt.DeviceID != "dev-1" || jt.Roles != "storage,master" {
		t.Fatalf("Use = %+v, %v", jt, err)
	}
	if _, err := s.JoinTokens().Use(ctx, "m1", now); !errors.Is(err, ErrTokenUsed) {
		t.Fatalf("Use again = %v, want ErrTokenUsed", err)
	}
	if _, err := s.JoinTokens().Use(ctx, "old", now); !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("Use expired = %v, want ErrTokenExpired", err)
	}
	if _, err := s.JoinTokens().Use(ctx, "nope", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Use unknown = %v, want ErrNotFound", err)
	}
	if all, masters, err := s.JoinTokens().PendingMinted(ctx, now); err != nil || all != 1 || masters != 0 {
		t.Fatalf("PendingMinted after use = %d, %d, %v; want 1, 0", all, masters, err)
	}
}
