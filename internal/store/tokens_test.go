// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"encoding/hex"
	"errors"
	"strings"
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
	jt, err := s.JoinTokens().Use(ctx, "m1", "hub-1", now)
	if err != nil || jt.DeviceID != "dev-1" || jt.Roles != "storage,master" {
		t.Fatalf("Use = %+v, %v", jt, err)
	}
	if _, err := s.JoinTokens().Use(ctx, "m1", "hub-1", now); !errors.Is(err, ErrTokenUsed) {
		t.Fatalf("Use again = %v, want ErrTokenUsed", err)
	}
	if _, err := s.JoinTokens().Use(ctx, "old", "hub-3", now); !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("Use expired = %v, want ErrTokenExpired", err)
	}
	if _, err := s.JoinTokens().Use(ctx, "nope", "hub-4", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Use unknown = %v, want ErrNotFound", err)
	}
	if all, masters, err := s.JoinTokens().PendingMinted(ctx, now); err != nil || all != 1 || masters != 0 {
		t.Fatalf("PendingMinted after use = %d, %d, %v; want 1, 0", all, masters, err)
	}

	// The hub that joined with a minted token, and got its certificate,
	// counts as joined, by the token's roles; one with an admin's token does
	// not, nor one without a certificate (refused), nor one removed.
	if _, err := s.JoinTokens().Use(ctx, "admin", "hub-x", now); err != nil {
		t.Fatal(err)
	}
	if joined, err := s.JoinTokens().JoinedSince(ctx, now.Add(-time.Minute)); err != nil || len(joined) != 0 {
		t.Fatalf("JoinedSince without a certificate = %v, %v; want none", joined, err)
	}
	for _, id := range []string{"hub-1", "hub-x"} {
		if err := s.Hubs().RecordCert(ctx, "c-"+id, id); err != nil {
			t.Fatal(err)
		}
	}
	joined, err := s.JoinTokens().JoinedSince(ctx, now.Add(-time.Minute))
	if err != nil || len(joined) != 1 || joined["hub-1"] != "storage,master" {
		t.Fatalf("JoinedSince = %v, %v; want hub-1 as storage,master", joined, err)
	}
	if joined, err := s.JoinTokens().JoinedSince(ctx, now); err != nil || len(joined) != 0 {
		t.Fatalf("JoinedSince(now) = %v, %v; want none", joined, err)
	}
	if _, err := s.Hubs().RevokeCerts(ctx, "hub-1", now); err != nil {
		t.Fatal(err)
	}
	if joined, err := s.JoinTokens().JoinedSince(ctx, now.Add(-time.Minute)); err != nil || len(joined) != 0 {
		t.Fatalf("JoinedSince after removal = %v, %v; want none", joined, err)
	}
}

// HubEligible lists the hubs whose latest join used a token minted for a
// device, with an unrevoked hub certificate: not one that joined with an
// admin's token, nor one that rejoined with one after a minted join, nor
// one removed.
func TestHubEligible(t *testing.T) {
	ctx := t.Context()
	s := openAtSchema(t, hubTokenSchema)
	t0 := time.Now().Add(-time.Hour)
	join := func(secret, device, node string, at time.Time) {
		t.Helper()
		if err := s.JoinTokens().CreateFor(ctx, secret, at.Add(time.Minute), "storage", device); err != nil {
			t.Fatal(err)
		}
		if _, err := s.JoinTokens().Use(ctx, secret, node, at); err != nil {
			t.Fatal(err)
		}
	}
	join("m1", "dev-1", "hub-1", t0)
	join("m2", "dev-2", "hub-2", t0.Add(time.Minute))
	join("a3", "", "hub-3", t0)
	join("m4", "dev-4", "hub-4", t0)
	join("a4", "", "hub-4", t0.Add(time.Minute))
	join("m5", "dev-5", "hub-5", t0)
	for _, id := range []string{"hub-1", "hub-2", "hub-3", "hub-4", "hub-5"} {
		if err := s.Hubs().RecordCert(ctx, "c-"+id, id); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.Hubs().RevokeCerts(ctx, "hub-5", time.Now()); err != nil {
		t.Fatal(err)
	}
	got, err := s.JoinTokens().HubEligible(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || !got["hub-1"].Equal(t0.Truncate(time.Millisecond)) || !got["hub-2"].After(got["hub-1"]) {
		t.Fatalf("HubEligible = %v; want hub-1 then hub-2", got)
	}
}

// HubOf links a device to the hub that joined last with a token minted for
// it, while that hub's certificate is not revoked.
func TestHubOf(t *testing.T) {
	ctx := t.Context()
	s := openAtSchema(t, hubTokenSchema)
	now := time.Now()
	for _, secret := range []string{"first", "second", "admin"} {
		device := "dev-1"
		if secret == "admin" {
			device = ""
		}
		if err := s.JoinTokens().CreateFor(ctx, secret, now.Add(time.Hour), "storage", device); err != nil {
			t.Fatal(err)
		}
	}
	if node, err := s.JoinTokens().HubOf(ctx, "dev-1"); err != nil || node != "" {
		t.Fatalf("HubOf before any join = %q, %v; want none", node, err)
	}
	for i, j := range []struct{ secret, node string }{{"first", "hub-a"}, {"second", "hub-b"}, {"admin", "hub-x"}} {
		if _, err := s.JoinTokens().Use(ctx, j.secret, j.node, now.Add(time.Duration(i)*time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	if node, err := s.JoinTokens().HubOf(ctx, "dev-1"); err != nil || node != "" {
		t.Fatalf("HubOf without a certificate = %q, %v; want none (the join was refused)", node, err)
	}
	for _, id := range []string{"hub-a", "hub-b", "hub-x"} {
		if err := s.Hubs().RecordCert(ctx, "c-"+id, id); err != nil {
			t.Fatal(err)
		}
	}
	if node, err := s.JoinTokens().HubOf(ctx, "dev-1"); err != nil || node != "hub-b" {
		t.Fatalf("HubOf = %q, %v; want the last join, hub-b", node, err)
	}
	if node, err := s.JoinTokens().HubOf(ctx, ""); err != nil || node != "" {
		t.Fatalf("HubOf of no device = %q, %v; want none", node, err)
	}
	if _, err := s.Hubs().RevokeCerts(ctx, "hub-b", now); err != nil {
		t.Fatal(err)
	}
	if node, err := s.JoinTokens().HubOf(ctx, "dev-1"); err != nil || node != "hub-a" {
		t.Fatalf("HubOf after hub-b's removal = %q, %v; want hub-a", node, err)
	}
	if _, err := s.Hubs().RevokeCerts(ctx, "hub-a", now); err != nil {
		t.Fatal(err)
	}
	if node, err := s.JoinTokens().HubOf(ctx, "dev-1"); err != nil || node != "" {
		t.Fatalf("HubOf after both removals = %q, %v; want none", node, err)
	}
}

// ListUnused lists the tokens neither used nor expired, soonest to expire
// first; Revoke spends one by its ID so it cannot enroll, and refuses a
// used, expired, unknown or malformed ID.
func TestRevokeToken(t *testing.T) {
	ctx := t.Context()
	s := openTest(t)
	now := time.Now()
	id := func(secret string) string {
		h := hashSecret(secret)
		return hex.EncodeToString(h[:6])
	}
	if err := s.Tokens().CreateHub(ctx, "hub", "garage", "storage,master", map[string]string{"a": "b"}, now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	for secret, exp := range map[string]time.Time{"plain": now.Add(time.Minute), "used": now.Add(time.Minute), "old": now.Add(-time.Minute)} {
		if err := s.Tokens().Create(ctx, secret, nil, exp); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.Tokens().Consume(ctx, "used", now); err != nil {
		t.Fatal(err)
	}
	list, err := s.Tokens().ListUnused(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 || list[0].ID != id("plain") || list[0].HubEligible ||
		list[1].ID != id("hub") || !list[1].HubEligible || list[1].Name != "garage" || list[1].Labels["a"] != "b" {
		t.Fatalf("ListUnused = %+v; want plain, then hub", list)
	}
	if got, err := s.Tokens().Unused(ctx, strings.ToUpper(id("hub")), now); err != nil || !got.HubEligible {
		t.Fatalf("Unused(hub) = %+v, %v", got, err)
	}

	for _, tc := range []struct {
		name, id string
		want     error
	}{
		{"used", id("used"), ErrTokenUsed},
		{"expired", id("old"), ErrTokenExpired},
		{"unknown", id("nope"), ErrNotFound},
		{"malformed", "zz", ErrNotFound},
		{"too short", id("plain")[:8], ErrNotFound},
	} {
		if err := s.Tokens().Revoke(ctx, tc.id, now); !errors.Is(err, tc.want) {
			t.Errorf("Revoke %s = %v, want %v", tc.name, err, tc.want)
		}
	}

	if err := s.Tokens().Revoke(ctx, id("hub"), now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Tokens().Consume(ctx, "hub", now); !errors.Is(err, ErrTokenUsed) {
		t.Fatalf("Consume revoked = %v, want it refused", err)
	}
	if err := s.Tokens().Revoke(ctx, id("hub"), now); !errors.Is(err, ErrTokenUsed) {
		t.Fatalf("Revoke again = %v, want ErrTokenUsed", err)
	}
	if list, err := s.Tokens().ListUnused(ctx, now); err != nil || len(list) != 1 || list[0].ID != id("plain") {
		t.Fatalf("ListUnused after revoke = %+v, %v; want plain only", list, err)
	}
}

// Below schema 32, tokens are listed without a name or hub roles.
func TestListUnusedBelowSchema(t *testing.T) {
	ctx := t.Context()
	s := openAtSchema(t, tokenNameSchema-1)
	if err := s.Tokens().Create(ctx, "plain", nil, time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if list, err := s.Tokens().ListUnused(ctx, time.Now()); err != nil || len(list) != 1 || list[0].Name != "" || list[0].HubEligible {
		t.Fatalf("ListUnused = %+v, %v", list, err)
	}
}
