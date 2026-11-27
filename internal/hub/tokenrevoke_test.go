// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"context"
	"crypto/sha256"
	"net/http"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/gvart/hearth/internal/pki"
	"github.com/gvart/hearth/internal/policy"
	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
	"github.com/gvart/hearth/internal/store"
	"github.com/gvart/hearth/internal/store/storetest"
)

// newTokenRevokeFixture is an API fixture holding an unused plain token, an
// unused hub-eligible one and a used one, by secret.
func newTokenRevokeFixture(t *testing.T, cfg policy.Config) *apiFixture {
	t.Helper()
	f := newAPIFixture(t, true, withPolicy(cfg))
	f.api.argon = testArgon
	exp := time.Now().Add(10 * time.Minute)
	for _, tok := range []struct{ secret, name, roles string }{
		{"plain-secret", "", ""},
		{"hub-secret", "garage", allJoinRoles},
		{"used-secret", "", ""},
	} {
		if err := f.st.Tokens().CreateHub(t.Context(), tok.secret, tok.name, tok.roles, nil, exp); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.st.Tokens().Consume(t.Context(), "used-secret", time.Now()); err != nil {
		t.Fatal(err)
	}
	return f
}

func unusedTokens(t *testing.T, f *apiFixture) map[string]PendingTokenJSON {
	t.Helper()
	c := sessionCookie(t, f.login(t, testPassword))
	resp := f.do(t, http.MethodGet, "/api/v1/tokens", "", c)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET tokens = %d %s", resp.StatusCode, resp.body)
	}
	out := map[string]PendingTokenJSON{}
	for _, tok := range decode[struct{ Tokens []PendingTokenJSON }](t, resp).Tokens {
		out[tok.ID] = tok
	}
	return out
}

// The web UI lists the unused tokens, with their hub flag and expiry, and
// never their secret.
func TestAPIListTokens(t *testing.T) {
	f := newTokenRevokeFixture(t, policy.Config{})
	if resp := f.do(t, http.MethodGet, "/api/v1/tokens", "", nil); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("GET tokens without a session = %d, want 401", resp.StatusCode)
	}
	got := unusedTokens(t, f)
	plain, hub := got[tokenActorID("plain-secret")], got[tokenActorID("hub-secret")]
	if len(got) != 2 || plain.Hub || !hub.Hub || hub.Name != "garage" || hub.ExpiresAt.IsZero() {
		t.Fatalf("tokens = %+v; want plain and the hub-eligible garage", got)
	}
}

// Revoking is token.revoke by web, audited, refusals too: a hub-eligible
// token needs the password again, a used or unknown one is refused, and a
// policy that denies it keeps the token.
func TestAPIRevokeToken(t *testing.T) {
	plain, hub, used := tokenActorID("plain-secret"), tokenActorID("hub-secret"), tokenActorID("used-secret")
	for _, tc := range []struct {
		name   string
		cfg    policy.Config
		stale  bool
		id     string
		status int
		code   string
		allow  bool
	}{
		{name: "plain", id: plain, status: http.StatusNoContent, allow: true},
		{name: "plain, stale session", stale: true, id: plain, status: http.StatusNoContent, allow: true},
		{name: "hub-eligible", id: hub, status: http.StatusNoContent, allow: true},
		{name: "hub-eligible, stale session", stale: true, id: hub, status: http.StatusForbidden, code: "reauth_required"},
		{name: "used", id: used, status: http.StatusConflict, code: "token_used", allow: true},
		{name: "unknown", id: "0123456789ab", status: http.StatusNotFound, code: "not_found", allow: true},
		{
			name: "denied by policy", id: plain, status: http.StatusForbidden, code: "forbidden",
			cfg: policy.Config{Actors: map[string]map[policy.Class]policy.Mode{policy.ActorWeb: {policy.Safe: policy.ModeDeny}}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newTokenRevokeFixture(t, tc.cfg)
			c := sessionCookie(t, f.login(t, testPassword))
			if tc.stale {
				c = staleSession(t, f)
			}
			resp := f.do(t, http.MethodDelete, "/api/v1/tokens/"+tc.id, "", c)
			if resp.StatusCode != tc.status || (tc.code != "" && errorCode(t, resp) != tc.code) {
				t.Fatalf("DELETE = %d %s, want %d %s", resp.StatusCode, resp.body, tc.status, tc.code)
			}
			e := auditOf(t, f, policy.TokenRevoke)
			if len(e) != 1 || e[0].Target != tc.id || (e[0].Decision == policy.Allow) != tc.allow {
				t.Fatalf("token.revoke audit = %+v, want one entry for %s, allowed %v", e, tc.id, tc.allow)
			}
			_, listed := unusedTokens(t, f)[tc.id]
			if revoked := tc.status == http.StatusNoContent; listed == revoked && tc.id != used && tc.code != "not_found" {
				t.Fatalf("token %s listed = %v after DELETE %d", tc.id, listed, resp.StatusCode)
			}
		})
	}
}

// In an AP cluster only the master that created a token revokes it: another
// master is refused, naming the owner, and the token stays usable.
func TestAPIRevokeTokenNotOwner(t *testing.T) {
	// This hub is master hub-b: every write it applies is hub-b's.
	st := storetest.Open(t, store.WithApplier(func(s *store.Store) store.Applier {
		return store.ApplierFunc(func(ctx context.Context, cmd store.Command) (store.Result, error) {
			return s.ApplyLocal(ctx, store.OwnedBy(cmd, "hub-b"))
		})
	}))
	h := sha256.Sum256([]byte("owned-secret"))
	if _, err := st.ApplyLocal(t.Context(), store.CreateToken{
		Hash: h[:], Labels: "{}", ExpiresAt: time.Now().Add(time.Hour).UnixMilli(), Owner: "hub-a",
	}); err != nil {
		t.Fatal(err)
	}
	if err := setAdminPassword(t.Context(), st, policy.New(st.Audit()), "test", testPassword, testArgon); err != nil {
		t.Fatal(err)
	}
	f := newAPIFixture(t, true, func(c *Config) { c.Store = st })
	f.api.argon = testArgon
	c := sessionCookie(t, f.login(t, testPassword))
	id := tokenActorID("owned-secret")
	resp := f.do(t, http.MethodDelete, "/api/v1/tokens/"+id, "", c)
	if resp.StatusCode != http.StatusConflict || errorCode(t, resp) != "not_owner" || !strings.Contains(string(resp.body), "hub-a") {
		t.Fatalf("DELETE on another master = %d %s, want 409 not_owner naming hub-a", resp.StatusCode, resp.body)
	}
	if e := auditOf(t, f, policy.TokenRevoke); len(e) != 1 || e[0].Target != id || e[0].Result == "ok" {
		t.Fatalf("token.revoke audit = %+v, want one failed entry", e)
	}
	if tok, err := st.Tokens().Unused(t.Context(), id, time.Now()); err != nil || tok.ID != id {
		t.Fatalf("token after a refused revoke = %+v, %v; want it still unused", tok, err)
	}
}

// A revoked token cannot enroll a device; a revoked hub-eligible one mints
// no join token, as it never enrolls.
func TestEnrollRevokedToken(t *testing.T) {
	f := newAutoHubFixture(t, 1, 1)
	secret := f.token(t, true)
	if err := f.st.Tokens().Revoke(t.Context(), tokenActorID(secret), time.Now()); err != nil {
		t.Fatal(err)
	}
	key, err := pki.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	csr, err := pki.NewCSR(key, "pi")
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.e.Enroll(t.Context(), connect.NewRequest(&agentv1.EnrollRequest{
		TokenSecret: secret, Csr: csr, Hostname: "pi", HubOffer: capableOffer(),
	}))
	if connect.CodeOf(err) != connect.CodeUnauthenticated || !strings.Contains(err.Error(), "already used") {
		t.Fatalf("enroll with a revoked token = %v, want it refused", err)
	}
	if all, _, err := f.st.JoinTokens().PendingMinted(t.Context(), time.Now()); err != nil || all != 0 {
		t.Fatalf("%d join tokens minted, %v; want none", all, err)
	}
	if devs, err := f.st.Devices().List(t.Context()); err != nil || len(devs) != 0 {
		t.Fatalf("devices = %v, %v; want none", devs, err)
	}
	if e := auditEntries(t, f.st, policy.DeviceEnroll); len(e) != 1 || e[0].Result == "" || e[0].Result == "ok" {
		t.Fatalf("device.enroll audit = %+v, want one failed entry", e)
	}
}
