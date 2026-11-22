// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"database/sql"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/gvart/hearth/internal/pki"
	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
	"github.com/gvart/hearth/internal/store/storetest"
)

// A hub-eligible enrollment token ("hub": true, #328) is decided twice:
// token.create, then cluster.token.create behind the password again. It is
// stored with the hub roles and audited by its handle, never its secret.
func TestAPICreateHubToken(t *testing.T) {
	f, _ := clusterCAFixture(t, policy.Config{})
	c := sessionCookie(t, f.login(t, testPassword))
	resp := f.do(t, http.MethodPost, "/api/v1/tokens", `{"hub":true,"name":"pi-1"}`, c)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d, body %s", resp.StatusCode, resp.body)
	}
	got := decode[TokenJSON](t, resp)
	tok, err := pki.ParseToken(got.Token)
	if err != nil {
		t.Fatal(err)
	}
	entries := auditOf(t, f, policy.ClusterTokenCreate)
	if len(entries) != 1 || entries[0].ActorKind != policy.ActorWeb || entries[0].Result != "ok" {
		t.Fatalf("cluster.token.create audit = %+v, want one by web, ok", entries)
	}
	for _, want := range []string{`"via":"enrollment_token"`, `"roles":"storage,master"`, `"token":"` + tokenActorID(tok.Secret) + `"`} {
		if !strings.Contains(string(entries[0].Detail), want) {
			t.Errorf("cluster.token.create detail %s lacks %s", entries[0].Detail, want)
		}
	}
	if tc := auditOf(t, f, policy.TokenCreate); len(tc) == 0 || !strings.Contains(string(tc[0].Detail), `"hub":true`) {
		t.Errorf("token.create audit = %+v, want hub true", tc)
	}
	for _, where := range []string{f.logs.String(), allAuditText(t, f)} {
		if strings.Contains(where, tok.Secret) {
			t.Fatal("the token secret is in the logs or the audit log")
		}
	}
	et, err := f.st.Tokens().Consume(t.Context(), tok.Secret, time.Now())
	if err != nil || et.HubRoles != "storage,master" || et.Name != "pi-1" {
		t.Fatalf("consume = %+v, %v; want hub roles storage,master", et, err)
	}

	// Without "hub" the token offers no hub, and asks no password again.
	stale := staleSession(t, f)
	resp = f.do(t, http.MethodPost, "/api/v1/tokens", `{}`, stale)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("plain token on a stale session = %d %s", resp.StatusCode, resp.body)
	}
	plain, _ := pki.ParseToken(decode[TokenJSON](t, resp).Token)
	if et, err := f.st.Tokens().Consume(t.Context(), plain.Secret, time.Now()); err != nil || et.HubRoles != "" {
		t.Fatalf("plain consume = %+v, %v; want no hub roles", et, err)
	}
}

// Refusals of a hub-eligible token create no token at all.
func TestAPICreateHubTokenRefused(t *testing.T) {
	t.Run("no re-auth", func(t *testing.T) {
		f, _ := clusterCAFixture(t, policy.Config{})
		resp := f.do(t, http.MethodPost, "/api/v1/tokens", `{"hub":true}`, staleSession(t, f))
		if resp.StatusCode != http.StatusForbidden || errorCode(t, resp) != "reauth_required" {
			t.Fatalf("hub token without re-auth = %d %s, want 403 reauth_required", resp.StatusCode, resp.body)
		}
		if e := auditOf(t, f, policy.ClusterTokenCreate); len(e) != 1 || e[0].Decision != policy.Deny {
			t.Fatalf("audit = %+v, want one denial", e)
		}
		if n := countTokens(t, f); n != 0 {
			t.Fatalf("%d tokens created without re-auth", n)
		}
	})
	t.Run("denied", func(t *testing.T) {
		f, _ := clusterCAFixture(t, policy.Config{
			Actors: map[string]map[policy.Class]policy.Mode{policy.ActorWeb: {policy.Dangerous: policy.ModeDeny}},
		})
		c := sessionCookie(t, f.login(t, testPassword))
		resp := f.do(t, http.MethodPost, "/api/v1/tokens", `{"hub":true}`, c)
		if resp.StatusCode != http.StatusForbidden || errorCode(t, resp) != "forbidden" {
			t.Fatalf("hub token denied = %d %s, want 403 forbidden", resp.StatusCode, resp.body)
		}
		if n := countTokens(t, f); n != 0 {
			t.Fatalf("%d tokens created against the policy", n)
		}
		// The dry run says so too, and a plain token is still allowed.
		if resp := f.do(t, http.MethodPost, "/api/v1/tokens", `{"hub":true,"dry_run":true}`, c); resp.StatusCode != http.StatusForbidden {
			t.Fatalf("dry run = %d %s, want 403", resp.StatusCode, resp.body)
		}
		if resp := f.do(t, http.MethodPost, "/api/v1/tokens", `{}`, c); resp.StatusCode != http.StatusCreated {
			t.Fatalf("plain token = %d %s", resp.StatusCode, resp.body)
		}
	})
	t.Run("held dry run", func(t *testing.T) {
		f, _ := clusterCAFixture(t, policy.Config{
			Actors: map[string]map[policy.Class]policy.Mode{policy.ActorWeb: {policy.Dangerous: policy.ModeConfirm}},
		})
		c := sessionCookie(t, f.login(t, testPassword))
		resp := f.do(t, http.MethodPost, "/api/v1/tokens", `{"hub":true,"dry_run":true}`, c)
		if resp.StatusCode != http.StatusOK || decode[DryRunJSON](t, resp).Decision != policy.Confirm {
			t.Fatalf("dry run = %d %s, want confirm", resp.StatusCode, resp.body)
		}
		if n := countTokens(t, f); n != 0 {
			t.Fatalf("%d tokens created by a dry run", n)
		}
	})
	t.Run("outside an AP cluster", func(t *testing.T) {
		f := newAPIFixture(t, true)
		c := sessionCookie(t, f.login(t, testPassword))
		if resp := f.do(t, http.MethodPost, "/api/v1/tokens", `{"hub":true}`, c); resp.StatusCode != http.StatusNotFound {
			t.Fatalf("hub token outside AP = %d %s, want 404", resp.StatusCode, resp.body)
		}
	})
	t.Run("schema too old", func(t *testing.T) {
		old := oldSchemaStore(t, 33)
		pol := policy.New(old.Audit())
		if err := setAdminPassword(t.Context(), old, pol, "test", testPassword, testArgon); err != nil {
			t.Fatal(err)
		}
		f := newAPIFixture(t, false, func(c *Config) {
			c.Store, c.Policy, c.ClusterCA = old, pol, &fakeClusterCA{pol: pol}
		})
		f.api.argon = testArgon
		c := sessionCookie(t, f.login(t, testPassword))
		resp := f.do(t, http.MethodPost, "/api/v1/tokens", `{"hub":true}`, c)
		if resp.StatusCode != http.StatusConflict || errorCode(t, resp) != "schema_too_old" {
			t.Fatalf("hub token at schema 33 = %d %s, want 409 schema_too_old", resp.StatusCode, resp.body)
		}
		if resp := f.do(t, http.MethodPost, "/api/v1/tokens", `{}`, c); resp.StatusCode != http.StatusCreated {
			t.Fatalf("plain token at schema 33 = %d %s", resp.StatusCode, resp.body)
		}
	})
}

// countTokens is how many enrollment token creations of f succeeded.
func countTokens(t *testing.T, f *apiFixture) int {
	t.Helper()
	n := 0
	for _, e := range auditOf(t, f, policy.TokenCreate) {
		if e.Result == "ok" {
			n++
		}
	}
	return n
}

// oldSchemaStore is a store whose database is at schema v, as on a hub not
// yet upgraded: migrated, then the newer migrations undone by hand.
func oldSchemaStore(t *testing.T, v int64) *store.Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "hearth.db")
	storetest.Migrated(t, path)
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`ALTER TABLE join_tokens DROP COLUMN device_id`,
		`ALTER TABLE tokens DROP COLUMN hub_roles`,
	} {
		if _, err := db.ExecContext(t.Context(), q); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.ExecContext(t.Context(), `DELETE FROM goose_db_version WHERE version_id > ?`, v); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	st, err := store.Open(t.Context(), path, store.WithoutUpgrade())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if got, err := st.SchemaVersion(t.Context()); err != nil || got != v {
		t.Fatalf("schema = %d, %v; want %d", got, err, v)
	}
	return st
}

