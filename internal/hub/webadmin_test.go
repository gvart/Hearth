// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

// staleSession is a valid session that has not entered the password lately,
// as a session older than ReauthTTL or a stolen cookie: made in the store
// directly, without a login.
func staleSession(t *testing.T, f *apiFixture) *http.Cookie {
	t.Helper()
	secret, err := newSessionSecret()
	if err != nil {
		t.Fatal(err)
	}
	now := f.api.now()
	if err := f.st.Admin().CreateSession(t.Context(), secret, now, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	return testCookie(secret)
}

// fixtureClock makes f's api run on a clock the test advances.
func fixtureClock(f *apiFixture) func(time.Duration) {
	var mu sync.Mutex
	now := time.Now()
	f.api.now = func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	return func(d time.Duration) { mu.Lock(); defer mu.Unlock(); now = now.Add(d) }
}

// auditOf is f's audit entries of action, newest first.
func auditOf(t *testing.T, f *apiFixture, action policy.Action) []store.AuditEntry {
	t.Helper()
	all, err := f.st.Audit().List(t.Context(), 500)
	if err != nil {
		t.Fatal(err)
	}
	var out []store.AuditEntry
	for _, e := range all {
		if e.Action == string(action) {
			out = append(out, e)
		}
	}
	return out
}

func errorCode(t *testing.T, resp apiResp) string {
	t.Helper()
	var e ErrorJSON
	_ = json.Unmarshal(resp.body, &e)
	return e.Code
}

func newWebAdminFixture(t *testing.T, cfg policy.Config) *apiFixture {
	t.Helper()
	f := newAPIFixture(t, true, withPolicy(cfg))
	f.api.argon = testArgon
	enrollDevice(t, f.st, "pi")
	if err := f.st.Certs().Create(t.Context(), "0a", "pi"); err != nil {
		t.Fatal(err)
	}
	return f
}

// A sensitive action needs the password entered again within ReauthTTL: a
// session alone, stale or stolen, is refused and audited as a denial, and
// nothing happens. Entering the password again lets it through, until the
// TTL passes.
func TestReauthRequiredForSensitiveActions(t *testing.T) {
	f := newWebAdminFixture(t, policy.Config{})
	advance := fixtureClock(f)
	stale := staleSession(t, f)

	actions := []struct {
		name, method, path, body string
		action                   policy.Action
	}{
		{"revoke", http.MethodPost, "/api/v1/devices/pi/revoke", "", policy.DeviceRevoke},
		{"mcp create", http.MethodPost, "/api/v1/mcp/tokens", `{"name":"claude","scope":"read"}`, policy.MCPTokenCreate},
		{"mcp revoke", http.MethodDelete, "/api/v1/mcp/tokens/claude", "", policy.MCPTokenRevoke},
	}
	for _, a := range actions {
		resp := f.do(t, a.method, a.path, a.body, stale)
		if resp.StatusCode != http.StatusForbidden || errorCode(t, resp) != "reauth_required" {
			t.Fatalf("%s without re-auth = %d %s, want 403 reauth_required", a.name, resp.StatusCode, resp.body)
		}
		entries := auditOf(t, f, a.action)
		if len(entries) != 1 || entries[0].Decision != policy.Deny || !strings.Contains(entries[0].Result, "password was not entered again") {
			t.Fatalf("%s audit = %+v, want one re-auth denial", a.name, entries)
		}
	}

	// A wrong password does not re-authenticate.
	if resp := f.do(t, http.MethodPost, "/api/v1/session/reauth", passwordBody("wrong-guess-9d2e"), stale); resp.StatusCode != http.StatusForbidden || errorCode(t, resp) != "reauth_failed" {
		t.Fatalf("reauth with a wrong password = %d %s", resp.StatusCode, resp.body)
	}
	if resp := f.do(t, http.MethodPost, "/api/v1/devices/pi/revoke", "", stale); errorCode(t, resp) != "reauth_required" {
		t.Fatalf("revoke after a wrong password = %d %s", resp.StatusCode, resp.body)
	}
	// The right one does.
	resp := f.do(t, http.MethodPost, "/api/v1/session/reauth", passwordBody(testPassword), stale)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("reauth = %d %s", resp.StatusCode, resp.body)
	}
	if got := decode[ReauthJSON](t, resp); got.Until.Sub(f.api.now()) != ReauthTTL {
		t.Errorf("reauth until %v, want now + %s", got.Until, ReauthTTL)
	}
	if s := decode[SessionJSON](t, f.do(t, http.MethodGet, "/api/v1/session", "", stale)); s.ReauthUntil == nil {
		t.Error("the session does not say it re-authenticated")
	}
	resp = f.do(t, http.MethodPost, "/api/v1/mcp/tokens", `{"name":"claude","scope":"read"}`, stale)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("mcp create after re-auth = %d %s", resp.StatusCode, resp.body)
	}

	// After ReauthTTL the password is needed again.
	advance(ReauthTTL)
	if resp := f.do(t, http.MethodPost, "/api/v1/devices/pi/revoke", "", stale); errorCode(t, resp) != "reauth_required" {
		t.Fatalf("revoke after the re-auth expired = %d %s", resp.StatusCode, resp.body)
	}
	if s := decode[SessionJSON](t, f.do(t, http.MethodGet, "/api/v1/session", "", stale)); s.ReauthUntil != nil {
		t.Error("the session still says it re-authenticated")
	}

	// Every attempt is audited, without the password.
	reauths := auditOf(t, f, policy.AdminReauth)
	if len(reauths) != 2 {
		t.Fatalf("audited %d re-authentications, want 2: %+v", len(reauths), reauths)
	}
	all, _ := f.st.Audit().List(t.Context(), 500)
	for _, e := range all {
		if strings.Contains(e.Result+e.Target+string(e.Detail), testPassword) {
			t.Errorf("audit entry holds the password: %+v", e)
		}
	}
	if strings.Contains(f.logs.String(), testPassword) || strings.Contains(f.logs.String(), "wrong-guess-9d2e") {
		t.Error("the logs hold a password")
	}
}

// A login is a fresh entry of the password; a re-auth is for one session
// only, and ends with it.
func TestReauthIsPerSession(t *testing.T) {
	f := newWebAdminFixture(t, policy.Config{})
	login := f.login(t, testPassword)
	if s := decode[SessionJSON](t, login); s.ReauthUntil == nil {
		t.Error("a login does not count as entering the password")
	}
	fresh := sessionCookie(t, login)
	stale := staleSession(t, f)
	if resp := f.do(t, http.MethodPost, "/api/v1/devices/pi/revoke", "", stale); errorCode(t, resp) != "reauth_required" {
		t.Fatalf("another session's re-auth let it through: %d %s", resp.StatusCode, resp.body)
	}
	if resp := f.do(t, http.MethodPost, "/api/v1/logout", "", fresh); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("logout = %d", resp.StatusCode)
	}
	if f.api.reauths.until(fresh.Value, f.api.now()) != (time.Time{}) {
		t.Error("logout kept the session's re-auth")
	}
}

// Re-authenticating shares login's rate limit.
func TestReauthRateLimited(t *testing.T) {
	f := newWebAdminFixture(t, policy.Config{})
	c := staleSession(t, f)
	limited := false
	for range loginBurst + 1 {
		resp := f.do(t, http.MethodPost, "/api/v1/session/reauth", passwordBody("wrong-guess-a1b2c3"), c)
		if resp.StatusCode == http.StatusTooManyRequests {
			limited = true
			break
		}
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("reauth = %d %s", resp.StatusCode, resp.body)
		}
	}
	if !limited {
		t.Fatal("wrong passwords were never rate limited")
	}
	if resp := f.login(t, testPassword); resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("login after wrong re-auths = %d, want 429: they share the limit", resp.StatusCode)
	}
	if resp := f.do(t, http.MethodPost, "/api/v1/session/reauth", passwordBody(testPassword), c); resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("reauth while limited = %d, want 429", resp.StatusCode)
	}
}

func TestWebRevokeDevice(t *testing.T) {
	f := newWebAdminFixture(t, policy.Config{})
	c := sessionCookie(t, f.login(t, testPassword))
	resp := f.do(t, http.MethodPost, "/api/v1/devices/pi/revoke", "", c)
	if resp.StatusCode != http.StatusOK || decode[RevokedJSON](t, resp).Revoked != 1 {
		t.Fatalf("revoke = %d %s", resp.StatusCode, resp.body)
	}
	if err := f.st.Certs().Check(t.Context(), "0a", "pi"); !errors.Is(err, store.ErrCertRevoked) {
		t.Errorf("certificate check = %v, want revoked", err)
	}
	if resp := f.do(t, http.MethodPost, "/api/v1/devices/nope/revoke", "", c); resp.StatusCode != http.StatusNotFound {
		t.Errorf("revoke of an unknown device = %d", resp.StatusCode)
	}
	entries := auditOf(t, f, policy.DeviceRevoke)
	if len(entries) == 0 || entries[len(entries)-1].ActorKind != policy.ActorWeb {
		t.Errorf("audit = %+v", entries)
	}
}

// Policy decides every web action: a configuration that denies dangerous
// web actions refuses a revocation, and one that holds them holds it. The
// re-auth check runs first, so a stale session is never held.
func TestWebAdminFollowsPolicy(t *testing.T) {
	f := newWebAdminFixture(t, policy.Config{Actors: map[string]map[policy.Class]policy.Mode{
		policy.ActorWeb: {policy.Dangerous: policy.ModeDeny},
	}})
	c := sessionCookie(t, f.login(t, testPassword))
	for _, req := range []struct{ method, path, body string }{
		{http.MethodPost, "/api/v1/devices/pi/revoke", ""},
		{http.MethodPost, "/api/v1/mcp/tokens", `{"name":"x"}`},
		{http.MethodPut, "/api/v1/admin/password", `{"current_password":"` + testPassword + `","new_password":"another-password-1"}`},
	} {
		resp := f.do(t, req.method, req.path, req.body, c)
		if resp.StatusCode != http.StatusForbidden || errorCode(t, resp) != "forbidden" {
			t.Errorf("%s %s with dangerous denied = %d %s, want 403", req.method, req.path, resp.StatusCode, resp.body)
		}
	}
	if err := f.st.Certs().Check(t.Context(), "0a", "pi"); err != nil {
		t.Error("a denied revocation revoked")
	}
	if err := CheckAdminPassword(t.Context(), f.st, testPassword); err != nil {
		t.Errorf("a denied password change changed it: %v", err)
	}
}

// The web actor is admitted only to the rules that name it: without
// ActorWeb in device.revoke's rule, policy would deny the web UI's revoke.
func TestWebActorAdmitted(t *testing.T) {
	for _, a := range []policy.Action{policy.DeviceRevoke, policy.MCPTokenCreate, policy.MCPTokenRevoke,
		policy.AdminSetPassword, policy.AdminReauth, policy.HubBackup, policy.ConfigImport} {
		if !policy.Admits(a, policy.ActorWeb) {
			t.Errorf("%s does not admit the web actor", a)
		}
	}
	// Restore and the CLI's recovery stay on the hub host.
	for _, a := range []policy.Action{policy.HubRestore, policy.ConfigExport, policy.ClusterCARotate, policy.ClusterTokenCreate} {
		if policy.Admits(a, policy.ActorWeb) {
			t.Errorf("%s admits the web actor", a)
		}
	}
}

// An MCP token's secret is shown once, at creation: the list never holds it,
// nor do the audit log or the logs.
func TestWebMCPTokens(t *testing.T) {
	f := newWebAdminFixture(t, policy.Config{})
	c := sessionCookie(t, f.login(t, testPassword))
	for _, body := range []string{`{"name":"Bad Name"}`, `{"name":"ok","scope":"root"}`, `{"name":"ok","extra":1}`} {
		if resp := f.do(t, http.MethodPost, "/api/v1/mcp/tokens", body, c); resp.StatusCode != http.StatusBadRequest {
			t.Errorf("create %s = %d, want 400", body, resp.StatusCode)
		}
	}
	resp := f.do(t, http.MethodPost, "/api/v1/mcp/tokens", `{"name":"claude","scope":"dangerous"}`, c)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create = %d %s", resp.StatusCode, resp.body)
	}
	created := decode[CreatedMCPTokenJSON](t, resp)
	if !strings.HasPrefix(created.Secret, "hearth_mcp_") || created.Scope != "dangerous" {
		t.Fatalf("created = %+v", created)
	}
	if tok, err := f.st.MCPTokens().Check(t.Context(), created.Secret); err != nil || tok.Name != "claude" {
		t.Fatalf("the token does not authenticate: %+v, %v", tok, err)
	}
	if resp := f.do(t, http.MethodPost, "/api/v1/mcp/tokens", `{"name":"claude"}`, c); resp.StatusCode != http.StatusConflict {
		t.Errorf("create of a taken name = %d, want 409", resp.StatusCode)
	}
	list := f.do(t, http.MethodGet, "/api/v1/mcp/tokens", "", c)
	if strings.Contains(string(list.body), created.Secret) {
		t.Fatal("the list holds the secret")
	}
	toks := decode[struct {
		Tokens []MCPTokenJSON `json:"tokens"`
	}](t, list).Tokens
	if len(toks) != 1 || toks[0].Name != "claude" || toks[0].RevokedAt != nil {
		t.Fatalf("tokens = %+v", toks)
	}
	if resp := f.do(t, http.MethodDelete, "/api/v1/mcp/tokens/claude", "", c); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("revoke = %d %s", resp.StatusCode, resp.body)
	}
	if resp := f.do(t, http.MethodDelete, "/api/v1/mcp/tokens/claude", "", c); resp.StatusCode != http.StatusNotFound {
		t.Errorf("revoke again = %d, want 404", resp.StatusCode)
	}
	if _, err := f.st.MCPTokens().Check(t.Context(), created.Secret); err == nil {
		t.Error("a revoked token still authenticates")
	}
	all, _ := f.st.Audit().List(t.Context(), 500)
	for _, e := range all {
		if strings.Contains(e.Result+e.Target+string(e.Detail), created.Secret) {
			t.Errorf("audit entry holds the secret: %+v", e)
		}
	}
	if strings.Contains(f.logs.String(), created.Secret) {
		t.Error("the logs hold the secret")
	}
}

// Changing the password needs the current one, refused and audited when it
// is wrong; it ends every session.
func TestWebChangePassword(t *testing.T) {
	const next = "a-brand-new-password"
	f := newWebAdminFixture(t, policy.Config{})
	c := sessionCookie(t, f.login(t, testPassword))
	other := sessionCookie(t, f.login(t, testPassword))
	body := func(current, newPw string) string {
		b, _ := json.Marshal(map[string]string{"current_password": current, "new_password": newPw})
		return string(b)
	}
	if resp := f.do(t, http.MethodPut, "/api/v1/admin/password", body(testPassword, "short"), c); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("a short password = %d, want 400", resp.StatusCode)
	}
	for _, current := range []string{"", "wrong-guess-77aa"} {
		resp := f.do(t, http.MethodPut, "/api/v1/admin/password", body(current, next), c)
		if resp.StatusCode != http.StatusForbidden || errorCode(t, resp) != "reauth_failed" {
			t.Errorf("change with current %q = %d %s, want 403 reauth_failed", current, resp.StatusCode, resp.body)
		}
	}
	if err := CheckAdminPassword(t.Context(), f.st, testPassword); err != nil {
		t.Fatalf("a refused change changed the password: %v", err)
	}
	resp := f.do(t, http.MethodPut, "/api/v1/admin/password", body(testPassword, next), c)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("change = %d %s", resp.StatusCode, resp.body)
	}
	if err := CheckAdminPassword(t.Context(), f.st, next); err != nil {
		t.Fatalf("the new password does not work: %v", err)
	}
	for _, s := range []*http.Cookie{c, other} {
		if resp := f.do(t, http.MethodGet, "/api/v1/session", "", s); resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("a session survived the change: %d", resp.StatusCode)
		}
	}
	entries := auditOf(t, f, policy.AdminSetPassword)
	web := 0
	for _, e := range entries {
		if e.ActorKind == policy.ActorWeb {
			web++
		}
		for _, pw := range []string{testPassword, next, "wrong-guess-77aa"} {
			if strings.Contains(e.Result+e.Target+string(e.Detail), pw) {
				t.Errorf("audit entry holds a password: %+v", e)
			}
		}
	}
	if web < 3 {
		t.Errorf("audited %d web password changes, want the two refusals and the change", web)
	}
	for _, pw := range []string{testPassword, next, "wrong-guess-77aa"} {
		if strings.Contains(f.logs.String(), pw) {
			t.Error("the logs hold a password")
		}
	}
}
