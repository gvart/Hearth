// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

const testPassword = "hunter2-but-longer"

type apiFixture struct {
	srv  *httptest.Server
	st   *store.Store
	logs *syncBuffer
}

func newAPIFixture(t *testing.T, withPassword bool) *apiFixture {
	t.Helper()
	st := newTestStore(t)
	logs := &syncBuffer{}
	log := slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	pol := policy.New(st.Audit())
	if withPassword {
		if err := setAdminPassword(t.Context(), st, pol, "test", testPassword, testArgon); err != nil {
			t.Fatal(err)
		}
	}
	a := newAPI(Config{Store: st, Policy: pol, Log: log, Registry: NewRegistry(RegistryConfig{Store: st, Log: log})})
	srv := httptest.NewServer(a.routes())
	t.Cleanup(srv.Close)
	return &apiFixture{srv: srv, st: st, logs: logs}
}

// apiResp is a fully read response, so tests never leak bodies.
type apiResp struct {
	StatusCode int
	Header     http.Header
	cookies    []*http.Cookie
	body       []byte
}

func (r apiResp) Cookies() []*http.Cookie { return r.cookies }

// testCookie is a request cookie; attributes only matter on responses.
func testCookie(value string) *http.Cookie {
	return &http.Cookie{Name: SessionCookie, Value: value} //nolint:gosec // request cookie: Secure/HttpOnly/SameSite are response attributes
}

func (f *apiFixture) do(t *testing.T, method, path, body string, cookie *http.Cookie) apiResp {
	t.Helper()
	return f.send(t, method, path, "application/json", body, cookie)
}

func (f *apiFixture) send(t *testing.T, method, path, contentType, body string, cookie *http.Cookie) apiResp {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), method, f.srv.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if body != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}
	resp, err := f.srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return apiResp{StatusCode: resp.StatusCode, Header: resp.Header, cookies: resp.Cookies(), body: b}
}

func (f *apiFixture) login(t *testing.T, password string) apiResp {
	t.Helper()
	b, _ := json.Marshal(map[string]string{"password": password})
	return f.do(t, http.MethodPost, "/api/v1/login", string(b), nil)
}

func sessionCookie(t *testing.T, resp apiResp) *http.Cookie {
	t.Helper()
	for _, c := range resp.Cookies() {
		if c.Name == SessionCookie {
			return c
		}
	}
	t.Fatalf("no %s cookie in response", SessionCookie)
	return nil
}

func decode[T any](t *testing.T, resp apiResp) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(resp.body, &v); err != nil {
		t.Fatalf("decode %T: %v", v, err)
	}
	return v
}

func TestAPIUnauthenticated(t *testing.T) {
	f := newAPIFixture(t, true)
	// An expired session: still in the store, past its expiry.
	now := time.Now()
	if err := f.st.Admin().CreateSession(t.Context(), "expired-secret", now.Add(-2*time.Hour), now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	cookies := map[string]*http.Cookie{
		"no cookie":       nil,
		"empty cookie":    testCookie(""),
		"unknown session": testCookie("made-up"),
		"expired session": testCookie("expired-secret"),
	}
	endpoints := []struct{ method, path string }{
		{http.MethodGet, "/api/v1/session"},
		{http.MethodPost, "/api/v1/logout"},
		{http.MethodGet, "/api/v1/devices"},
		{http.MethodGet, "/api/v1/devices/pi"},
		{http.MethodGet, "/api/v1/events"},
		{http.MethodGet, "/api/v1/no-such-endpoint"},
	}
	for name, c := range cookies {
		for _, ep := range endpoints {
			t.Run(name+" "+ep.method+" "+ep.path, func(t *testing.T) {
				resp := f.do(t, ep.method, ep.path, "", c)
				if resp.StatusCode != http.StatusUnauthorized {
					t.Fatalf("status = %d, want 401", resp.StatusCode)
				}
				if e := decode[ErrorJSON](t, resp); e.Code != "unauthenticated" {
					t.Errorf("error = %+v", e)
				}
			})
		}
	}
}

func TestAPILogin(t *testing.T) {
	tests := []struct {
		name         string
		withPassword bool
		contentType  string
		body         string
		wantStatus   int
		wantCode     string
		wantAudit    bool // the attempt reached policy
	}{
		{"right password", true, "application/json", `{"password":"` + testPassword + `"}`, http.StatusOK, "", true},
		{"wrong password", true, "application/json", `{"password":"nope-nope-nope"}`, http.StatusUnauthorized, "bad_credentials", true},
		{"empty password", true, "application/json", `{"password":""}`, http.StatusUnauthorized, "bad_credentials", true},
		{"password not set", false, "application/json", `{"password":"anything-at-all"}`, http.StatusServiceUnavailable, "password_not_set", true},
		{"not JSON", true, "application/json", `password=x`, http.StatusBadRequest, "bad_request", false},
		{"form content type", true, "application/x-www-form-urlencoded", `{"password":"x"}`, http.StatusUnsupportedMediaType, "bad_request", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newAPIFixture(t, tt.withPassword)
			resp := f.send(t, http.MethodPost, "/api/v1/login", tt.contentType, tt.body, nil)
			if resp.StatusCode != tt.wantStatus {
				t.Fatalf("status = %d, want %d", resp.StatusCode, tt.wantStatus)
			}
			if tt.wantCode != "" {
				if e := decode[ErrorJSON](t, resp); e.Code != tt.wantCode {
					t.Errorf("code = %q, want %q (%s)", e.Code, tt.wantCode, e.Error)
				}
				for _, c := range resp.Cookies() {
					if c.Name == SessionCookie {
						t.Error("failed login set a session cookie")
					}
				}
			} else {
				c := sessionCookie(t, resp)
				if !c.HttpOnly || c.SameSite != http.SameSiteStrictMode || c.Path != "/" {
					t.Errorf("cookie = %+v, want HttpOnly, SameSite=Strict, Path=/", c)
				}
				s := decode[SessionJSON](t, resp)
				if s.User != "admin" || time.Until(s.ExpiresAt) < SessionTTL-time.Minute {
					t.Errorf("session = %+v", s)
				}
			}

			entries, err := f.st.Audit().List(t.Context(), 10)
			if err != nil {
				t.Fatal(err)
			}
			var logins int
			for _, e := range entries {
				if e.Action == string(policy.AdminLogin) {
					logins++
					if e.ActorKind != policy.ActorWeb || e.ActorID != "127.0.0.1" {
						t.Errorf("audit actor = %s/%s", e.ActorKind, e.ActorID)
					}
				}
			}
			if want := map[bool]int{true: 1, false: 0}[tt.wantAudit]; logins != want {
				t.Errorf("admin.login audit entries = %d, want %d", logins, want)
			}
		})
	}
}

func TestAPISessionLifecycle(t *testing.T) {
	f := newAPIFixture(t, true)
	enrollDevice(t, f.st, "pi")
	c := sessionCookie(t, f.login(t, testPassword))

	if resp := f.do(t, http.MethodGet, "/api/v1/session", "", c); resp.StatusCode != http.StatusOK {
		t.Fatalf("session: status %d", resp.StatusCode)
	} else if s := decode[SessionJSON](t, resp); s.User != "admin" || s.ExpiresAt.IsZero() {
		t.Errorf("session = %+v", s)
	}

	resp := f.do(t, http.MethodGet, "/api/v1/devices", "", c)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("devices: status %d", resp.StatusCode)
	}
	list := decode[struct {
		Devices []DeviceJSON `json:"devices"`
	}](t, resp)
	if len(list.Devices) != 1 || list.Devices[0].ID != "pi" || list.Devices[0].Labels["room"] != "attic" ||
		list.Devices[0].Status != store.StatusUnknown || string(list.Devices[0].Facts) != "{}" {
		t.Fatalf("devices = %+v", list.Devices)
	}

	if resp := f.do(t, http.MethodGet, "/api/v1/devices/pi", "", c); resp.StatusCode != http.StatusOK {
		t.Fatalf("device: status %d", resp.StatusCode)
	} else if d := decode[DeviceJSON](t, resp); d.ID != "pi" || d.Name != "pi-name" {
		t.Errorf("device = %+v", d)
	}
	if resp := f.do(t, http.MethodGet, "/api/v1/devices/ghost", "", c); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("missing device: status %d, want 404", resp.StatusCode)
	}

	resp = f.do(t, http.MethodPost, "/api/v1/logout", "", c)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("logout: status %d", resp.StatusCode)
	}
	if cleared := sessionCookie(t, resp); cleared.MaxAge >= 0 {
		t.Errorf("logout cookie = %+v, want MaxAge < 0", cleared)
	}
	if resp := f.do(t, http.MethodGet, "/api/v1/devices", "", c); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("after logout: status %d, want 401", resp.StatusCode)
	}
}

func TestAPISessionEndsOnPasswordReset(t *testing.T) {
	f := newAPIFixture(t, true)
	c := sessionCookie(t, f.login(t, testPassword))
	if err := setAdminPassword(t.Context(), f.st, policy.New(f.st.Audit()), "test", "a-new-password", testArgon); err != nil {
		t.Fatal(err)
	}
	if resp := f.do(t, http.MethodGet, "/api/v1/session", "", c); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status %d, want 401", resp.StatusCode)
	}
	if resp := f.login(t, testPassword); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("old password: status %d, want 401", resp.StatusCode)
	}
}

func TestAPISessionExpires(t *testing.T) {
	f := newAPIFixture(t, true)
	c := sessionCookie(t, f.login(t, testPassword))
	// Forge the same session's expiry into the past by re-creating it.
	now := time.Now()
	if err := f.st.Admin().DeleteSession(t.Context(), c.Value); err != nil {
		t.Fatal(err)
	}
	if err := f.st.Admin().CreateSession(t.Context(), c.Value, now.Add(-SessionTTL), now.Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if resp := f.do(t, http.MethodGet, "/api/v1/devices", "", c); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expired session: status %d, want 401", resp.StatusCode)
	}
}

func TestAPINeverLogsSecrets(t *testing.T) {
	f := newAPIFixture(t, true)
	f.login(t, "wrong-password-xyz")
	resp := f.login(t, testPassword)
	c := sessionCookie(t, resp)
	f.do(t, http.MethodGet, "/api/v1/devices", "", c)
	f.do(t, http.MethodPost, "/api/v1/logout", "", c)

	logs := f.logs.String()
	if !strings.Contains(logs, "admin login failed") || !strings.Contains(logs, "admin logged in") {
		t.Fatalf("expected login log lines, got:\n%s", logs)
	}
	entries, err := f.st.Audit().List(t.Context(), 100)
	if err != nil {
		t.Fatal(err)
	}
	var audit strings.Builder
	for _, e := range entries {
		audit.WriteString(e.ActorID + e.Target + e.Result + string(e.Detail))
	}
	for _, secret := range []string{testPassword, "wrong-password-xyz", c.Value} {
		if strings.Contains(logs, secret) {
			t.Errorf("secret %q found in logs:\n%s", secret, logs)
		}
		if strings.Contains(audit.String(), secret) {
			t.Errorf("secret %q found in audit log", secret)
		}
	}
}

func TestAPIServesWebUI(t *testing.T) {
	f := newAPIFixture(t, false)
	resp := f.do(t, http.MethodGet, "/", "", nil)
	if resp.StatusCode != http.StatusOK || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/html") {
		t.Fatalf("GET / = %d %s", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	if !strings.Contains(string(resp.body), "Hearth") {
		t.Errorf("body = %s", resp.body)
	}
}
