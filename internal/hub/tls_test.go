// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"io"
	stdlog "log"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/gvart/hearth/internal/pki"
	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/proto/hearth/agent/v1/agentv1connect"
)

type tlsFixture struct {
	srv *httptest.Server
	ca  *pki.CA
	// browser trusts the CA and has no client certificate.
	browser *http.Client
	// device presents a CA-issued client certificate.
	device *http.Client
}

// newTLSFixture serves NewTLSHandler as the hub does on its TLS listener.
func newTLSFixture(t *testing.T) *tlsFixture {
	t.Helper()
	st := newTestStore(t)
	log := slog.New(slog.DiscardHandler)
	pol := policy.New(st.Audit())
	if err := setAdminPassword(t.Context(), st, pol, "test", testPassword, testArgon); err != nil {
		t.Fatal(err)
	}
	ca, err := pki.LoadOrCreateCA(t.TempDir(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	serverCert, err := ca.IssueServerCert([]string{"127.0.0.1"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{
		Store: st, CA: ca, Policy: pol, Log: log, HeartbeatInterval: time.Hour,
		Registry: NewRegistry(RegistryConfig{Store: st, Log: log}), AgentHosts: []string{"127.0.0.1"},
	}
	srv := httptest.NewUnstartedServer(NewTLSHandler(cfg, NewHTTPHandler(cfg)))
	srv.TLS = TLSConfig(ca, serverCert)
	srv.EnableHTTP2 = true
	srv.Config.ErrorLog = stdlog.New(io.Discard, "", 0)
	srv.StartTLS()
	t.Cleanup(srv.Close)

	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert())
	key, err := pki.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	csr, err := pki.NewCSR(key, "pi")
	if err != nil {
		t.Fatal(err)
	}
	devCert, err := ca.SignClientCSR(csr, "dev-1", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	client := func(certs ...tls.Certificate) *http.Client {
		tr := &http.Transport{
			TLSClientConfig:   &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, Certificates: certs},
			ForceAttemptHTTP2: true,
		}
		t.Cleanup(tr.CloseIdleConnections)
		return &http.Client{Transport: tr}
	}
	return &tlsFixture{
		srv: srv, ca: ca,
		browser: client(),
		device:  client(tls.Certificate{Certificate: [][]byte{devCert.Raw}, PrivateKey: key}),
	}
}

func (f *tlsFixture) do(t *testing.T, c *http.Client, method, path, body string, cookie *http.Cookie) apiResp {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), method, f.srv.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}
	resp, err := c.Do(req)
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

func (f *tlsFixture) login(t *testing.T) *http.Cookie {
	t.Helper()
	b, _ := json.Marshal(map[string]string{"password": testPassword})
	resp := f.do(t, f.browser, http.MethodPost, "/api/v1/login", string(b), nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login over TLS: status %d, body %s", resp.StatusCode, resp.body)
	}
	for _, c := range resp.Cookies() {
		if c.Name == SessionCookie {
			t.Errorf("login over TLS set the plain-HTTP cookie %s", SessionCookie)
		}
		if c.Name == SecureSessionCookie {
			return c
		}
	}
	t.Fatalf("no %s cookie in response", SecureSessionCookie)
	return nil
}

// TestTLSWebUIAndAPI: a browser with no client certificate gets the UI and,
// after logging in, the API over the agent TLS listener.
func TestTLSWebUIAndAPI(t *testing.T) {
	f := newTLSFixture(t)

	if resp := f.do(t, f.browser, http.MethodGet, "/", "", nil); resp.StatusCode != http.StatusOK ||
		!strings.HasPrefix(resp.Header.Get("Content-Type"), "text/html") {
		t.Fatalf("GET / over TLS: %d %s", resp.StatusCode, resp.Header.Get("Content-Type"))
	}

	c := f.login(t)
	if !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteStrictMode || c.Path != "/" || c.Domain != "" {
		t.Errorf("cookie = %+v, want Secure, HttpOnly, SameSite=Strict, Path=/, no Domain", c)
	}
	for _, path := range []string{"/api/v1/session", "/api/v1/devices"} {
		if resp := f.do(t, f.browser, http.MethodGet, path, "", c); resp.StatusCode != http.StatusOK {
			t.Errorf("GET %s with session: status %d, body %s", path, resp.StatusCode, resp.body)
		}
	}

	// The plain-HTTP cookie name carries no session over TLS.
	if resp := f.do(t, f.browser, http.MethodGet, "/api/v1/devices", "", testCookie(c.Value)); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("GET /devices with %s over TLS: status %d, want 401", SessionCookie, resp.StatusCode)
	}

	// Logout clears the Secure cookie.
	resp := f.do(t, f.browser, http.MethodPost, "/api/v1/logout", "", c)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("logout: status %d", resp.StatusCode)
	}
	var cleared bool
	for _, rc := range resp.Cookies() {
		if rc.Name == SecureSessionCookie && rc.MaxAge < 0 && rc.Secure {
			cleared = true
		}
	}
	if !cleared {
		t.Errorf("logout did not clear %s: %+v", SecureSessionCookie, resp.Cookies())
	}
	if resp := f.do(t, f.browser, http.MethodGet, "/api/v1/devices", "", c); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("after logout: status %d, want 401", resp.StatusCode)
	}
}

// TestTLSClientCertIsNotAdmin: a device's client certificate grants nothing
// on the UI and API routes.
func TestTLSClientCertIsNotAdmin(t *testing.T) {
	f := newTLSFixture(t)
	for _, ep := range []struct{ method, path string }{
		{http.MethodGet, "/api/v1/session"},
		{http.MethodGet, "/api/v1/devices"},
		{http.MethodGet, "/api/v1/events"},
		{http.MethodPost, "/api/v1/tokens"},
	} {
		resp := f.do(t, f.device, ep.method, ep.path, "", nil)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s %s with a client certificate: status %d, want 401", ep.method, ep.path, resp.StatusCode)
		}
	}
}

// TestTLSAgentServiceStillNeedsCert: serving the UI on the same listener does
// not open AgentService to clients without a certificate.
func TestTLSAgentServiceStillNeedsCert(t *testing.T) {
	f := newTLSFixture(t)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	stream := agentv1connect.NewAgentServiceClient(f.browser, f.srv.URL).Connect(ctx)
	_ = stream.Send(hello(ProtocolMajor))
	_, err := stream.Receive()
	if got := connect.CodeOf(err); got != connect.CodeUnauthenticated {
		t.Fatalf("AgentService without a client certificate: %v (%v), want unauthenticated", got, err)
	}
	_ = stream.CloseResponse()
}

// TestTLSInstallCommandUsesHTTP: a token made from the HTTPS origin still
// fetches install.sh from the plain-HTTP listener.
func TestTLSInstallCommandUsesHTTP(t *testing.T) {
	f := newTLSFixture(t)
	c := f.login(t)
	resp := f.do(t, f.browser, http.MethodPost, "/api/v1/tokens", `{}`, c)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d, body %s", resp.StatusCode, resp.body)
	}
	got := decode[TokenJSON](t, resp)
	want := "curl -fsSL http://127.0.0.1:" + DefaultHTTPPort + "/install.sh | HEARTH_TOKEN=" + got.Token +
		" sh -s -- --hub https://127.0.0.1:" + DefaultAgentPort
	if got.InstallCommand != want {
		t.Errorf("install_command = %q, want %q", got.InstallCommand, want)
	}
}

func TestTLSInfo(t *testing.T) {
	f := newTLSFixture(t)
	resp := f.do(t, f.browser, http.MethodGet, "/api/v1/tls", "", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	got := decode[TLSInfoJSON](t, resp)
	fp := pki.Fingerprint(f.ca.Cert())
	wantFP := strings.ToUpper(hex.EncodeToString(fp[:]))
	if got.Port != DefaultAgentPort || len(got.Hosts) != 1 || got.Hosts[0] != "127.0.0.1" ||
		strings.ReplaceAll(got.CAFingerprint, ":", "") != wantFP || len(got.CAFingerprint) != len(wantFP)*3/2-1 {
		t.Errorf("tls info = %+v, want fingerprint %s as colon-separated pairs", got, wantFP)
	}
}
