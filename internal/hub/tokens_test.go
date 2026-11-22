// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/pki"
	"github.com/gvart/hearth/internal/policy"
)

// TestAPICreateTokenPinsHubVersion: a release hub's install command fetches
// install.sh of its own release tag from GitHub over HTTPS and pins the agent
// to that release, so the installer never has to look up a "latest" release
// (GitHub reports none while every release is a pre-release). A dev hub
// serves its own script and pins nothing. Neither names the hub: the token
// does.
func TestAPICreateTokenPinsHubVersion(t *testing.T) {
	for _, tc := range []struct {
		version string
		want    func(token string) string
	}{
		{"v0.0.1-rc.5", func(tok string) string {
			return "curl -fsSL https://raw.githubusercontent.com/gvart/Hearth/v0.0.1-rc.5/deploy/install.sh | HEARTH_TOKEN=" + tok +
				" sh -s -- --version v0.0.1-rc.5"
		}},
		{"v1.2.3", func(tok string) string {
			return "curl -fsSL https://raw.githubusercontent.com/gvart/Hearth/v1.2.3/deploy/install.sh | HEARTH_TOKEN=" + tok +
				" sh -s -- --version v1.2.3"
		}},
		{"dev", func(tok string) string {
			return "curl -fsSL http://hub.lan:7080/install.sh | HEARTH_TOKEN=" + tok + " sh"
		}},
		{"v0.0.2-snapshot", func(tok string) string {
			return "curl -fsSL http://hub.lan:7080/install.sh | HEARTH_TOKEN=" + tok + " sh"
		}},
	} {
		t.Run(tc.version, func(t *testing.T) {
			f := newAPIFixture(t, true, func(c *Config) { c.Version = tc.version })
			c := sessionCookie(t, f.login(t, testPassword))
			resp := f.do(t, http.MethodPost, "/api/v1/tokens", `{}`, c)
			if resp.StatusCode != http.StatusCreated {
				t.Fatalf("status = %d, body %s", resp.StatusCode, resp.body)
			}
			got := decode[TokenJSON](t, resp)
			if want := tc.want(got.Token); got.InstallCommand != want {
				t.Errorf("install_command = %q, want %q", got.InstallCommand, want)
			}
			if !strings.HasPrefix(got.Token, "hearth2.") {
				t.Errorf("token %q does not name its hub", got.Token)
			}
		})
	}
}

func TestReleaseVersion(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"v0.0.1-rc.5", "v0.0.1-rc.5"},
		{"v1.2.3", "v1.2.3"},
		{"v10.0.0-beta.2.x", "v10.0.0-beta.2.x"},
		{"v0.0.0-e2e", "v0.0.0-e2e"},
		{"", ""},
		{"dev", ""},
		{"0.0.1", ""},                                // goreleaser links in the v prefix
		{"v0.0.2-snapshot", ""},                      // `task release:snapshot`: never released
		{"v0.0.0-20250101000000-abcdef123456", ""},   // Go pseudo-version
		{"v1.2.4-0.20250101000000-abcdef123456", ""}, // Go pseudo-version after a tag
		{"v1.2.3+dirty", ""},                         // build metadata
		{"v1.2.3; rm -rf /", ""},                     // never anything a shell interprets
		{"v1.2.3\n", ""},                             // trailing newline
		{"v01.2.3", ""},                              // leading zero
	} {
		if got := releaseVersion(tc.in); got != tc.want {
			t.Errorf("releaseVersion(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestAPICreateToken(t *testing.T) {
	f := newAPIFixture(t, true)
	c := sessionCookie(t, f.login(t, testPassword))

	start := time.Now()
	resp := f.do(t, http.MethodPost, "/api/v1/tokens", `{"ttl":"30m","labels":{"room":"attic"}}`, c)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d, body %s", resp.StatusCode, resp.body)
	}
	got := decode[TokenJSON](t, resp)
	tok, err := pki.ParseToken(got.Token)
	if err != nil {
		t.Fatalf("parse token: %v", err)
	}
	if d := got.ExpiresAt.Sub(start); d < 29*time.Minute || d > 31*time.Minute {
		t.Errorf("expires_at %s is %s from now, want ~30m", got.ExpiresAt, d)
	}
	// The fixture serves on 127.0.0.1, which means nothing on a device:
	// the commands use the certificate name hub.lan instead.
	wantInstall := "curl -fsSL http://hub.lan:7080/install.sh | HEARTH_TOKEN=" + got.Token + " sh"
	if got.InstallCommand != wantInstall {
		t.Errorf("install_command = %q, want %q", got.InstallCommand, wantInstall)
	}
	// The token, not the commands, names the hub, at a certificate name.
	if tok.HubURL != "https://hub.lan:7443" {
		t.Errorf("token names hub %q, want https://hub.lan:7443", tok.HubURL)
	}
	// Everything after `| HEARTH_TOKEN=<token> sh` lands in the argv of the
	// user's sh, which any local user can read with ps: the token must not
	// be there.
	_, args, ok := strings.Cut(got.InstallCommand, got.Token+" sh")
	if !ok || strings.Contains(args, got.Token) || strings.Contains(args, "--token") {
		t.Errorf("install_command %q passes the token in the argv of sh", got.InstallCommand)
	}
	if want := "HEARTH_TOKEN=" + got.Token + " hearth agent join"; got.JoinCommand != want {
		t.Errorf("join_command = %q, want %q", got.JoinCommand, want)
	}
	// Likewise the argv of hearth: the token is only in its environment.
	_, args, ok = strings.Cut(got.JoinCommand, " hearth ")
	if !ok || strings.Contains(args, got.Token) {
		t.Errorf("join_command %q passes the token in the argv of hearth", got.JoinCommand)
	}

	// The token is stored, single use, and carries the labels.
	consumed, err := f.st.Tokens().Consume(t.Context(), tok.Secret, time.Now())
	if err != nil || consumed.Labels["room"] != "attic" || consumed.Name != "" {
		t.Fatalf("consume = %+v, %v", consumed, err)
	}
	if _, err := f.st.Tokens().Consume(t.Context(), tok.Secret, time.Now()); err == nil {
		t.Error("token consumed twice")
	}

	entries, err := f.st.Audit().List(t.Context(), 10)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, e := range entries {
		if e.Action != string(policy.TokenCreate) {
			continue
		}
		found = true
		if e.ActorKind != policy.ActorWeb || e.ActorID != "127.0.0.1" || e.Decision != policy.Allow || e.Result != "ok" {
			t.Errorf("audit = %+v", e)
		}
		var detail map[string]any
		if err := json.Unmarshal(e.Detail, &detail); err != nil || detail["ttl"] != "30m0s" {
			t.Errorf("audit detail = %s (%v)", e.Detail, err)
		}
		if strings.Contains(string(e.Detail), tok.Secret) {
			t.Error("token secret in audit detail")
		}
	}
	if !found {
		t.Error("no token.create audit entry")
	}
	if logs := f.logs.String(); strings.Contains(logs, tok.Secret) {
		t.Errorf("token secret in logs:\n%s", logs)
	}
}

// A name, trimmed, is stored with the token and audited.
func TestAPICreateNamedToken(t *testing.T) {
	f := newAPIFixture(t, true)
	c := sessionCookie(t, f.login(t, testPassword))
	resp := f.do(t, http.MethodPost, "/api/v1/tokens", `{"name":"  garage-pi "}`, c)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d, body %s", resp.StatusCode, resp.body)
	}
	tok, err := pki.ParseToken(decode[TokenJSON](t, resp).Token)
	if err != nil {
		t.Fatal(err)
	}
	got, err := f.st.Tokens().Consume(t.Context(), tok.Secret, time.Now())
	if err != nil || got.Name != "garage-pi" {
		t.Fatalf("consume = %+v, %v; want the name garage-pi", got, err)
	}
	entries, err := f.st.Audit().List(t.Context(), 10)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Action == string(policy.TokenCreate) && !strings.Contains(string(e.Detail), `"name":"garage-pi"`) {
			t.Errorf("audit detail %s lacks the name", e.Detail)
		}
	}
}

func TestDeviceName(t *testing.T) {
	tests := []struct {
		in, want string
		ok       bool
	}{
		{"", "", true},
		{"garage-pi", "garage-pi", true},
		{" Pi4.lan ", "Pi4.lan", true},
		{"nas_01", "nas_01", true},
		{strings.Repeat("a", 63), strings.Repeat("a", 63), true},
		{strings.Repeat("a", 64), "", false},
		{"   ", "", false},
		{"-pi", "", false},
		{".pi", "", false},
		{"garage pi", "", false},
		{"pi;rm -rf", "", false},
		{"pi$(id)", "", false},
		{"pï", "", false},
	}
	for _, tt := range tests {
		got, err := DeviceName(tt.in)
		if (err == nil) != tt.ok || got != tt.want {
			t.Errorf("DeviceName(%q) = %q, %v; want %q, ok %v", tt.in, got, err, tt.want, tt.ok)
		}
	}
}

func TestAPICreateTokenDefaults(t *testing.T) {
	f := newAPIFixture(t, true)
	c := sessionCookie(t, f.login(t, testPassword))
	for _, body := range []string{`{}`, `{"ttl":""}`} {
		start := time.Now()
		resp := f.do(t, http.MethodPost, "/api/v1/tokens", body, c)
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("%s: status = %d, body %s", body, resp.StatusCode, resp.body)
		}
		if d := decode[TokenJSON](t, resp).ExpiresAt.Sub(start); d < 14*time.Minute || d > 16*time.Minute {
			t.Errorf("%s: default ttl = %s, want ~15m", body, d)
		}
	}
}

func TestAPICreateTokenRejects(t *testing.T) {
	f := newAPIFixture(t, true)
	c := sessionCookie(t, f.login(t, testPassword))
	manyLabels := map[string]string{}
	for i := range maxTokenLabels + 1 {
		manyLabels[strings.Repeat("k", i+1)] = "v"
	}
	tooMany, _ := json.Marshal(map[string]any{"labels": manyLabels})

	tests := []struct {
		name, contentType, body string
		wantStatus              int
	}{
		{"form content type", "application/x-www-form-urlencoded", `{}`, http.StatusUnsupportedMediaType},
		{"no body or content type", "application/json", ``, http.StatusUnsupportedMediaType},
		{"empty JSON body", "application/json", ` `, http.StatusBadRequest},
		{"not JSON", "application/json", `ttl=15m`, http.StatusBadRequest},
		{"unknown field", "application/json", `{"ttl":"15m","admin":true}`, http.StatusBadRequest},
		{"ttl not a duration", "application/json", `{"ttl":"soon"}`, http.StatusBadRequest},
		{"ttl a number", "application/json", `{"ttl":900}`, http.StatusBadRequest},
		{"ttl zero", "application/json", `{"ttl":"0s"}`, http.StatusBadRequest},
		{"ttl negative", "application/json", `{"ttl":"-5m"}`, http.StatusBadRequest},
		{"ttl too long", "application/json", `{"ttl":"25h"}`, http.StatusBadRequest},
		{"empty label key", "application/json", `{"labels":{"":"x"}}`, http.StatusBadRequest},
		{"label value too long", "application/json", `{"labels":{"k":"` + strings.Repeat("v", 129) + `"}}`, http.StatusBadRequest},
		{"too many labels", "application/json", string(tooMany), http.StatusBadRequest},
		{"name blank", "application/json", `{"name":"  "}`, http.StatusBadRequest},
		{"name too long", "application/json", `{"name":"` + strings.Repeat("a", 64) + `"}`, http.StatusBadRequest},
		{"name with a space", "application/json", `{"name":"garage pi"}`, http.StatusBadRequest},
		{"name with shell characters", "application/json", `{"name":"pi;reboot"}`, http.StatusBadRequest},
		{"name not a string", "application/json", `{"name":7}`, http.StatusBadRequest},
		{"body too large", "application/json", `{"ttl":"` + strings.Repeat(" ", maxTokenBody) + `"}`, http.StatusBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := f.send(t, http.MethodPost, "/api/v1/tokens", tt.contentType, tt.body, c)
			if resp.StatusCode != tt.wantStatus {
				t.Fatalf("status = %d, want %d (%s)", resp.StatusCode, tt.wantStatus, resp.body)
			}
			if e := decode[ErrorJSON](t, resp); e.Code != "bad_request" {
				t.Errorf("error = %+v", e)
			}
		})
	}
	// Nothing reached policy, so nothing was created or audited.
	entries, err := f.st.Audit().List(t.Context(), 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Action == string(policy.TokenCreate) {
			t.Errorf("rejected request audited: %+v", e)
		}
	}
}

func TestCommandHosts(t *testing.T) {
	a := &api{agentHosts: []string{"localhost", "hub.lan", "127.0.0.1", "::1"}, httpPort: "7080"}
	tests := []struct {
		reqHost             string
		overTLS             bool
		wantHTTP, wantAgent string
		ok                  bool
	}{
		{"hub.lan:7080", false, "hub.lan:7080", "hub.lan", true},
		{"HUB.lan:7080", false, "HUB.lan:7080", "HUB.lan", true},
		{"hub.lan", false, "hub.lan", "hub.lan", true},
		// Loopback means nothing on another device, certificate name or
		// not: both URLs use the first certificate name that is not
		// loopback, at the HTTP listener's port (the browser may come
		// through a port forward or the Vite dev server).
		{"localhost", false, "hub.lan:7080", "hub.lan", true},
		{"localhost:5173", false, "hub.lan:7080", "hub.lan", true},
		{"LOCALHOST:7080", false, "hub.lan:7080", "hub.lan", true},
		{"app.localhost:7080", false, "hub.lan:7080", "hub.lan", true},
		{"127.0.0.1:7080", false, "hub.lan:7080", "hub.lan", true},
		{"127.1.2.3:7080", false, "hub.lan:7080", "hub.lan", true},
		{"[::1]:7080", false, "hub.lan:7080", "hub.lan", true},
		{"[::1]:7443", true, "hub.lan:7080", "hub.lan", true},
		// Not in the certificate: agents would fail to verify it.
		{"192.168.1.20:7080", false, "hub.lan:7080", "hub.lan", true},
		{"nas.example.com", false, "hub.lan:7080", "hub.lan", true},
		// Over HTTPS the install script still comes from the HTTP listener:
		// curl on a new device does not trust the hub CA yet.
		{"hub.lan:7443", true, "hub.lan:7080", "hub.lan", true},
		{"hub.lan", true, "hub.lan:7080", "hub.lan", true},
		{"192.168.1.20:7443", true, "hub.lan:7080", "hub.lan", true},
		{"", false, "", "", false},
		{"evil;rm -rf /:7080", false, "", "", false},
		{"$(id).lan:7080", false, "", "", false},
		{"$(id).lan:7443", true, "", "", false},
		{"hub.lan:70x0", false, "", "", false},
		{"hub.lan:0", false, "", "", false},
		{"hub.lan:99999", false, "", "", false},
		{"hub.lan:07080", false, "", "", false},
	}
	for _, tt := range tests {
		name := tt.reqHost
		if tt.overTLS {
			name = "https " + name
		}
		t.Run(name, func(t *testing.T) {
			httpHost, agentHost, ok := a.commandHosts(tt.reqHost, tt.overTLS)
			if ok != tt.ok || httpHost != tt.wantHTTP || agentHost != tt.wantAgent {
				t.Errorf("commandHosts(%q, %v) = %q, %q, %v; want %q, %q, %v",
					tt.reqHost, tt.overTLS, httpHost, agentHost, ok, tt.wantHTTP, tt.wantAgent, tt.ok)
			}
		})
	}
}

// TestCommandHostsLANAddress: with a bare hub's certificate (LAN addresses
// before a bare hostname) the commands name a LAN address, unless the
// browser came by a name other devices resolve or by another certificate
// address. An explicit --host list keeps its order.
func TestCommandHostsLANAddress(t *testing.T) {
	bare := []string{"192.168.2.124", "10.0.5.2", "DNP6J4RC7Q", "localhost", "127.0.0.1", "::1"}
	for _, tc := range []struct {
		hosts              []string
		reqHost, wantAgent string
	}{
		{bare, "localhost:7080", "192.168.2.124"},
		{bare, "127.0.0.1:7080", "192.168.2.124"},
		{bare, "DNP6J4RC7Q:7080", "192.168.2.124"},
		{bare, "dnp6j4rc7q:7080", "192.168.2.124"},
		{bare, "10.0.5.2:7080", "10.0.5.2"},
		{bare, "192.168.2.124:7080", "192.168.2.124"},
		{bare, "192.168.9.9:7080", "192.168.2.124"},
		{[]string{"192.168.2.124", "mac.local", "localhost"}, "mac.local:7080", "192.168.2.124"},
		{[]string{"hub.home.arpa", "192.168.2.124", "localhost"}, "localhost:7080", "hub.home.arpa"},
		{[]string{"hub.home.arpa", "192.168.2.124", "localhost"}, "hub.home.arpa:7080", "hub.home.arpa"},
		// --host hub (the e2e compose): a bare name first stays first.
		{[]string{"hub"}, "localhost:7080", "hub"},
		{[]string{"hub"}, "hub:7080", "hub"},
		{[]string{"pi", "192.168.2.131"}, "pi:7080", "pi"},
		{[]string{"pi", "192.168.2.131"}, "localhost:7080", "pi"},
		// hearth.local is answered by one master only: never in a command.
		{[]string{"192.168.2.124", "DNP6J4RC7Q", "localhost", "hearth.local"}, "hearth.local:7080", "192.168.2.124"},
		{[]string{"hub.home.arpa", "192.168.2.124", "localhost", "hearth.local"}, "hearth.local:7080", "hub.home.arpa"},
		{[]string{"nas.lan", "hearth.local"}, "HEARTH.local.:7080", "nas.lan"},
		{[]string{"hub", "hearth.local"}, "hearth.local:7080", "hub"},
		// Nor picked over a later name when the first names are loopback.
		{[]string{"127.0.0.1", "hearth.local", "hub.lan"}, "127.0.0.1:7080", "hub.lan"},
	} {
		a := &api{agentHosts: tc.hosts, httpPort: "7080"}
		httpHost, agentHost, ok := a.commandHosts(tc.reqHost, false)
		if !ok || agentHost != tc.wantAgent || httpHost != net.JoinHostPort(tc.wantAgent, "7080") {
			t.Errorf("hosts %v: commandHosts(%q) = %q, %q, %v; want agent host %q", tc.hosts, tc.reqHost, httpHost, agentHost, ok, tc.wantAgent)
		}
	}
}

func TestBareHostname(t *testing.T) {
	for h, want := range map[string]bool{
		"DNP6J4RC7Q": true, "pi": true, "pi.": true, "mac.local": true, "MAC.LOCAL.": true,
		"hub.lan": false, "hub.home.arpa": false, "192.168.2.124": false, "fd00::10": false, "": false,
	} {
		if got := BareHostname(h); got != want {
			t.Errorf("BareHostname(%q) = %v, want %v", h, got, want)
		}
	}
}

// TestCommandHostsIPv6AndNoChoice brackets an IPv6 certificate name in the
// script URL, and keeps the browser's host when the certificate names only
// loopback addresses (or nothing): no choice works then.
func TestCommandHostsIPv6AndNoChoice(t *testing.T) {
	for _, tc := range []struct {
		hosts                        []string
		reqHost, wantHTTP, wantAgent string
	}{
		{[]string{"::1", "fd00::10"}, "[::1]:7080", "[fd00::10]:7080", "fd00::10"},
		{[]string{"fd00::10"}, "[fd00::10]:7080", "[fd00::10]:7080", "fd00::10"},
		{[]string{"localhost", "127.0.0.1"}, "localhost:7080", "localhost:7080", "localhost"},
		{nil, "localhost:7080", "localhost:7080", "localhost"},
	} {
		a := &api{agentHosts: tc.hosts, httpPort: "7080"}
		httpHost, agentHost, ok := a.commandHosts(tc.reqHost, false)
		if !ok || httpHost != tc.wantHTTP || agentHost != tc.wantAgent {
			t.Errorf("hosts %v: commandHosts(%q) = %q, %q, %v; want %q, %q", tc.hosts, tc.reqHost, httpHost, agentHost, ok, tc.wantHTTP, tc.wantAgent)
		}
	}
}

// TestAPICreateTokenFromLoopback: a browser on the hub machine at localhost
// gets commands a device can use: no loopback address in the script URL or
// in the token, and no --hub.
func TestAPICreateTokenFromLoopback(t *testing.T) {
	f := newAPIFixture(t, true, func(c *Config) { c.AgentHosts = []string{"localhost", "hub.lan", "127.0.0.1", "::1"} })
	c := sessionCookie(t, f.login(t, testPassword))
	for _, host := range []string{"localhost:7080", "127.0.0.1:7080", "[::1]:7080"} {
		t.Run(host, func(t *testing.T) {
			req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, f.srv.URL+"/api/v1/tokens", strings.NewReader(`{}`))
			if err != nil {
				t.Fatal(err)
			}
			req.Host = host
			req.Header.Set("Content-Type", "application/json")
			req.AddCookie(c)
			resp, err := f.srv.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			var got TokenJSON
			if resp.StatusCode != http.StatusCreated {
				t.Fatalf("status = %d", resp.StatusCode)
			}
			if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
				t.Fatal(err)
			}
			tok, err := pki.ParseToken(got.Token)
			if err != nil {
				t.Fatal(err)
			}
			if tok.HubURL != "https://hub.lan:7443" {
				t.Errorf("token names hub %q, want https://hub.lan:7443", tok.HubURL)
			}
			if want := "curl -fsSL http://hub.lan:7080/install.sh | HEARTH_TOKEN=" + got.Token + " sh"; got.InstallCommand != want {
				t.Errorf("install_command = %q, want %q", got.InstallCommand, want)
			}
			if want := "HEARTH_TOKEN=" + got.Token + " hearth agent join"; got.JoinCommand != want {
				t.Errorf("join_command = %q, want %q", got.JoinCommand, want)
			}
			for _, cmd := range []string{got.InstallCommand, got.JoinCommand} {
				for _, bad := range []string{"localhost", "127.0.0.1", "::1", "--hub"} {
					if strings.Contains(cmd, bad) {
						t.Errorf("command %q contains %q", cmd, bad)
					}
				}
			}
		})
	}
}
