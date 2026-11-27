// SPDX-License-Identifier: AGPL-3.0-only

package unifi

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gvart/hearth/internal/integrations/unifi/unifimock"
)

// mode is one way of reaching a controller.
type mode struct {
	kind string
	key  bool
}

var modes = map[string]mode{
	"unifi os, api key":  {unifimock.UniFiOS, true},
	"unifi os, password": {unifimock.UniFiOS, false},
	"classic, password":  {unifimock.Classic, false},
}

// newMockServer serves mock over https and returns its URL and pinned
// fingerprint.
func newMockServer(t *testing.T, h http.Handler) (string, string) {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	sum := sha256.Sum256(srv.Certificate().Raw)
	return srv.URL, hex.EncodeToString(sum[:])
}

func mockConnection(m mode, url, fp string) Connection {
	c := Connection{URL: url, Kind: m.kind, Site: unifimock.Site, Fingerprint: fp}
	if m.key {
		c.APIKey = unifimock.APIKey
	} else {
		c.Username, c.Password = unifimock.Username, unifimock.Password
	}
	return c
}

func newMockClient(t *testing.T, m mode) (*client, *unifimock.Server) {
	t.Helper()
	mock := unifimock.New(m.kind)
	url, fp := newMockServer(t, mock)
	conn, err := mockConnection(m, url, fp).normalize()
	if err != nil {
		t.Fatal(err)
	}
	c, err := newClient(conn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.close)
	return c, mock
}

func TestReadsDevicesClientsAndHealth(t *testing.T) {
	for name, m := range modes {
		t.Run(name, func(t *testing.T) {
			c, mock := newMockClient(t, m)
			r, err := c.read(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			var names []string
			for _, d := range r.devices {
				names = append(names, d.Name+":"+d.Kind+":"+d.State)
			}
			if got := strings.Join(names, ","); got != "Dream Machine:gateway:connected,Rack switch:switch:connected,"+
				"Living room AP:access_point:connected,Office AP:access_point:disconnected" {
				t.Errorf("devices = %s", got)
			}
			if d := r.devices[0]; d.Model != "UDMPRO" || d.Version != "4.0.21.9965" || d.Uptime != 1728000 || d.Clients != 6 {
				t.Errorf("gateway = %+v", d)
			}
			byMAC := map[string]Client{}
			for _, cl := range r.clients {
				byMAC[cl.MAC] = cl
			}
			if len(byMAC) != 5 {
				t.Fatalf("clients = %+v", r.clients)
			}
			if p := byMAC["a4:5e:60:00:00:11"]; p.Wired || p.Hostname != "Ana's phone" || p.IP != "192.168.1.23" ||
				p.Uplink != "Living room AP" || p.SSID != "home" || p.Signal != -58 || p.Vendor != "Google" {
				t.Errorf("phone = %+v: want its alias, its AP and SSID", p)
			}
			if n := byMAC["2c:cf:67:00:00:10"]; !n.Wired || n.Uplink != "Rack switch" || n.Port != 3 || n.SSID != "" {
				t.Errorf("nas = %+v: want its switch and port", n)
			}
			if e := byMAC["de:ad:be:00:00:14"]; e.IP != "" || e.Wired {
				t.Errorf("client without address = %+v", e)
			}
			if r.clients[len(r.clients)-1].Hostname != "" {
				t.Errorf("clients without a name sort last: %+v", r.clients)
			}
			var wan Health
			for _, h := range r.health {
				if h.Subsystem == "wan" {
					wan = h
				}
			}
			if len(r.health) != 5 || wan.Status != "ok" || wan.WANIP != "203.0.113.7" || wan.ISP != "Example Fiber" || wan.RxRate != 2400000 {
				t.Errorf("health = %+v", r.health)
			}
			if len(r.missing) != 0 {
				t.Errorf("missing = %v", r.missing)
			}
			if _, err := c.read(t.Context()); err != nil {
				t.Fatal(err)
			}
			want := 1
			if m.key {
				want = 0
			}
			if mock.Logins() != want {
				t.Errorf("logins after two reads = %d, want %d", mock.Logins(), want)
			}
			for _, req := range mock.Requests() {
				if m.key && (req.APIKey != unifimock.APIKey || req.Session != "") {
					t.Errorf("an API key request carried %+v", req)
				}
				if !m.key && req.APIKey != "" {
					t.Errorf("a login request carried an API key: %+v", req)
				}
			}
		})
	}
}

func TestBadCredentials(t *testing.T) {
	for name, m := range modes {
		t.Run(name, func(t *testing.T) {
			c, mock := newMockClient(t, m)
			mock.SetPassword("another password")
			mock.SetAPIKey("another key")
			_, err := c.read(t.Context())
			if !errors.Is(err, ErrBadLogin) {
				t.Fatalf("read = %v, want ErrBadLogin", err)
			}
			if strings.Contains(err.Error(), unifimock.Password) || strings.Contains(err.Error(), unifimock.APIKey) {
				t.Errorf("the error quotes a credential: %v", err)
			}
			if n := len(mock.Requests()); n != 1 {
				t.Errorf("requests after a refused login = %d, want 1", n)
			}
		})
	}
}

func TestSessionExpiryLogsInAgain(t *testing.T) {
	for _, name := range []string{"unifi os, password", "classic, password"} {
		t.Run(name, func(t *testing.T) {
			c, mock := newMockClient(t, modes[name])
			if _, err := c.read(t.Context()); err != nil {
				t.Fatal(err)
			}
			mock.Expire()
			r, err := c.read(t.Context())
			if err != nil {
				t.Fatalf("read after the session expired = %v, want a new login", err)
			}
			if len(r.devices) != 4 || len(r.clients) != 5 {
				t.Errorf("read after re-login = %+v", r)
			}
			if mock.Logins() != 2 {
				t.Errorf("logins = %d, want 2", mock.Logins())
			}
		})
	}
}

func TestForbiddenEndpointIsNotRead(t *testing.T) {
	for name, m := range modes {
		t.Run(name, func(t *testing.T) {
			c, mock := newMockClient(t, m)
			mock.Deny("stat/health")
			for range 3 {
				r, err := c.read(t.Context())
				if err != nil {
					t.Fatalf("read = %v, want the health missing only", err)
				}
				if len(r.missing) != 1 || !strings.Contains(r.missing[0], "health") || !strings.Contains(r.missing[0], "403") {
					t.Errorf("missing = %v", r.missing)
				}
				if len(r.health) != 0 || len(r.devices) != 4 || len(r.clients) != 5 {
					t.Errorf("read = %+v", r)
				}
			}
			// A 403 is no expired session: it never logs in again.
			if m.key && mock.Logins() != 0 || !m.key && mock.Logins() != 1 {
				t.Errorf("logins = %d", mock.Logins())
			}
		})
	}
}

func TestRequiredReadForbidden(t *testing.T) {
	c, mock := newMockClient(t, modes["classic, password"])
	mock.Deny("stat/device")
	if _, err := c.read(t.Context()); !errors.Is(err, errForbidden) {
		t.Errorf("read = %v, want the devices refused", err)
	}
}

func TestUnknownSite(t *testing.T) {
	mock := unifimock.New(unifimock.Classic)
	url, fp := newMockServer(t, mock)
	conn := mockConnection(modes["classic, password"], url, fp)
	conn.Site = "attic"
	c, err := newClient(conn)
	if err != nil {
		t.Fatal(err)
	}
	defer c.close()
	if _, err := c.read(t.Context()); err == nil || !strings.Contains(err.Error(), `no site "attic"`) {
		t.Errorf("read = %v, want no site attic", err)
	}
}

func TestWrongKind(t *testing.T) {
	for name, tc := range map[string]struct{ serve, conn string }{
		"a classic controller adopted as unifi os": {unifimock.Classic, unifimock.UniFiOS},
		"a unifi os console adopted as classic":    {unifimock.UniFiOS, unifimock.Classic},
	} {
		t.Run(name, func(t *testing.T) {
			url, fp := newMockServer(t, unifimock.New(tc.serve))
			c, err := newClient(mockConnection(mode{kind: tc.conn}, url, fp))
			if err != nil {
				t.Fatal(err)
			}
			defer c.close()
			if _, err := c.read(t.Context()); err == nil || !strings.Contains(err.Error(), "?") {
				t.Errorf("read = %v, want a hint at the controller kind", err)
			}
		})
	}
}

func TestRestartNeedsCSRF(t *testing.T) {
	c, mock := newMockClient(t, modes["unifi os, password"])
	if _, err := c.read(t.Context()); err != nil {
		t.Fatal(err)
	}
	body := map[string]any{"cmd": "restart", "mac": "74:ac:b9:00:00:03"}
	if err := c.batch().call(t.Context(), http.MethodPost, "/cmd/devmgr", body, nil); err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	c.csrf = "stale"
	c.mu.Unlock()
	if err := c.batch().call(t.Context(), http.MethodPost, "/cmd/devmgr", body, nil); !errors.Is(err, errForbidden) {
		t.Errorf("a POST with a wrong CSRF token = %v, want refused", err)
	}
	if got := mock.Restarts(); len(got) != 1 {
		t.Errorf("restarts = %v, want 1", got)
	}
}

func TestPinnedFingerprint(t *testing.T) {
	mock := unifimock.New(unifimock.Classic)
	url, fp := newMockServer(t, mock)
	for name, tc := range map[string]struct {
		fp   string
		fail bool
	}{
		"pinned":       {fp, false},
		"other cert":   {strings.Repeat("ab", 32), true},
		"system roots": {"", true},
	} {
		t.Run(name, func(t *testing.T) {
			conn, err := mockConnection(modes["classic, password"], url, tc.fp).normalize()
			if err != nil {
				t.Fatal(err)
			}
			c, err := newClient(conn)
			if err != nil {
				t.Fatal(err)
			}
			defer c.close()
			_, err = c.read(t.Context())
			if (err != nil) != tc.fail {
				t.Errorf("read = %v, want failure %v", err, tc.fail)
			}
		})
	}
}

func TestNormalize(t *testing.T) {
	login := Connection{Kind: KindClassic, Username: "hearth", Password: "pw"}
	for _, tc := range []struct {
		url, fp, want string
		fail          bool
	}{
		{url: "https://192.168.1.1", want: "https://192.168.1.1:443"},
		{url: "https://unifi.lan:8443/manage/", want: "https://unifi.lan:8443"},
		{url: "https://[fd00::1]/network", want: "https://[fd00::1]:443"},
		{url: "http://192.168.1.1", fail: true},
		{url: "https://root:pw@192.168.1.1", fail: true}, //nolint:gosec // a URL that must be refused
		{url: "https://192.168.1.1/admin", fail: true},
		{url: "https://192.168.1.1", fp: "AB:CD", fail: true},
	} {
		c := login
		c.URL, c.Fingerprint = tc.url, tc.fp
		got, err := c.normalize()
		if (err != nil) != tc.fail || (err == nil && got.URL != tc.want) {
			t.Errorf("normalize(%q, %q) = %q, %v", tc.url, tc.fp, got.URL, err)
		}
		if err != nil && !errors.Is(err, ErrBadConnection) {
			t.Errorf("normalize(%q) error %v is no ErrBadConnection", tc.url, err)
		}
		if err == nil && got.Site != DefaultSite {
			t.Errorf("site = %q, want default", got.Site)
		}
	}
	u := "https://192.168.1.1"
	for name, c := range map[string]Connection{
		"no kind":                {URL: u, Username: "a", Password: "b"},
		"no username":            {URL: u, Kind: KindClassic, Password: "pw"},
		"username with a space":  {URL: u, Kind: KindClassic, Username: "a b", Password: "pw"},
		"no password":            {URL: u, Kind: KindClassic, Username: "root"},
		"api key on classic":     {URL: u, Kind: KindClassic, APIKey: "k"},
		"api key and a password": {URL: u, Kind: KindUniFiOS, APIKey: "k", Username: "a", Password: "b"},
		"site with a slash":      {URL: u, Kind: KindUniFiOS, APIKey: "k", Site: "a/../b"},
	} {
		if _, err := c.normalize(); !errors.Is(err, ErrBadConnection) {
			t.Errorf("%s: normalize = %v, want ErrBadConnection", name, err)
		}
	}
	if c, err := (Connection{URL: u, Kind: KindUniFiOS, APIKey: " key ", Site: "ab12cd34"}).normalize(); err != nil ||
		c.APIKey != "key" || c.Site != "ab12cd34" || c.authMode() != AuthAPIKey {
		t.Errorf("api key connection = %+v, %v", c, err)
	}
}
