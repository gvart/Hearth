// SPDX-License-Identifier: AGPL-3.0-only

package openwrt

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gvart/hearth/internal/integrations/openwrt/openwrtmock"
)

func newMockClient(t *testing.T) (*client, *openwrtmock.Server) {
	t.Helper()
	mock := openwrtmock.New(openwrtmock.Username, openwrtmock.Password)
	srv := httptest.NewServer(mock)
	t.Cleanup(srv.Close)
	c, err := newClient(Connection{URL: srv.URL, Username: openwrtmock.Username, Password: openwrtmock.Password})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.close)
	return c, mock
}

func TestReadsSystemInterfacesAndClients(t *testing.T) {
	c, mock := newMockClient(t)
	r, err := c.read(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	sys := r.system
	if sys.Hostname != "gateway" || sys.Model != "GL.iNet GL-MT6000" || sys.Release != "OpenWrt 24.10.0 r28427-6df0e3d02a" ||
		sys.Target != "mediatek/filogic" || sys.Uptime != 864000 || sys.Load != [3]float64{0.3, 0.2, 0.1} ||
		sys.MemTotal != 1031000064 || sys.MemAvailable != 780000000 {
		t.Errorf("system = %+v", sys)
	}
	var names []string
	for _, i := range r.interfaces {
		names = append(names, i.Name)
	}
	if strings.Join(names, ",") != "br-lan,eth1,lan2,phy0-ap0" {
		t.Errorf("interfaces = %v, want loopback left out", names)
	}
	if eth := r.interfaces[1]; eth.RxBytes != 912000000000 || eth.TxBytes != 81000000000 || !eth.Up || eth.MAC != "94:83:c4:00:00:10" {
		t.Errorf("eth1 = %+v", eth)
	}
	byMAC := map[string]Client{}
	for _, cl := range r.clients {
		byMAC[cl.MAC] = cl
	}
	if len(byMAC) != 5 {
		t.Fatalf("clients = %+v, want 4 leases and 1 wireless-only client", r.clients)
	}
	phone := byMAC["a4:5e:60:00:00:02"]
	if !phone.Lease || !phone.Wireless || phone.IP != "192.168.1.23" || phone.Hostname != "pixel-8" ||
		phone.Radio != "phy0-ap0" || phone.Signal != -62 || phone.Inactive != 1200 {
		t.Errorf("phone = %+v: want its lease and its association merged, signal -62 dBm", phone)
	}
	if odd := byMAC["de:ad:be:00:00:04"]; odd.Hostname != "" || odd.IP != "192.168.1.77" {
		t.Errorf("client without a name = %+v, want dnsmasq's * dropped", odd)
	}
	if w := byMAC["f0:99:b6:00:00:05"]; !w.Wireless || w.Lease || w.IP != "" || w.Signal != -71 {
		t.Errorf("wireless-only client = %+v", w)
	}
	if p := byMAC["00:1b:a9:00:00:03"]; !p.Lease || p.LeaseExpires != 0 {
		t.Errorf("static lease = %+v", p)
	}
	if r.clients[len(r.clients)-1].Hostname != "" {
		t.Errorf("clients without a name sort last: %+v", r.clients)
	}
	if len(r.missing) != 0 {
		t.Errorf("missing = %v, want none", r.missing)
	}
	if mock.Logins() != 1 {
		t.Errorf("logins = %d, want 1", mock.Logins())
	}
	if _, err := c.read(t.Context()); err != nil {
		t.Fatal(err)
	}
	if mock.Logins() != 1 {
		t.Errorf("logins after a second read = %d, want the session reused", mock.Logins())
	}
}

func TestBadCredentials(t *testing.T) {
	c, mock := newMockClient(t)
	mock.SetPassword("another password")
	_, err := c.read(t.Context())
	if !errors.Is(err, ErrBadLogin) {
		t.Fatalf("read = %v, want ErrBadLogin", err)
	}
	if strings.Contains(err.Error(), openwrtmock.Password) {
		t.Errorf("the error quotes the password: %v", err)
	}
	for _, call := range mock.Calls() {
		if call.Object != "session" {
			t.Errorf("a call after a refused login: %+v", call)
		}
	}
}

func TestSessionExpiryLogsInAgain(t *testing.T) {
	c, mock := newMockClient(t)
	if _, err := c.read(t.Context()); err != nil {
		t.Fatal(err)
	}
	mock.Expire()
	r, err := c.read(t.Context())
	if err != nil {
		t.Fatalf("read after the session expired = %v, want a new login", err)
	}
	if len(r.clients) == 0 || len(r.missing) != 0 {
		t.Errorf("read after re-login = %+v", r)
	}
	if mock.Logins() != 2 {
		t.Errorf("logins = %d, want 2", mock.Logins())
	}
}

func TestACLDeniedIsMissingWithoutLoginLoop(t *testing.T) {
	c, mock := newMockClient(t)
	mock.Deny("luci-rpc", "getDHCPLeases")
	mock.Remove("iwinfo")
	for range 3 {
		r, err := c.read(t.Context())
		if err != nil {
			t.Fatalf("read = %v, want the leases and wireless clients missing only", err)
		}
		if len(r.missing) != 2 || !strings.Contains(r.missing[0], "DHCP leases") || !strings.Contains(r.missing[0], "ACL") ||
			!strings.Contains(r.missing[1], "wireless clients") || !strings.Contains(r.missing[1], "not on this router") {
			t.Errorf("missing = %v", r.missing)
		}
		if len(r.clients) != 0 || r.system.Hostname != "gateway" || len(r.interfaces) == 0 {
			t.Errorf("read = %+v", r)
		}
	}
	// The first denial logs in once more, in case the session expired; the
	// same session is not asked again.
	if mock.Logins() != 2 {
		t.Errorf("logins = %d, want 2", mock.Logins())
	}
}

func TestRequiredReadDenied(t *testing.T) {
	c, mock := newMockClient(t)
	mock.Deny("system", "info")
	if _, err := c.read(t.Context()); !errors.Is(err, errDenied) {
		t.Errorf("read = %v, want a denial of system info", err)
	}
}

func TestNoUbus(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(srv.Close)
	c, err := newClient(Connection{URL: srv.URL, Username: "root", Password: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.read(t.Context()); err == nil || !strings.Contains(err.Error(), "uhttpd-mod-ubus") {
		t.Errorf("read = %v, want a hint to install uhttpd-mod-ubus", err)
	}
}

func TestRedirectToHTTPS(t *testing.T) {
	srv := httptest.NewServer(http.RedirectHandler("https://192.0.2.1/ubus", http.StatusMovedPermanently))
	t.Cleanup(srv.Close)
	c, err := newClient(Connection{URL: srv.URL, Username: "root", Password: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.read(t.Context()); err == nil || !strings.Contains(err.Error(), "https://") {
		t.Errorf("read = %v, want use an https:// URL", err)
	}
}

func TestPinnedFingerprint(t *testing.T) {
	mock := openwrtmock.New(openwrtmock.Username, openwrtmock.Password)
	srv := httptest.NewTLSServer(mock)
	t.Cleanup(srv.Close)
	sum := sha256.Sum256(srv.Certificate().Raw)
	for name, tc := range map[string]struct {
		fp   string
		fail bool
	}{
		"pinned":       {hex.EncodeToString(sum[:]), false},
		"other cert":   {strings.Repeat("ab", 32), true},
		"system roots": {"", true},
	} {
		t.Run(name, func(t *testing.T) {
			conn, err := Connection{URL: srv.URL, Username: openwrtmock.Username, Password: openwrtmock.Password, Fingerprint: tc.fp}.normalize()
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
	ok := Connection{Username: "hearth", Password: "pw"}
	for _, tc := range []struct {
		url, fp, want string
		fail          bool
	}{
		{url: "http://192.168.1.1", want: "http://192.168.1.1:80"},
		{url: "https://router.lan/cgi-bin/luci/", want: "https://router.lan:443"},
		{url: "http://192.168.1.1:8080/ubus", want: "http://192.168.1.1:8080"},
		{url: "https://[fd00::1]", want: "https://[fd00::1]:443"},
		{url: "ftp://192.168.1.1", fail: true},
		{url: "http://root:pw@192.168.1.1", fail: true},
		{url: "http://192.168.1.1/admin", fail: true},
		{url: "http://192.168.1.1", fp: strings.Repeat("ab", 32), fail: true},
		{url: "https://192.168.1.1", fp: "AB:CD", fail: true},
	} {
		c := ok
		c.URL, c.Fingerprint = tc.url, tc.fp
		got, err := c.normalize()
		if (err != nil) != tc.fail || (err == nil && got.URL != tc.want) {
			t.Errorf("normalize(%q, %q) = %q, %v", tc.url, tc.fp, got.URL, err)
		}
		if err != nil && !errors.Is(err, ErrBadConnection) {
			t.Errorf("normalize(%q) error %v is no ErrBadConnection", tc.url, err)
		}
	}
	for _, c := range []Connection{
		{URL: "http://192.168.1.1", Password: "pw"},
		{URL: "http://192.168.1.1", Username: "a b", Password: "pw"},
		{URL: "http://192.168.1.1", Username: "root"},
	} {
		if _, err := c.normalize(); !errors.Is(err, ErrBadConnection) {
			t.Errorf("normalize(%+v) = %v, want ErrBadConnection", c, err)
		}
	}
}
