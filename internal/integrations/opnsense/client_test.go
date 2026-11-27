// SPDX-License-Identifier: AGPL-3.0-only

package opnsense

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gvart/hearth/internal/integrations/opnsense/opnsensemock"
)

// newMockServer serves a fake firewall over https and returns the
// fingerprint that pins its certificate.
func newMockServer(t *testing.T) (*opnsensemock.Server, *httptest.Server, string) {
	t.Helper()
	mock := opnsensemock.New(opnsensemock.Key, opnsensemock.Secret)
	srv := httptest.NewTLSServer(mock)
	t.Cleanup(srv.Close)
	sum := sha256.Sum256(srv.Certificate().Raw)
	return mock, srv, hex.EncodeToString(sum[:])
}

func newMockClient(t *testing.T) (*client, *opnsensemock.Server) {
	t.Helper()
	mock, srv, fp := newMockServer(t)
	c, err := newClient(Connection{URL: srv.URL, Key: opnsensemock.Key, Secret: opnsensemock.Secret, Fingerprint: fp})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.close)
	return c, mock
}

func TestReadsSystemLeasesARPAndTraffic(t *testing.T) {
	c, _ := newMockClient(t)
	r, err := c.read(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	sys := r.system
	if sys.Hostname != "edge.home.arpa" || len(sys.Versions) != 3 || sys.Versions[0] != "OPNsense 25.7.4-amd64" ||
		sys.Uptime != "12 days, 03:04:05" || sys.Load != "0.24, 0.31, 0.29" ||
		sys.MemTotal != 8448794624 || sys.MemUsed != 2147483648 {
		t.Errorf("system = %+v", sys)
	}
	if fw := r.firmware; fw.Version != "25.7.4" || fw.Latest != "25.7.5" || fw.Status != "update" || fw.Product != "OPNsense" {
		t.Errorf("firmware = %+v", fw)
	}
	var names []string
	for _, i := range r.interfaces {
		names = append(names, i.Name+"="+i.Description)
	}
	if strings.Join(names, ",") != "lan=LAN,opt1=IOT,wan=WAN" {
		t.Errorf("interfaces = %v", names)
	}
	if wan := r.interfaces[2]; wan.Device != "igb0" || wan.RxBytes != 912000000000 || wan.TxBytes != 81000000000 ||
		wan.RxPackets != 9120000 || wan.RxErrors != 2 {
		t.Errorf("wan = %+v: want the string counters read as numbers", wan)
	}
	byMAC := map[string]Client{}
	for _, cl := range r.clients {
		byMAC[cl.MAC] = cl
	}
	// 1 ISC, 1 active Kea, 3 dnsmasq leases, 1 ARP-only host.
	if len(byMAC) != 6 {
		t.Fatalf("clients = %+v", r.clients)
	}
	if _, ok := byMAC["00:0d:b9:00:00:10"]; ok {
		t.Error("the firewall's own interface is listed as a client")
	}
	if _, ok := byMAC["b8:27:eb:00:00:07"]; ok {
		t.Error("an expired Kea lease is listed")
	}
	phone := byMAC["a4:5e:60:00:00:02"]
	if !phone.Lease || phone.LeaseSource != "dnsmasq" || phone.IP != "192.168.1.23" || phone.Hostname != "pixel-8" ||
		!phone.ARP || phone.Vendor != "Google, Inc." || phone.LeaseEnds != 1990000200 || phone.Static ||
		strings.Join(phone.IPv6, ",") != "fd00::23,fe80::a65e:60ff:fe00:2" {
		t.Errorf("phone = %+v: want its lease, ARP entry and NDP addresses merged", phone)
	}
	if nas := byMAC["2c:cf:67:00:00:01"]; !nas.Static || nas.Hostname != "nas" || nas.Interface != "LAN" {
		t.Errorf("nas = %+v: want the lease's name over the ARP table's reverse lookup", nas)
	}
	if p := byMAC["00:1b:a9:00:00:03"]; p.LeaseSource != "isc" || !p.Static || p.LeaseEnds != 0 || p.IP != "192.168.1.5" {
		t.Errorf("ISC lease = %+v", p)
	}
	if pi := byMAC["b8:27:eb:00:00:06"]; pi.LeaseSource != "kea" || pi.Hostname != "pi-iot" || pi.LeaseEnds != 1990000000 ||
		pi.Interface != "IOT" {
		t.Errorf("Kea lease = %+v: want the trailing dot of its FQDN dropped", pi)
	}
	if odd := byMAC["de:ad:be:00:00:04"]; odd.Hostname != "" || odd.IP != "192.168.1.77" {
		t.Errorf("client without a name = %+v, want dnsmasq's * dropped", odd)
	}
	if s := byMAC["f0:99:b6:00:00:05"]; s.Lease || !s.ARP || s.IP != "192.168.1.200" || s.Vendor != "Apple, Inc." {
		t.Errorf("ARP-only host = %+v", s)
	}
	if r.clients[len(r.clients)-1].Hostname != "" {
		t.Errorf("clients without a name sort last: %+v", r.clients)
	}
	if len(r.missing) != 0 {
		t.Errorf("missing = %v, want none", r.missing)
	}
}

func TestBadKey(t *testing.T) {
	c, mock := newMockClient(t)
	mock.SetSecret("a new secret")
	_, err := c.read(t.Context())
	if !errors.Is(err, ErrBadLogin) {
		t.Fatalf("read = %v, want ErrBadLogin", err)
	}
	for _, s := range []string{opnsensemock.Key, opnsensemock.Secret} {
		if strings.Contains(err.Error(), s) {
			t.Errorf("the error quotes a credential: %v", err)
		}
	}
	if n := len(mock.Requests()); n != 1 {
		t.Errorf("requests after a refused key = %d, want the read to stop at the first", n)
	}
}

// A key whose user lacks a privilege: that part shows as not read, the rest
// is read.
func TestDeniedEndpointIsMissing(t *testing.T) {
	c, mock := newMockClient(t)
	mock.Deny(pathARP)
	mock.Deny(pathFirmware)
	r, err := c.read(t.Context())
	if err != nil {
		t.Fatalf("read = %v, want the ARP table and firmware missing only", err)
	}
	if len(r.missing) != 2 || !strings.HasPrefix(r.missing[0], "firmware status: ") || !strings.Contains(r.missing[0], "privileges") ||
		!strings.HasPrefix(r.missing[1], "ARP table: ") || !strings.Contains(r.missing[1], "privileges") {
		t.Errorf("missing = %v", r.missing)
	}
	if r.firmware.Version != "" || r.system.Hostname != "edge.home.arpa" || len(r.interfaces) != 3 {
		t.Errorf("read = %+v", r)
	}
	for _, cl := range r.clients {
		if cl.ARP {
			t.Errorf("client %+v from a denied ARP table", cl)
		}
	}
}

func TestLeaseBackends(t *testing.T) {
	for name, tc := range map[string]struct {
		deny, remove []string
		leases       int
		missing      []string
	}{
		// The default of a current install: the ISC plugin is not there.
		"no ISC plugin": {remove: []string{pathISCLeases}, leases: 4},
		// A key with the privilege of the one server in use.
		"only dnsmasq allowed": {remove: []string{pathISCLeases}, deny: []string{pathKeaLeases}, leases: 3},
		"none allowed": {
			remove: []string{pathISCLeases}, deny: []string{pathKeaLeases, pathDnsmasq},
			missing: []string{"DHCP leases (kea): not allowed by the API key's privileges", "DHCP leases (dnsmasq): not allowed by the API key's privileges"},
		},
		"none there": {
			remove: []string{pathISCLeases, pathKeaLeases, pathDnsmasq}, missing: []string{"DHCP leases: not on this firewall"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			c, mock := newMockClient(t)
			for _, p := range tc.deny {
				mock.Deny(p)
			}
			for _, p := range tc.remove {
				mock.Remove(p)
			}
			r, err := c.read(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			leases := 0
			for _, cl := range r.clients {
				if cl.Lease {
					leases++
				}
			}
			if leases != tc.leases || strings.Join(r.missing, "|") != strings.Join(tc.missing, "|") {
				t.Errorf("leases = %d, missing = %q; want %d, %q", leases, r.missing, tc.leases, tc.missing)
			}
		})
	}
}

func TestRequiredReadDenied(t *testing.T) {
	c, mock := newMockClient(t)
	mock.Deny(pathSystemInfo)
	if _, err := c.read(t.Context()); !errors.Is(err, errDenied) {
		t.Errorf("read = %v, want a denial of the system information", err)
	}
}

func TestRestartUnbound(t *testing.T) {
	c, mock := newMockClient(t)
	if err := c.restartUnbound(t.Context()); err != nil {
		t.Fatal(err)
	}
	if mock.Restarts() != 1 {
		t.Errorf("restarts = %d, want 1", mock.Restarts())
	}
	mock.Deny(pathRestartDNS)
	if err := c.restartUnbound(t.Context()); !errors.Is(err, errDenied) {
		t.Errorf("restart without the privilege = %v, want errDenied", err)
	}
}

func TestRedirect(t *testing.T) {
	srv := httptest.NewTLSServer(http.RedirectHandler("https://192.0.2.1/", http.StatusFound))
	t.Cleanup(srv.Close)
	sum := sha256.Sum256(srv.Certificate().Raw)
	c, err := newClient(Connection{URL: srv.URL, Key: "k", Secret: "s", Fingerprint: hex.EncodeToString(sum[:])})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.read(t.Context()); err == nil || !strings.Contains(err.Error(), "redirect") {
		t.Errorf("read = %v, want a redirect refused", err)
	}
}

func TestPinnedFingerprint(t *testing.T) {
	_, srv, fp := newMockServer(t)
	for name, tc := range map[string]struct {
		fp   string
		fail bool
	}{
		"pinned":       {fp, false},
		"other cert":   {strings.Repeat("ab", 32), true},
		"system roots": {"", true},
	} {
		t.Run(name, func(t *testing.T) {
			conn, err := Connection{URL: srv.URL, Key: opnsensemock.Key, Secret: opnsensemock.Secret, Fingerprint: tc.fp}.normalize()
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
	ok := Connection{Key: "key", Secret: "secret"}
	for _, tc := range []struct {
		url, fp, want string
		fail          bool
	}{
		{url: "https://192.168.1.1", want: "https://192.168.1.1:443"},
		{url: "https://opnsense.lan/ui/", want: "https://opnsense.lan:443"},
		{url: "https://192.168.1.1:8443/api", want: "https://192.168.1.1:8443"},
		{url: "https://[fd00::1]", want: "https://[fd00::1]:443"},
		{url: "https://192.168.1.1", fp: strings.Repeat("AB:", 31) + "AB", want: "https://192.168.1.1:443"},
		{url: "http://192.168.1.1", fail: true},
		{url: "ftp://192.168.1.1", fail: true},
		{url: "https://key:secret@192.168.1.1", fail: true}, //nolint:gosec // a URL that must be refused
		{url: "https://192.168.1.1/admin", fail: true},
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
		{URL: "https://192.168.1.1", Secret: "zz-secret-zz"}, //nolint:gosec // values that must be refused
		{URL: "https://192.168.1.1", Key: "k"},
		{URL: "https://192.168.1.1", Key: "a b", Secret: "zz-secret-zz"}, //nolint:gosec // values that must be refused
		{URL: "https://192.168.1.1", Key: "k", Secret: "zz:secret-zz"},   //nolint:gosec // values that must be refused
	} {
		got, err := c.normalize()
		if !errors.Is(err, ErrBadConnection) {
			t.Errorf("normalize(%+v) = %v, want ErrBadConnection", c, err)
		}
		if err != nil && (c.Secret != "" && strings.Contains(err.Error(), c.Secret)) {
			t.Errorf("the error quotes the secret: %v (%+v)", err, got)
		}
	}
}
