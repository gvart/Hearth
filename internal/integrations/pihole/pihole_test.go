// SPDX-License-Identifier: AGPL-3.0-only

package pihole

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/gvart/hearth/internal/discovery"
	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

// now is the fake Pi-hole's clock: 2022-10-02, as in the API docs' examples.
var now = time.Unix(1664700000, 0)

// Response bodies in the shapes of the Pi-hole v6 API reference
// (FTL src/api/docs/content/specs: auth.yaml, network.yaml, dhcp.yaml).
const (
	authOK = `{"session":{"valid":true,"totp":false,"sid":"vFA+EP4MQ5JJvJg+3Q2Jnw=","csrf":"Ux87YTIiMOf/GKCefVIOMw=",` +
		`"validity":300,"message":"correct password"},"took":0.003}`
	authBad = `{"session":{"valid":false,"totp":false,"sid":null,"csrf":null,"validity":-1,` +
		`"message":"password incorrect"},"took":0.002}`
	devicesBody = `{"devices":[
	 {"id":1,"hwaddr":"00:11:22:33:44:55","interface":"enp2s0","firstSeen":1664623620,"lastQuery":1664688620,
	  "numQueries":585462,"macVendor":"Digital Data Communications Asia Co.,Ltd",
	  "ips":[{"ip":"fe80::211:22ff:fe33:4455","name":null,"lastSeen":1664688630,"nameUpdated":0},
	         {"ip":"192.168.1.51","name":"ubuntu-server","lastSeen":1664688620,"nameUpdated":1664688620},
	         {"ip":"192.168.1.12","name":"old-name","lastSeen":1664600000,"nameUpdated":1664600000}]},
	 {"id":2,"hwaddr":"ip-192.168.5.9","interface":"N/A","firstSeen":1664623620,"lastQuery":1664688620,
	  "numQueries":12,"macVendor":null,"ips":[{"ip":"192.168.5.9","name":null,"lastSeen":1664688620,"nameUpdated":0}]},
	 {"id":3,"hwaddr":"b8:27:eb:00:00:01","interface":"enp2s0","firstSeen":1600000000,"lastQuery":1600000000,
	  "numQueries":3,"macVendor":"Raspberry Pi Foundation",
	  "ips":[{"ip":"192.168.1.60","name":"stale-pi","lastSeen":1600000000,"nameUpdated":1600000000}]},
	 {"id":4,"hwaddr":"3c:2e:f9:00:00:03","interface":"enp2s0","firstSeen":1664623620,"lastQuery":0,
	  "numQueries":0,"macVendor":"Apple, Inc.",
	  "ips":[{"ip":"192.168.1.70","name":null,"lastSeen":1664690000,"nameUpdated":0}]}
	],"took":0.012}`
	leasesBody = `{"leases":[
	 {"expires":1664710000,"name":"raspberrypi","hwaddr":"2c:cf:67:00:00:01","ip":"192.168.2.111","clientid":"01:2c:cf:67:00:00:01"},
	 {"expires":0,"name":"*","hwaddr":"aa:bb:cc:00:00:02","ip":"192.168.2.112","clientid":"*"},
	 {"expires":1664600000,"name":"gone","hwaddr":"aa:bb:cc:00:00:03","ip":"192.168.2.113","clientid":"*"}
	],"took":0.001}`
)

// fakePihole serves the v6 API with password "app-pass" and counts the
// sessions open.
type fakePihole struct {
	mu       sync.Mutex
	open     int
	logins   int
	password string
}

func (f *fakePihole) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	const sid = "vFA+EP4MQ5JJvJg+3Q2Jnw="
	authed := f.password == "" || r.Header.Get("X-FTL-SID") == sid && f.open > 0
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/api/auth":
		f.logins++
		var body struct{ Password string }
		b, _ := io.ReadAll(r.Body)
		if json.Unmarshal(b, &body) != nil || body.Password != f.password {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, authBad)
			return
		}
		f.open++
		_, _ = io.WriteString(w, authOK)
	case r.Method == http.MethodDelete && r.URL.Path == "/api/auth":
		if authed && f.open > 0 {
			f.open--
		}
		w.WriteHeader(http.StatusNoContent)
	case !authed:
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"error":{"key":"unauthorized","message":"Unauthorized","hint":null},"took":0.0001}`)
	case r.Method == http.MethodGet && r.URL.Path == "/api/network/devices":
		if r.URL.Query().Get("max_devices") == "" {
			http.Error(w, "want max_devices", http.StatusBadRequest)
			return
		}
		_, _ = io.WriteString(w, devicesBody)
	case r.Method == http.MethodGet && r.URL.Path == "/api/dhcp/leases":
		_, _ = io.WriteString(w, leasesBody)
	default:
		http.NotFound(w, r)
	}
}

func newClient(t *testing.T, f *fakePihole, path, password string) *Client {
	t.Helper()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	c, err := New(srv.URL+path, password, srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	c.now = func() time.Time { return now }
	return c
}

func TestRecords(t *testing.T) {
	for _, tt := range []struct{ name, path, password, serverPassword string }{
		{"app password", "", "app-pass", "app-pass"},
		{"url with /admin/", "/admin/", "app-pass", "app-pass"},
		{"no password", "/api", "", ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := &fakePihole{password: tt.serverPassword}
			recs, err := newClient(t, f, tt.path, tt.password).Records(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			want := []discovery.Record{
				{
					MAC: "00:11:22:33:44:55", IP: "192.168.1.51", Hostname: "ubuntu-server",
					Vendor: "Digital Data Communications Asia Co.,Ltd", Seen: time.Unix(1664688620, 0).UTC(),
				},
				{MAC: "3c:2e:f9:00:00:03", IP: "192.168.1.70", Vendor: "Apple, Inc.", Seen: time.Unix(1664690000, 0).UTC()},
				// The "ip-…" pseudo-device stays: the importer drops what is not a MAC.
				{MAC: "ip-192.168.5.9", IP: "192.168.5.9", Seen: time.Unix(1664688620, 0).UTC()},
				{MAC: "2c:cf:67:00:00:01", IP: "192.168.2.111", Hostname: "raspberrypi", Lease: true},
				{MAC: "aa:bb:cc:00:00:02", IP: "192.168.2.112", Hostname: "*", Lease: true},
			}
			byMAC := map[string]discovery.Record{}
			for _, r := range recs {
				byMAC[r.MAC] = r
			}
			if len(recs) != len(want) {
				t.Errorf("got %d records, want %d: %+v", len(recs), len(want), recs)
			}
			for _, w := range want {
				if g := byMAC[w.MAC]; g != w {
					t.Errorf("%s = %+v, want %+v", w.MAC, g, w)
				}
			}
			if f.open != 0 {
				t.Errorf("%d sessions left open; want every login logged out", f.open)
			}
		})
	}
}

func TestRecordsErrors(t *testing.T) {
	// A wrong password: the error says so and never holds the password.
	f := &fakePihole{password: "app-pass"}
	_, err := newClient(t, f, "", "wrong-secret").Records(t.Context())
	if err == nil || !strings.Contains(err.Error(), "401") || strings.Contains(err.Error(), "wrong-secret") {
		t.Errorf("wrong password: err = %v; want a 401 without the password", err)
	}
	// A password-protected Pi-hole and no password.
	_, err = newClient(t, f, "", "").Records(t.Context())
	if err == nil || !strings.Contains(err.Error(), "unauthorized") {
		t.Errorf("no password: err = %v; want unauthorized", err)
	}
}

func TestNew(t *testing.T) {
	for _, u := range []string{"pi.hole", "ftp://pi.hole", "http://user:pw@pi.hole", "http://pi.hole/?sid=x", "http://"} {
		if _, err := New(u, "", nil); err == nil {
			t.Errorf("New(%q) succeeded", u)
		}
	}
	c, err := New("https://pi.hole:8443/admin", "secret", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := c.Target(); got != "pihole:https://pi.hole:8443" {
		t.Errorf("Target = %q", got)
	}
}

// Devices known to Pi-hole show their Pi-hole names: a host the scan named
// over mDNS takes the Pi-hole name, and hosts the scan never saw are added.
func TestImportShowsPiholeNames(t *testing.T) {
	ctx := t.Context()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "hearth.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if _, err := st.NetworkHosts().RecordScan(ctx, time.Unix(1664688000, 0), time.Hour, []store.NetworkHost{
		{MAC: "00:11:22:33:44:55", IP: "192.168.1.51", Hostname: "ubuntu.local"},
	}); err != nil {
		t.Fatal(err)
	}
	im := discovery.NewImporter(discovery.ImportConfig{
		Sources: []discovery.Source{newClient(t, &fakePihole{password: "app-pass"}, "", "app-pass")},
		Hosts:   st.NetworkHosts(), Policy: policy.New(st.Audit()),
	})
	if err := im.Import(ctx); err != nil {
		t.Fatal(err)
	}
	hosts, err := st.NetworkHosts().List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]store.NetworkHost{}
	for _, h := range hosts {
		got[h.MAC] = h
	}
	if h := got["00:11:22:33:44:55"]; h.Hostname != "ubuntu-server" || h.HostnameSource != store.SourcePihole ||
		strings.Join(h.Sources, ",") != "pihole,scan" {
		t.Errorf("scanned host = %+v; want its Pi-hole name", h)
	}
	if h := got["2c:cf:67:00:00:01"]; h.Hostname != "raspberrypi" || h.IP != "192.168.2.111" {
		t.Errorf("lease-only host = %+v; want it added with its lease name", h)
	}
	if _, ok := got["b8:27:eb:00:00:01"]; ok {
		t.Error("a device Pi-hole last saw two years ago was imported")
	}
	if len(got) != 4 { // the scanned host, the Apple device, two leases
		t.Errorf("hosts = %+v; want 4", hosts)
	}
}

// TestRealPihole reads a real Pi-hole v6, e.g. the pihole/pihole container:
//
//	HEARTH_PIHOLE_TEST_URL=http://localhost:8080 HEARTH_PIHOLE_TEST_PASSWORD=... go test ./internal/integrations/pihole -run Real -v
func TestRealPihole(t *testing.T) {
	u := os.Getenv("HEARTH_PIHOLE_TEST_URL")
	if u == "" {
		t.Skip("HEARTH_PIHOLE_TEST_URL is not set")
	}
	c, err := New(u, os.Getenv("HEARTH_PIHOLE_TEST_PASSWORD"), nil)
	if err != nil {
		t.Fatal(err)
	}
	// Twice: a session must be freed each time, or the API seats run out.
	for range 2 {
		recs, err := c.Records(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range recs {
			if r.IP == "" || r.MAC == "" {
				t.Errorf("record without MAC or IP: %+v", r)
			}
			t.Logf("%+v", r)
		}
	}
}

func TestRedirectRefused(t *testing.T) {
	var second atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		second.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"devices":[]}`)
	}))
	t.Cleanup(target.Close)
	targetURL := target.URL + "/api/network/devices"
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, targetURL, http.StatusTemporaryRedirect)
	}))
	t.Cleanup(first.Close)
	for name, hc := range map[string]*http.Client{"nil client": nil, "plain client": {Timeout: time.Second}} {
		t.Run(name, func(t *testing.T) {
			c, err := New(first.URL, "", hc)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := c.Records(t.Context()); err == nil || !strings.Contains(err.Error(), "307") {
				t.Errorf("Records = %v; want a 307 error", err)
			}
			if n := second.Load(); n != 0 {
				t.Errorf("the redirect target got %d requests; want none", n)
			}
		})
	}
}

func TestErrorMessageClipped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		// Multi-byte, so the cut lands inside a character.
		_, _ = io.WriteString(w, `{"error":{"key":"bad","message":"`+strings.Repeat("é", 1<<20)+`"}}`)
	}))
	t.Cleanup(srv.Close)
	c, err := New(srv.URL, "", srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Records(t.Context())
	if err == nil || len(err.Error()) > 1024 || !utf8.ValidString(err.Error()) || !strings.Contains(err.Error(), "500: bad") {
		n := 0
		if err != nil {
			n = len(err.Error())
		}
		t.Errorf("error is %d bytes (%v); want a short valid UTF-8 one naming the status and key", n, err != nil)
	}
}
