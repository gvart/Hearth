// SPDX-License-Identifier: AGPL-3.0-only

package netalertx_test

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/discovery"
	"github.com/gvart/hearth/internal/integrations/netalertx"
	"github.com/gvart/hearth/internal/integrations/netalertx/netalertxmock"
	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

func serve(t *testing.T, m *netalertxmock.Server) string {
	t.Helper()
	srv := httptest.NewServer(m)
	t.Cleanup(srv.Close)
	return srv.URL
}

func TestRecords(t *testing.T) {
	m := netalertxmock.New(netalertxmock.Token)
	c, err := netalertx.New(serve(t, m)+"/", netalertxmock.Token, nil)
	if err != nil {
		t.Fatal(err)
	}
	recs, err := c.Records(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	byMAC := map[string]discovery.Record{}
	for _, r := range recs {
		byMAC[strings.ToLower(r.MAC)] = r
	}
	if _, ok := byMAC["aa:bb:cc:00:00:09"]; ok {
		t.Error("an archived device was imported")
	}
	pi := byMAC["2c:cf:67:12:34:56"]
	if pi.IP != "192.168.20.171" || pi.Hostname != "pi5" || pi.Vendor != "Raspberry Pi Trading Ltd" || pi.Seen.IsZero() {
		t.Errorf("present device = %+v", pi)
	}
	apple := byMAC["3c:2e:f9:00:00:03"]
	if apple.Hostname != "" {
		t.Errorf("placeholder name %q imported; want none", apple.Hostname)
	}
	if !apple.Seen.IsZero() {
		t.Errorf("a device absent from the last scan has Seen %v; want zero", apple.Seen)
	}
	if got := c.Target(); !strings.HasPrefix(got, "netalertx:http://") || strings.Contains(got, netalertxmock.Token) {
		t.Errorf("Target = %q", got)
	}
}

func TestErrors(t *testing.T) {
	tests := []struct {
		name  string
		setup func(m *netalertxmock.Server)
		token string
		want  string
	}{
		{name: "wrong token", token: "nope", want: "HTTP 403: ERROR: Not authorized (wrong API token?)"},
		{name: "malformed", token: netalertxmock.Token, setup: func(m *netalertxmock.Server) { m.SetBody(`{"success":true,"devices":[{`) }, want: "decode response"},
		{name: "wrong shape", token: netalertxmock.Token, setup: func(m *netalertxmock.Server) { m.SetBody(`{"success":true,"devices":{"a":1}}`) }, want: "decode response"},
		{name: "not success", token: netalertxmock.Token, setup: func(m *netalertxmock.Server) { m.SetBody(`{"success":false}`) }, want: "success is false"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := netalertxmock.New(netalertxmock.Token)
			if tt.setup != nil {
				tt.setup(m)
			}
			c, err := netalertx.New(serve(t, m), tt.token, nil)
			if err != nil {
				t.Fatal(err)
			}
			_, err = c.Records(t.Context())
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v; want %q", err, tt.want)
			}
			if strings.Contains(err.Error(), netalertxmock.Token) || strings.Contains(err.Error(), "nope") {
				t.Errorf("error %q holds the token", err)
			}
		})
	}
}

func TestTimeout(t *testing.T) {
	m := netalertxmock.New(netalertxmock.Token)
	release := make(chan struct{})
	defer close(release)
	m.Hang(release)
	c, err := netalertx.New(serve(t, m), netalertxmock.Token, &http.Client{Timeout: 50 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if _, err := c.Records(t.Context()); err == nil {
		t.Fatal("no error from a server that never answers")
	}
	if took := time.Since(start); took > 5*time.Second {
		t.Errorf("took %v; want the client timeout", took)
	}
}

func TestNew(t *testing.T) {
	for _, tt := range []struct{ url, token string }{
		{"ftp://x", "t"}, {"http://", "t"}, {"http://u:p@x", "t"}, {"http://x?token=t", "t"}, {"http://x", ""},
	} {
		if _, err := netalertx.New(tt.url, tt.token, nil); err == nil {
			t.Errorf("New(%q) = nil error", tt.url)
		}
	}
}

// NetAlertX names replace a scan's name, placeholders do not, and hosts the
// scan never saw are added, all under the network.import read action.
func TestImport(t *testing.T) {
	ctx := t.Context()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "hearth.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if _, err := st.NetworkHosts().RecordScan(ctx, time.Now().Add(-time.Minute), time.Hour, []store.NetworkHost{
		{MAC: "2c:cf:67:12:34:56", IP: "192.168.20.171", Hostname: "raspberrypi.local"},
		{MAC: "3c:2e:f9:00:00:03", IP: "192.168.20.70", Hostname: "macbook.local"},
	}); err != nil {
		t.Fatal(err)
	}
	c, err := netalertx.New(serve(t, netalertxmock.New(netalertxmock.Token)), netalertxmock.Token, nil)
	if err != nil {
		t.Fatal(err)
	}
	im := discovery.NewImporter(discovery.ImportConfig{
		Sources: []discovery.Source{c}, Hosts: st.NetworkHosts(), Policy: policy.New(st.Audit()),
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
	if h := got["2c:cf:67:12:34:56"]; h.Hostname != "pi5" || h.HostnameSource != store.SourceNetAlertX ||
		strings.Join(h.Sources, ",") != "netalertx,scan" {
		t.Errorf("scanned host = %+v; want its NetAlertX name", h)
	}
	if h := got["3c:2e:f9:00:00:03"]; h.Hostname != "macbook.local" {
		t.Errorf("host with a placeholder name = %+v; want the scan's name kept", h)
	}
	if len(got) != 2 {
		t.Errorf("hosts = %+v; want 2 (no archived device, no Internet node)", hosts)
	}
	entries, err := st.Audit().List(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Action != string(policy.NetworkImport) || !strings.HasPrefix(entries[0].Target, "netalertx:") {
		t.Errorf("audit = %+v; want one network.import entry", entries)
	}
}
