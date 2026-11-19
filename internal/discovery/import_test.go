// SPDX-License-Identifier: AGPL-3.0-only

package discovery

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

var leaseNow = time.Date(2024, 1, 4, 12, 0, 0, 0, time.UTC)

const dnsmasqLeases = `1704412800 2c:cf:67:00:00:01 192.168.2.171 pi5 01:2c:cf:67:00:00:01
0 aa:bb:cc:00:00:02 192.168.20.5 * *
1704300000 aa:bb:cc:00:00:03 192.168.2.40 expired *
duid 00:01:00:01:2c:5b:6a:21:aa:bb:cc:dd:ee:ff
1704412800 1234567 fd00::5 laptop 00:01:00:01:2c:5b:6a:21
garbage
`

const iscLeases = `# The format of this file is documented in the dhcpd.leases(5) manual page.
# This lease file was written by isc-dhcp-4.4.3
authoring-byte-order little-endian;
server-duid "\000\001\000\001";

failover peer "dhcp" state {
  my state normal at 4 2024/01/04 08:00:00;
}

lease 192.168.30.10 {
  starts 4 2024/01/04 08:00:00;
  ends 4 2024/01/04 20:00:00;
  cltt 4 2024/01/04 10:00:00;
  binding state active;
  next binding state free;
  rewind binding state free;
  hardware ethernet 00:11:32:00:00:0a;
  uid "\001\000\0212\000\000\012";
  client-hostname "nas";
}
lease 192.168.30.11 {
  starts epoch 1704355200; # 2024/01/04 08:00:00
  ends never;
  binding state active;
  hardware ethernet 3c:2e:f9:00:00:0b;
  client-hostname "iPhone";
}
lease 192.168.30.12 {
  starts 4 2024/01/04 08:00:00;
  ends 4 2024/01/04 20:00:00;
  binding state active;
  hardware ethernet aa:bb:cc:00:00:0c;
}
lease 192.168.30.12 {
  starts 4 2024/01/04 08:00:00;
  ends 4 2024/01/04 09:00:00;
  binding state free;
  hardware ethernet aa:bb:cc:00:00:0c;
}
lease 192.168.30.13 {
  starts 3 2024/01/03 08:00:00;
  ends 3 2024/01/03 20:00:00;
  binding state active;
  hardware ethernet aa:bb:cc:00:00:0d;
  client-hostname "expired";
}
`

func TestParseDnsmasqLeases(t *testing.T) {
	got, err := ParseDnsmasqLeases(strings.NewReader(dnsmasqLeases), leaseNow)
	if err != nil {
		t.Fatal(err)
	}
	want := []Record{
		{MAC: "2c:cf:67:00:00:01", IP: "192.168.2.171", Hostname: "pi5", Lease: true},
		{MAC: "aa:bb:cc:00:00:02", IP: "192.168.20.5", Hostname: "*", Lease: true},
		// The IPv6 lease's IAID is no MAC: the merge drops it.
		{MAC: "1234567", IP: "fd00::5", Hostname: "laptop", Lease: true},
	}
	if !slices.Equal(got, want) {
		t.Errorf("got %+v\nwant %+v", got, want)
	}
}

func TestParseISCLeases(t *testing.T) {
	got, err := ParseISCLeases(strings.NewReader(iscLeases), leaseNow)
	if err != nil {
		t.Fatal(err)
	}
	want := []Record{
		{
			MAC: "00:11:32:00:00:0a", IP: "192.168.30.10", Hostname: "nas", Lease: true,
			Seen: time.Date(2024, 1, 4, 10, 0, 0, 0, time.UTC),
		},
		{
			MAC: "3c:2e:f9:00:00:0b", IP: "192.168.30.11", Hostname: "iPhone", Lease: true,
			Seen: time.Date(2024, 1, 4, 8, 0, 0, 0, time.UTC),
		},
	}
	if !slices.Equal(got, want) {
		t.Errorf("got %+v\nwant %+v", got, want)
	}
}

func TestLeaseFileDetectsFormat(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{"dnsmasq.leases": dnsmasqLeases, "dhcpd.leases": iscLeases} {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		recs, err := LeaseFile{Path: p, now: func() time.Time { return leaseNow }}.Records(t.Context())
		if err != nil || len(recs) == 0 {
			t.Errorf("%s: %d records, %v", name, len(recs), err)
		}
	}
	if _, err := (LeaseFile{Path: filepath.Join(dir, "missing")}).Records(t.Context()); err == nil {
		t.Error("a missing lease file read")
	}
}

func TestMergeRecords(t *testing.T) {
	t1 := time.Unix(1_700_000_000, 0)
	got := mergeRecords([]sourceRecords{
		{name: store.SourcePihole, recs: []Record{
			// A network-table name, then a lease name for the same MAC: the lease wins.
			{MAC: "2C-CF-67-00-00-01", IP: "192.168.2.170", Hostname: "pi5.lan.", Vendor: "Raspberry Pi", Seen: t1},
			{MAC: "2c:cf:67:00:00:01", IP: "192.168.2.171", Hostname: "pi5", Lease: true},
			{MAC: "ip-192.168.5.9", IP: "192.168.5.9"},
			{MAC: "00:00:00:00:00:00", IP: "192.168.2.2"},
			{MAC: "01:00:5e:00:00:01", IP: "192.168.2.3"},
			{MAC: "aa:bb:cc:00:00:02", IP: "fe80::1"},
		}},
		{name: store.SourceDHCP, recs: []Record{
			{MAC: "2c:cf:67:00:00:01", IP: "192.168.2.172", Hostname: "other", Lease: true, Seen: t1.Add(time.Minute)},
			{MAC: "aa:bb:cc:00:00:03", IP: "192.168.20.5", Hostname: "*", Lease: true},
		}},
	})
	want := []store.ImportedHost{
		{
			MAC: "2c:cf:67:00:00:01", IP: "192.168.2.172", Hostname: "pi5", HostnameSource: store.SourcePihole,
			Vendor: "Raspberry Pi", Sources: []string{store.SourceDHCP, store.SourcePihole}, Seen: t1.Add(time.Minute).UnixMilli(),
		},
		{MAC: "aa:bb:cc:00:00:03", IP: "192.168.20.5", Sources: []string{store.SourceDHCP}},
	}
	if len(got) != len(want) {
		t.Fatalf("got %+v\nwant %+v", got, want)
	}
	for i := range want {
		g, w := got[i], want[i]
		if g.MAC != w.MAC || g.IP != w.IP || g.Hostname != w.Hostname || g.HostnameSource != w.HostnameSource ||
			g.Vendor != w.Vendor || !slices.Equal(g.Sources, w.Sources) || g.Seen != w.Seen {
			t.Errorf("host %d = %+v\nwant %+v", i, g, w)
		}
	}
}

type fakeSource struct {
	name string
	recs []Record
	err  error
}

func (f fakeSource) Name() string   { return f.name }
func (f fakeSource) Target() string { return f.name + ":test" }
func (f fakeSource) Records(context.Context) ([]Record, error) {
	return f.recs, f.err
}

func TestImportOneAuditEntryAndPartialFailure(t *testing.T) {
	st := openStore(t)
	ctx := t.Context()
	im := NewImporter(ImportConfig{
		Sources: []Source{
			fakeSource{name: store.SourcePihole, err: errors.New("connection refused")},
			fakeSource{name: store.SourceDHCP, recs: []Record{{MAC: "aa:bb:cc:00:00:03", IP: "192.168.20.5", Hostname: "tv", Lease: true}}},
		},
		Hosts: st.NetworkHosts(), Policy: policy.New(st.Audit()),
	})
	if err := im.Import(ctx); err != nil {
		t.Fatalf("Import with one source down = %v; want the others imported", err)
	}
	hosts, err := st.NetworkHosts().List(ctx)
	if err != nil || len(hosts) != 1 || hosts[0].Hostname != "tv" || !slices.Equal(hosts[0].Sources, []string{store.SourceDHCP}) {
		t.Fatalf("hosts = %+v, %v; want the lease's host", hosts, err)
	}
	entries, err := st.Audit().List(ctx, 10)
	if err != nil || len(entries) != 1 {
		t.Fatalf("audit = %+v, %v; want one entry per import", entries, err)
	}
	e := entries[0]
	if e.Action != string(policy.NetworkImport) || e.ActorKind != policy.ActorHub || e.Result != "ok" ||
		e.Target != "pihole:test,dhcp:test" {
		t.Errorf("audit entry = %+v", e)
	}
	var detail map[string]any
	if err := json.Unmarshal(e.Detail, &detail); err != nil {
		t.Fatal(err)
	}
	if detail["hosts"] != float64(1) || len(detail["failed"].([]any)) != 1 {
		t.Errorf("audit detail = %v", detail)
	}

	// Every source down: the import fails.
	im = NewImporter(ImportConfig{
		Sources: []Source{fakeSource{name: store.SourcePihole, err: errors.New("connection refused")}},
		Hosts:   st.NetworkHosts(), Policy: policy.New(st.Audit()),
	})
	if err := im.Import(ctx); err == nil {
		t.Error("Import with every source down succeeded")
	}
}

func TestImportDeniedByPolicyReadsNothing(t *testing.T) {
	st := openStore(t)
	cfg := policy.Config{Classes: map[policy.Class]policy.Mode{policy.Read: policy.ModeDeny}}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	read := false
	src := &readSpy{read: &read}
	im := NewImporter(ImportConfig{Sources: []Source{src}, Hosts: st.NetworkHosts(), Policy: policy.NewWithConfig(st.Audit(), nil, cfg)})
	if err := im.Import(t.Context()); !errors.Is(err, policy.ErrDenied) {
		t.Fatalf("Import = %v, want ErrDenied", err)
	}
	if read {
		t.Error("a denied import read its source")
	}
}

type readSpy struct{ read *bool }

func (*readSpy) Name() string   { return store.SourceDHCP }
func (*readSpy) Target() string { return "dhcp:spy" }
func (s *readSpy) Records(context.Context) ([]Record, error) {
	*s.read = true
	return nil, nil
}

func TestMergeRecordsClipsText(t *testing.T) {
	// "é" is 2 bytes: an odd cut lands inside one.
	multi := strings.Repeat("é", maxTextLen)
	for _, tt := range []struct {
		name, host, vendor string
		wantHost, wantVend string
	}{
		{"short", "pi5", "Raspberry Pi", "pi5", "Raspberry Pi"},
		{"vendor at the limit", "", strings.Repeat("v", maxTextLen), "", strings.Repeat("v", maxTextLen)},
		{"over-long vendor", "", strings.Repeat("v", 8<<20), "", strings.Repeat("v", maxTextLen)},
		{"over-long hostname", strings.Repeat("h", 1<<20), "", strings.Repeat("h", maxTextLen), ""},
		{"multi-byte vendor at the cut", "", multi, "", strings.Repeat("é", maxTextLen/2)},
		{"multi-byte hostname at the cut", multi, "", strings.Repeat("é", maxTextLen/2), ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := mergeRecords([]sourceRecords{{name: store.SourcePihole, recs: []Record{
				{MAC: "2c:cf:67:00:00:01", IP: "192.168.2.1", Hostname: tt.host, Vendor: tt.vendor},
			}}})
			if len(got) != 1 {
				t.Fatalf("got %d hosts, want 1", len(got))
			}
			if got[0].Hostname != tt.wantHost || got[0].Vendor != tt.wantVend {
				t.Errorf("hostname %d bytes, vendor %d bytes; want %d and %d", len(got[0].Hostname), len(got[0].Vendor), len(tt.wantHost), len(tt.wantVend))
			}
		})
	}
}

func manyRecords(n int) []Record {
	recs := make([]Record, n)
	for i := range recs {
		recs[i] = Record{MAC: fmt.Sprintf("02:00:00:00:%02x:%02x", i>>8, i&0xff), IP: "192.168.2.1"}
	}
	return recs
}

func TestImportHostCap(t *testing.T) {
	for _, tt := range []struct {
		name    string
		sources []Source
		wantErr string
		want    int // hosts stored
	}{
		{"at the cap", []Source{fakeSource{name: store.SourcePihole, recs: manyRecords(maxHostsPerSource)}}, "", maxHostsPerSource},
		{"over the cap", []Source{fakeSource{name: store.SourcePihole, recs: manyRecords(maxHostsPerSource + 1)}}, "too many hosts", 0},
		{"over-cap source skipped, the other imported", []Source{
			fakeSource{name: store.SourcePihole, recs: manyRecords(maxHostsPerSource + 1)},
			fakeSource{name: store.SourceDHCP, recs: manyRecords(2)},
		}, "", 2},
	} {
		t.Run(tt.name, func(t *testing.T) {
			st := openStore(t)
			im := NewImporter(ImportConfig{Sources: tt.sources, Hosts: st.NetworkHosts(), Policy: policy.New(st.Audit())})
			err := im.Import(t.Context())
			switch {
			case tt.wantErr == "" && err != nil:
				t.Fatalf("Import = %v", err)
			case tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)):
				t.Fatalf("Import = %v; want %q", err, tt.wantErr)
			}
			hosts, err := st.NetworkHosts().List(t.Context())
			if err != nil || len(hosts) != tt.want {
				t.Errorf("stored %d hosts, %v; want %d", len(hosts), err, tt.want)
			}
		})
	}
}
