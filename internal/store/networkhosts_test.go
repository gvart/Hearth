// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"errors"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

func TestNetworkHostsRescanKeyedByMAC(t *testing.T) {
	s := openTest(t)
	ctx := t.Context()
	hosts := s.NetworkHosts()
	t0 := time.UnixMilli(1_700_000_000_000).UTC()
	const absent = time.Hour
	pi := NetworkHost{MAC: "2c:cf:67:00:00:01", IP: "192.168.2.171", Hostname: "pi5.local", Vendor: "Raspberry Pi"}
	nas := NetworkHost{MAC: "00:11:32:00:00:02", IP: "192.168.2.20", Vendor: "Synology"}

	// The first scan is the baseline: stored, nothing new.
	res, err := hosts.RecordScan(ctx, t0, absent, []NetworkHost{pi, nas})
	if err != nil || len(res.New) != 0 || len(res.Returned) != 0 {
		t.Fatalf("baseline scan = %+v, %v; want no events", res, err)
	}

	// The Pi moves to another IP and the scan finds no hostname for it; a
	// phone joins.
	pi2 := pi
	pi2.IP, pi2.Hostname, pi2.Vendor = "192.168.2.172", "", ""
	phone := NetworkHost{MAC: "3c:2e:f9:00:00:03", IP: "192.168.2.30", Vendor: "Apple"}
	t1 := t0.Add(5 * time.Minute)
	res, err = hosts.RecordScan(ctx, t1, absent, []NetworkHost{pi2, nas, phone})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.New) != 1 || res.New[0].MAC != phone.MAC || len(res.Returned) != 0 {
		t.Fatalf("rescan = %+v; want the phone new, nothing returned", res)
	}

	list, err := hosts.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 3 {
		t.Fatalf("List = %+v; want 3 hosts, no duplicates", list)
	}
	byMAC := map[string]NetworkHost{}
	for _, h := range list {
		byMAC[h.MAC] = h
	}
	got := byMAC[pi.MAC]
	if got.IP != "192.168.2.172" || got.Hostname != "pi5.local" || got.Vendor != "Raspberry Pi" ||
		!got.FirstSeen.Equal(t0) || !got.LastSeen.Equal(t1) {
		t.Errorf("Pi after moving = %+v; want the new IP, the kept hostname and vendor, first seen at t0", got)
	}

	// The phone leaves for longer than absentAfter and comes back; the NAS
	// was seen recently and is not "returned".
	t2 := t1.Add(2 * time.Hour)
	if _, err := hosts.RecordScan(ctx, t2.Add(-time.Minute), absent, []NetworkHost{nas}); err != nil {
		t.Fatal(err)
	}
	res, err = hosts.RecordScan(ctx, t2, absent, []NetworkHost{nas, phone})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.New) != 0 || len(res.Returned) != 1 || res.Returned[0].MAC != phone.MAC {
		t.Fatalf("return scan = %+v; want only the phone returned", res)
	}

	if _, err := hosts.RecordScan(ctx, t2, absent, []NetworkHost{{MAC: "aa:aa:aa:aa:aa:aa"}}); err == nil {
		t.Error("RecordScan of a host without an IP succeeded")
	}
}

// A newer binary on a cluster database before schema 12 records no scans:
// the write is refused the same way on every node.
func TestNetworkHostsBeforeTheirSchema(t *testing.T) {
	ctx := t.Context()
	path := filepath.Join(t.TempDir(), "hearth.db")
	s, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	p, err := s.newMigrator()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.DownTo(ctx, networkHostsSchema-1); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	s, err = Open(ctx, path, WithoutUpgrade())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })

	if got, err := s.NetworkHosts().List(ctx); err != nil || len(got) != 0 {
		t.Errorf("List before the schema = %v, %v; want none", got, err)
	}
	_, err = s.NetworkHosts().RecordScan(ctx, time.Now(), time.Hour, []NetworkHost{{MAC: "aa:aa:aa:aa:aa:aa", IP: "10.0.0.2"}})
	if !errors.Is(err, ErrSchemaTooOld) || !IsDomainError(err) {
		t.Errorf("RecordScan before the schema = %v, want a domain ErrSchemaTooOld", err)
	}
}

// Names Pi-hole or a DHCP lease gave override and outlast scan names; an
// import adds hosts no scan saw, and moves IP and last_seen only with its
// own observation time.
func TestNetworkHostsImportMergesByMAC(t *testing.T) {
	s := openTest(t)
	ctx := t.Context()
	hosts := s.NetworkHosts()
	t0 := time.UnixMilli(1_700_000_000_000).UTC()
	pi := NetworkHost{MAC: "2c:cf:67:00:00:01", IP: "192.168.2.171", Hostname: "raspberrypi.local", Vendor: "Raspberry Pi"}
	nas := NetworkHost{MAC: "00:11:32:00:00:02", IP: "192.168.2.20", Hostname: "nas.local", Vendor: "Synology"}
	if _, err := hosts.RecordScan(ctx, t0, time.Hour, []NetworkHost{pi, nas}); err != nil {
		t.Fatal(err)
	}

	t1 := t0.Add(time.Minute)
	err := hosts.RecordImport(ctx, t1, []ImportedHost{
		// Pi-hole names the Pi and saw it after the scan, on a new IP.
		{
			MAC: pi.MAC, IP: "192.168.2.180", Hostname: "pi5", HostnameSource: SourcePihole,
			Sources: []string{SourcePihole}, Seen: t1.UnixMilli(),
		},
		// A lease without a time for the NAS: no IP or last_seen change.
		{MAC: nas.MAC, IP: "192.168.2.99", Sources: []string{SourceDHCP}},
		// A host on another VLAN, unseen by ARP.
		{
			MAC: "aa:bb:cc:00:00:03", IP: "192.168.20.5", Hostname: "tv", HostnameSource: SourceDHCP,
			Vendor: "LG", Sources: []string{SourceDHCP, SourcePihole},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	// A rescan finds the Pi's mDNS name again: the Pi-hole name stays, the
	// scan's IP wins.
	t2 := t1.Add(time.Minute)
	if _, err := hosts.RecordScan(ctx, t2, time.Hour, []NetworkHost{pi}); err != nil {
		t.Fatal(err)
	}

	list, err := hosts.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	byMAC := map[string]NetworkHost{}
	for _, h := range list {
		byMAC[h.MAC] = h
	}
	tests := []struct {
		mac, ip, name, nameSource string
		sources                   []string
		lastSeen                  time.Time
	}{
		{pi.MAC, pi.IP, "pi5", SourcePihole, []string{SourcePihole, SourceScan}, t2},
		{nas.MAC, nas.IP, "nas.local", SourceScan, []string{SourceDHCP, SourceScan}, t0},
		{"aa:bb:cc:00:00:03", "192.168.20.5", "tv", SourceDHCP, []string{SourceDHCP, SourcePihole}, t1},
	}
	for _, tt := range tests {
		got := byMAC[tt.mac]
		if got.IP != tt.ip || got.Hostname != tt.name || got.HostnameSource != tt.nameSource ||
			!slices.Equal(got.Sources, tt.sources) || !got.LastSeen.Equal(tt.lastSeen) {
			t.Errorf("%s = %+v; want ip %s, name %q from %s, sources %v, last seen %v",
				tt.mac, got, tt.ip, tt.name, tt.nameSource, tt.sources, tt.lastSeen)
		}
	}

	if err := hosts.RecordImport(ctx, t2, []ImportedHost{{MAC: "aa:aa:aa:aa:aa:aa", IP: "10.0.0.2"}}); err == nil {
		t.Error("RecordImport of a host without a source succeeded")
	}
}

// New and baseline count scans only: an import before the first scan does
// not end the baseline, and a host an import added is new to the first
// scan that finds it.
func TestNetworkHostsImportKeepsScanEvents(t *testing.T) {
	s := openTest(t)
	ctx := t.Context()
	hosts := s.NetworkHosts()
	t0 := time.UnixMilli(1_700_000_000_000).UTC()
	phone := NetworkHost{MAC: "3c:2e:f9:00:00:03", IP: "192.168.2.30"}
	nas := NetworkHost{MAC: "00:11:32:00:00:02", IP: "192.168.2.20"}
	tv := NetworkHost{MAC: "aa:bb:cc:00:00:04", IP: "192.168.2.40"}
	if err := hosts.RecordImport(ctx, t0, []ImportedHost{
		{MAC: nas.MAC, IP: nas.IP, Sources: []string{SourceDHCP}},
		{MAC: phone.MAC, IP: phone.IP, Hostname: "phone", HostnameSource: SourcePihole, Sources: []string{SourcePihole}},
	}); err != nil {
		t.Fatal(err)
	}
	res, err := hosts.RecordScan(ctx, t0.Add(time.Minute), time.Hour, []NetworkHost{nas, tv})
	if err != nil || len(res.New) != 0 || len(res.Returned) != 0 {
		t.Fatalf("first scan after an import = %+v, %v; want the baseline, no events", res, err)
	}
	res, err = hosts.RecordScan(ctx, t0.Add(2*time.Minute), time.Hour, []NetworkHost{nas, tv, phone})
	if err != nil || len(res.New) != 1 || res.New[0].MAC != phone.MAC || res.New[0].Hostname != "phone" {
		t.Fatalf("scan finding the imported phone = %+v, %v; want it new, with its Pi-hole name", res, err)
	}
}

// Before schema 14 an import is refused the same way on every node, and
// scans still record.
func TestNetworkHostsImportBeforeItsSchema(t *testing.T) {
	ctx := t.Context()
	path := filepath.Join(t.TempDir(), "hearth.db")
	s, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	p, err := s.newMigrator()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.DownTo(ctx, networkHostSourcesSchema-1); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	s, err = Open(ctx, path, WithoutUpgrade())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })

	err = s.NetworkHosts().RecordImport(ctx, time.Now(), []ImportedHost{{MAC: "aa:aa:aa:aa:aa:aa", IP: "10.0.0.2", Sources: []string{SourceDHCP}}})
	if !errors.Is(err, ErrSchemaTooOld) || !IsDomainError(err) {
		t.Errorf("RecordImport before the schema = %v, want a domain ErrSchemaTooOld", err)
	}
	if _, err := s.NetworkHosts().RecordScan(ctx, time.Now(), time.Hour, []NetworkHost{{MAC: "aa:aa:aa:aa:aa:aa", IP: "10.0.0.2", Hostname: "x.local"}}); err != nil {
		t.Fatalf("RecordScan at schema 13: %v", err)
	}
	if got, err := s.NetworkHosts().List(ctx); err != nil || len(got) != 1 || got[0].Hostname != "x.local" || got[0].Sources != nil {
		t.Errorf("List at schema 13 = %+v, %v; want the scanned host without sources", got, err)
	}
}
