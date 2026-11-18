// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"errors"
	"path/filepath"
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
