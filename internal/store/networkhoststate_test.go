// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestNetworkHostState(t *testing.T) {
	s := openTest(t)
	ctx := t.Context()
	hosts := s.NetworkHosts()
	t0 := time.UnixMilli(1_700_000_000_000).UTC()
	router := NetworkHost{MAC: "00:11:22:00:00:01", IP: "192.168.2.1"}
	phone := NetworkHost{MAC: "3c:2e:f9:00:00:03", IP: "192.168.2.30"}
	if _, err := hosts.RecordScan(ctx, t0, time.Hour, []NetworkHost{router}); err != nil {
		t.Fatal(err)
	}
	res, err := hosts.RecordScan(ctx, t0.Add(time.Minute), time.Hour, []NetworkHost{router, phone})
	if err != nil || len(res.New) != 1 || res.New[0].State != HostUnreviewed {
		t.Fatalf("phone joins = %+v, %v; want it new and unreviewed", res, err)
	}

	if err := hosts.SetState(ctx, phone.MAC, HostIgnored); err != nil {
		t.Fatal(err)
	}
	if err := hosts.SetState(ctx, router.MAC, HostKnown); err != nil {
		t.Fatal(err)
	}
	// A rescan keeps the state, and a returned host carries it.
	res, err = hosts.RecordScan(ctx, t0.Add(3*time.Hour), time.Hour, []NetworkHost{router, phone})
	if err != nil || len(res.Returned) != 2 {
		t.Fatalf("rescan = %+v, %v; want both returned", res, err)
	}
	want := map[string]string{router.MAC: HostKnown, phone.MAC: HostIgnored}
	for _, h := range res.Returned {
		if h.State != want[h.MAC] {
			t.Errorf("returned %s state = %q, want %q", h.MAC, h.State, want[h.MAC])
		}
	}
	list, err := hosts.List(ctx)
	if err != nil || len(list) != 2 || list[0].State != HostKnown || list[1].State != HostIgnored {
		t.Fatalf("List = %+v, %v; want the router known and the phone ignored", list, err)
	}
	if err := hosts.SetState(ctx, phone.MAC, HostUnreviewed); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name, mac, state string
		want             error
	}{
		{"unknown host", "aa:aa:aa:aa:aa:aa", HostKnown, ErrNotFound},
		{"unknown state", phone.MAC, "trusted", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := hosts.SetState(ctx, tt.mac, tt.state)
			if err == nil || (tt.want != nil && !errors.Is(err, tt.want)) {
				t.Errorf("SetState(%s, %q) = %v, want %v", tt.mac, tt.state, err, tt.want)
			}
		})
	}
}

// A newer binary on a cluster database at schema 12 lists and records hosts
// as unreviewed, and marks none.
func TestNetworkHostStateBeforeItsSchema(t *testing.T) {
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
	if _, err := p.DownTo(ctx, networkHostStateSchema-1); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	s, err = Open(ctx, path, WithoutUpgrade())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })

	hosts := s.NetworkHosts()
	t0 := time.UnixMilli(1_700_000_000_000).UTC()
	router := NetworkHost{MAC: "00:11:22:00:00:01", IP: "192.168.2.1"}
	phone := NetworkHost{MAC: "3c:2e:f9:00:00:03", IP: "192.168.2.30"}
	if _, err := hosts.RecordScan(ctx, t0, time.Hour, []NetworkHost{router}); err != nil {
		t.Fatal(err)
	}
	res, err := hosts.RecordScan(ctx, t0.Add(time.Minute), time.Hour, []NetworkHost{router, phone})
	if err != nil || len(res.New) != 1 || res.New[0].State != HostUnreviewed {
		t.Fatalf("scan at schema 12 = %+v, %v; want the phone new", res, err)
	}
	if list, err := hosts.List(ctx); err != nil || len(list) != 2 {
		t.Fatalf("List at schema 12 = %+v, %v", list, err)
	}
	err = hosts.SetState(ctx, phone.MAC, HostKnown)
	if !errors.Is(err, ErrSchemaTooOld) || !IsDomainError(err) {
		t.Errorf("SetState before the schema = %v, want a domain ErrSchemaTooOld", err)
	}
}

func TestNetworkHostAdopt(t *testing.T) {
	s := openTest(t)
	ctx := t.Context()
	hosts := s.NetworkHosts()
	t0 := time.UnixMilli(1_700_000_000_000).UTC()
	tv := NetworkHost{MAC: "00:11:22:00:00:05", IP: "192.168.2.50", Vendor: "LG"}
	if _, err := hosts.RecordScan(ctx, t0, time.Hour, []NetworkHost{tv}); err != nil {
		t.Fatal(err)
	}
	get := func() NetworkHost {
		t.Helper()
		list, err := hosts.List(ctx)
		if err != nil || len(list) != 1 {
			t.Fatalf("List = %+v, %v", list, err)
		}
		return list[0]
	}

	if err := hosts.Adopt(ctx, tv.MAC, "Living room TV"); err != nil {
		t.Fatal(err)
	}
	if h := get(); h.State != HostAdopted || h.Name != "Living room TV" {
		t.Fatalf("after adopt = %+v", h)
	}
	// A rescan keeps the adoption and the name.
	if _, err := hosts.RecordScan(ctx, t0.Add(time.Minute), time.Hour, []NetworkHost{tv}); err != nil {
		t.Fatal(err)
	}
	if h := get(); h.State != HostAdopted || h.Name != "Living room TV" {
		t.Fatalf("after rescan = %+v", h)
	}
	if err := hosts.Adopt(ctx, tv.MAC, "TV"); err != nil {
		t.Fatal(err)
	}
	if h := get(); h.Name != "TV" {
		t.Fatalf("after rename = %+v", h)
	}

	if err := hosts.Unadopt(ctx, tv.MAC); err != nil {
		t.Fatal(err)
	}
	if h := get(); h.State != HostUnreviewed || h.Name != "" {
		t.Fatalf("after unadopt = %+v; want unreviewed without a name", h)
	}

	// Unadopting a host that is not adopted leaves its mark alone.
	if err := hosts.SetState(ctx, tv.MAC, HostKnown); err != nil {
		t.Fatal(err)
	}
	if err := hosts.Unadopt(ctx, tv.MAC); err != nil {
		t.Fatal(err)
	}
	if h := get(); h.State != HostKnown {
		t.Fatalf("unadopt of a known host = %+v; want it still known", h)
	}

	// Marking an adopted host drops its name.
	if err := hosts.Adopt(ctx, tv.MAC, "TV"); err != nil {
		t.Fatal(err)
	}
	if err := hosts.SetState(ctx, tv.MAC, HostIgnored); err != nil {
		t.Fatal(err)
	}
	if h := get(); h.State != HostIgnored || h.Name != "" {
		t.Fatalf("ignore of an adopted host = %+v; want ignored without a name", h)
	}

	for _, tt := range []struct {
		name string
		err  error
	}{
		{"adopt", hosts.Adopt(ctx, "aa:aa:aa:aa:aa:aa", "x")},
		{"unadopt", hosts.Unadopt(ctx, "aa:aa:aa:aa:aa:aa")},
	} {
		if !errors.Is(tt.err, ErrNotFound) {
			t.Errorf("%s of an unknown host = %v, want ErrNotFound", tt.name, tt.err)
		}
	}
	if err := hosts.Adopt(ctx, tv.MAC, ""); err == nil {
		t.Error("adopt without a name: want an error")
	}
	if err := hosts.SetState(ctx, tv.MAC, HostAdopted); err == nil {
		t.Error("SetState(adopted): want an error, adopting needs a name")
	}
}

// A newer binary on a cluster database at schema 31 lists hosts without a
// name and marks them, but adopts none.
func TestNetworkHostAdoptBeforeItsSchema(t *testing.T) {
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
	if _, err := p.DownTo(ctx, networkHostServicesSchema); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	s, err = Open(ctx, path, WithoutUpgrade())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })

	hosts := s.NetworkHosts()
	tv := NetworkHost{MAC: "00:11:22:00:00:05", IP: "192.168.2.50"}
	if _, err := hosts.RecordScan(ctx, time.UnixMilli(1_700_000_000_000), time.Hour, []NetworkHost{tv}); err != nil {
		t.Fatal(err)
	}
	if err := hosts.SetState(ctx, tv.MAC, HostKnown); err != nil {
		t.Fatalf("SetState before the schema = %v", err)
	}
	err = hosts.Adopt(ctx, tv.MAC, "TV")
	if !errors.Is(err, ErrSchemaTooOld) || !IsDomainError(err) {
		t.Errorf("Adopt before the schema = %v, want a domain ErrSchemaTooOld", err)
	}
	if list, err := hosts.List(ctx); err != nil || len(list) != 1 || list[0].State != HostKnown || list[0].Name != "" {
		t.Errorf("List before the schema = %+v, %v", list, err)
	}

	// The migration keeps the mark, and then the host can be adopted.
	_ = s.Close()
	s, err = Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	hosts = s.NetworkHosts()
	if list, err := hosts.List(ctx); err != nil || len(list) != 1 || list[0].State != HostKnown {
		t.Fatalf("List after the migration = %+v, %v; want the host still known", list, err)
	}
	if err := hosts.Adopt(ctx, tv.MAC, "TV"); err != nil {
		t.Errorf("Adopt after the migration = %v", err)
	}
}
