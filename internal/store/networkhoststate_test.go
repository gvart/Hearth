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
