// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"net/netip"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

// Services a scan hears replace the stored ones; a scan that hears none
// keeps them. A scan that flags a gateway unflags the one it replaced in its
// subnets; a scan that flags none (a device's, say) changes no flag.
func TestNetworkHostsServicesAndGateway(t *testing.T) {
	s := openTest(t)
	ctx := t.Context()
	hosts := s.NetworkHosts()
	t0 := time.UnixMilli(1_700_000_000_000).UTC()
	lan := ScanScope{Subnets: []netip.Prefix{netip.MustParsePrefix("192.168.2.0/24")}}
	other := ScanScope{Subnets: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}}
	router := NetworkHost{MAC: "00:11:32:00:00:01", IP: "192.168.2.1", Gateway: true}
	printer := NetworkHost{MAC: "00:11:32:00:00:02", IP: "192.168.2.30", Services: []string{"_ipp._tcp", "_printer._tcp"}}
	vlanGW := NetworkHost{MAC: "00:11:32:00:00:09", IP: "10.0.0.1", Gateway: true}
	byMAC := func() map[string]NetworkHost {
		t.Helper()
		list, err := hosts.List(ctx)
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]NetworkHost{}
		for _, h := range list {
			out[h.MAC] = h
		}
		return out
	}

	if _, err := hosts.RecordScanFrom(ctx, t0, time.Hour, lan, []NetworkHost{router, printer}); err != nil {
		t.Fatal(err)
	}
	if _, err := hosts.RecordScanFrom(ctx, t0, time.Hour, other, []NetworkHost{vlanGW}); err != nil {
		t.Fatal(err)
	}
	got := byMAC()
	if !got[router.MAC].Gateway || got[printer.MAC].Gateway || !slices.Equal(got[printer.MAC].Services, printer.Services) {
		t.Fatalf("after the first scans: %+v", got)
	}

	// mDNS misses the printer; a device's scan of the LAN flags nothing.
	quiet := printer
	quiet.Services = nil
	plain := router
	plain.Gateway = false
	if _, err := hosts.RecordScanFrom(ctx, t0.Add(time.Minute), time.Hour,
		ScanScope{ScannedBy: "dev-pi", Subnets: lan.Subnets}, []NetworkHost{plain, quiet}); err != nil {
		t.Fatal(err)
	}
	got = byMAC()
	if !got[router.MAC].Gateway || !slices.Equal(got[printer.MAC].Services, printer.Services) {
		t.Errorf("after a scan that heard nothing: %+v; want the gateway and services kept", got)
	}

	// The router is replaced; the old one is not even seen.
	newRouter := NetworkHost{MAC: "00:11:32:00:00:03", IP: "192.168.2.1", Gateway: true}
	printer.Services = []string{"_ipps._tcp"}
	if _, err := hosts.RecordScanFrom(ctx, t0.Add(2*time.Minute), time.Hour, lan, []NetworkHost{newRouter, printer}); err != nil {
		t.Fatal(err)
	}
	got = byMAC()
	if got[router.MAC].Gateway || !got[newRouter.MAC].Gateway || !got[vlanGW.MAC].Gateway {
		t.Errorf("after the router changed: %+v; want only the new router and the other subnet's gateway flagged", got)
	}
	if !slices.Equal(got[printer.MAC].Services, []string{"_ipps._tcp"}) {
		t.Errorf("printer services = %v; want the newly heard ones", got[printer.MAC].Services)
	}
}

// Before schema 31 a scan records no services and no gateway.
func TestNetworkHostsServicesBeforeTheirSchema(t *testing.T) {
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
	if _, err := p.DownTo(ctx, networkHostServicesSchema-1); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	s, err = Open(ctx, path, WithoutUpgrade())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	host := NetworkHost{MAC: "aa:aa:aa:aa:aa:aa", IP: "10.0.0.1", Services: []string{"_ssh._tcp"}, Gateway: true}
	if _, err := s.NetworkHosts().RecordScan(ctx, time.Now(), time.Hour, []NetworkHost{host}); err != nil {
		t.Fatal(err)
	}
	list, err := s.NetworkHosts().List(ctx)
	if err != nil || len(list) != 1 || list[0].Services != nil || list[0].Gateway {
		t.Errorf("List = %+v, %v; want the host, with no services and not the gateway", list, err)
	}
}

// A schema-31 database whose writes are capped below it (a cluster with an
// older live member) writes neither column.
func TestNetworkHostsServicesCappedWriteSchema(t *testing.T) {
	ctx := t.Context()
	s, err := Open(ctx, filepath.Join(t.TempDir(), "hearth.db"),
		WithWriteSchema(func() int64 { return networkHostServicesSchema - 1 }))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	host := NetworkHost{MAC: "aa:aa:aa:aa:aa:aa", IP: "10.0.0.1", Services: []string{"_ssh._tcp"}, Gateway: true}
	if _, err := s.NetworkHosts().RecordScan(ctx, time.Now(), time.Hour, []NetworkHost{host}); err != nil {
		t.Fatal(err)
	}
	list, err := s.NetworkHosts().List(ctx)
	if err != nil || len(list) != 1 || list[0].Services != nil || list[0].Gateway {
		t.Errorf("List = %+v, %v; want no services and not the gateway", list, err)
	}
}
