// SPDX-License-Identifier: AGPL-3.0-only

package discovery

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/gvart/hearth/internal/policy"
)

func TestScanAsAuditsItsActorAndFallsBackToTheHubsLANs(t *testing.T) {
	tests := []struct {
		name    string
		subnets []netip.Prefix
		target  string
	}{
		{"configured subnets", []netip.Prefix{netip.MustParsePrefix("10.0.0.0/30")}, "10.0.0.0/30"},
		{"none: the hub's own LANs", nil, "192.168.2.0/24"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			st := openStore(t)
			neigh := []Neighbor{{IP: netip.MustParseAddr("192.168.2.171"), MAC: mustMAC(t, "2c:cf:67:00:00:01")}}
			s, swept := fakeScanner(t, st, policy.New(st.Audit()), nil, &neigh)
			s.cfg.Subnets = tt.subnets
			accepted := false
			sum, err := s.ScanAs(t.Context(), policy.ActorWeb, "192.168.2.50", func() { accepted = true })
			if err != nil {
				t.Fatal(err)
			}
			if !accepted || len(*swept) != 1 {
				t.Fatalf("accepted = %v, swept %d times; want one accepted sweep", accepted, len(*swept))
			}
			if tt.subnets == nil && sum.Hosts != 1 {
				t.Errorf("summary = %+v; want the Pi", sum)
			}
			entries, err := st.Audit().List(t.Context(), 10)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 1 {
				t.Fatalf("audit = %+v; want one entry", entries)
			}
			if e := entries[0]; e.ActorKind != policy.ActorWeb || e.ActorID != "192.168.2.50" ||
				e.Action != string(policy.NetworkScan) || e.Result != "ok" || e.Target != tt.target {
				t.Errorf("audit entry = %+v", e)
			}
		})
	}
}

func TestScanAsDeniedIsNotAccepted(t *testing.T) {
	st := openStore(t)
	cfg := policy.Config{Actors: map[string]map[policy.Class]policy.Mode{policy.ActorWeb: {policy.Read: policy.ModeDeny}}}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	var neigh []Neighbor
	s, swept := fakeScanner(t, st, policy.NewWithConfig(st.Audit(), nil, cfg), nil, &neigh)
	_, err := s.ScanAs(t.Context(), policy.ActorWeb, "192.168.2.50", func() { t.Error("a denied scan was accepted") })
	if !errors.Is(err, policy.ErrDenied) {
		t.Fatalf("ScanAs = %v, want ErrDenied", err)
	}
	if len(*swept) != 0 {
		t.Error("a denied scan swept the network")
	}
}

// One scan by the hub runs at a time, whoever asked for it: the second is
// refused without a sweep or an audit entry.
func TestOneScanAtATime(t *testing.T) {
	st := openStore(t)
	var neigh []Neighbor
	s, _ := fakeScanner(t, st, policy.New(st.Audit()), nil, &neigh)
	inSweep, release := make(chan struct{}), make(chan struct{})
	s.sweep = func(context.Context, []netip.Addr) error {
		close(inSweep)
		<-release
		return nil
	}
	done := make(chan error, 1)
	go func() { done <- s.Scan(t.Context()) }()
	<-inSweep

	if err := s.Scan(t.Context()); !errors.Is(err, ErrScanRunning) {
		t.Errorf("scheduled Scan during a scan = %v, want ErrScanRunning", err)
	}
	if _, err := s.ScanAs(t.Context(), policy.ActorWeb, "192.168.2.50", nil); !errors.Is(err, ErrScanRunning) {
		t.Errorf("ScanAs during a scan = %v, want ErrScanRunning", err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	entries, _ := st.Audit().List(t.Context(), 10)
	if len(entries) != 1 {
		t.Errorf("audit = %+v; want the one scan that ran", entries)
	}
	// Once it is done, the next one runs.
	s.sweep = func(context.Context, []netip.Addr) error { return nil }
	if _, err := s.ScanAs(t.Context(), policy.ActorWeb, "192.168.2.50", nil); err != nil {
		t.Errorf("ScanAs after the scan = %v", err)
	}
}
