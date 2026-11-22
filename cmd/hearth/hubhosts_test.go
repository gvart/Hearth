// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"log/slog"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/pki"
)

func addrs(ss ...string) []netip.Addr {
	var out []netip.Addr
	for _, s := range ss {
		out = append(out, netip.MustParseAddr(s))
	}
	return out
}

// TestDefaultHubHosts: without --host the certificate names the hostname,
// the LAN addresses and the loopback names, with a LAN address before a
// hostname other devices are unlikely to resolve.
func TestDefaultHubHosts(t *testing.T) {
	loop := []string{"localhost", "127.0.0.1", "::1"}
	tests := []struct {
		name, hostname string
		lan            []netip.Addr
		want           []string
	}{
		{
			"bare hostname after the LAN addresses", "DNP6J4RC7Q", addrs("192.168.2.124", "10.0.5.2"),
			append([]string{"192.168.2.124", "10.0.5.2", "DNP6J4RC7Q"}, loop...),
		},
		{
			".local hostname after the LAN addresses", "mac.local", addrs("192.168.2.124"),
			append([]string{"192.168.2.124", "mac.local"}, loop...),
		},
		{
			"FQDN first", "hub.home.arpa", addrs("192.168.2.124"),
			append([]string{"hub.home.arpa", "192.168.2.124"}, loop...),
		},
		{"no LAN address: as before", "pi", nil, append([]string{"pi"}, loop...)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := defaultHubHosts(tt.hostname, tt.lan); !slices.Equal(got, tt.want) {
				t.Errorf("defaultHubHosts(%q, %v) = %v, want %v", tt.hostname, tt.lan, got, tt.want)
			}
		})
	}
}

// TestHubHostsExplicit: --host is the certificate's names as given, with no
// LAN address added.
func TestHubHostsExplicit(t *testing.T) {
	log := slog.New(slog.DiscardHandler)
	flag := []string{"hub", "pi.lan"}
	if got := hubHosts(context.Background(), flag, log); !slices.Equal(got, flag) {
		t.Errorf("hubHosts(%v) = %v, want them unchanged", flag, got)
	}
	got := hubHosts(context.Background(), nil, log)
	if !slices.Contains(got, "localhost") || !slices.Contains(got, hostnameOr("localhost")) {
		t.Errorf("hubHosts() = %v, want the hostname and localhost", got)
	}
}

// TestServerCertCoversLANAddresses: the serving certificate is issued at
// start for the addresses of the moment, so after an address change a
// restart serves one for the new address, and agents that stored the
// hostname keep verifying it.
func TestServerCertCoversLANAddresses(t *testing.T) {
	ca, err := pki.LoadOrCreateCA(t.TempDir(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.DiscardHandler)
	for _, tc := range []struct {
		lan          []netip.Addr
		valid, wrong []string
	}{
		{addrs("192.168.2.124"), []string{"192.168.2.124", "dnp6j4rc7q", "localhost", "127.0.0.1"}, []string{"192.168.2.200", "169.254.1.1", "8.8.8.8"}},
		{addrs("192.168.2.200"), []string{"192.168.2.200", "dnp6j4rc7q"}, []string{"192.168.2.124"}},
	} {
		p, err := newServerCert(context.Background(), ca, defaultHubHosts("DNP6J4RC7Q", tc.lan), "", log)
		if err != nil {
			t.Fatal(err)
		}
		leaf := p.Load().Leaf
		for _, h := range tc.valid {
			if err := leaf.VerifyHostname(h); err != nil {
				t.Errorf("LAN %v: certificate does not cover %s: %v", tc.lan, h, err)
			}
		}
		for _, h := range tc.wrong {
			if leaf.VerifyHostname(h) == nil {
				t.Errorf("LAN %v: certificate covers %s", tc.lan, h)
			}
		}
	}
}
