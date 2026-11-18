// SPDX-License-Identifier: AGPL-3.0-only

package discovery

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"
)

// Reverse DNS names the hosts mDNS did not, from the LAN's own resolver
// (the router usually knows its DHCP clients). Only a nameserver with a
// private or link-local address is asked, so a lookup never leaves the LAN:
// a hub whose resolv.conf points at a public resolver, or only at a
// loopback stub, skips reverse DNS.
const (
	rdnsTimeout     = 2 * time.Second
	rdnsConcurrency = 16
	resolvConf      = "/etc/resolv.conf"
)

// lanNameservers returns the private and link-local nameservers of a
// resolv.conf.
func lanNameservers(r io.Reader) []netip.Addr {
	var out []netip.Addr
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 2 || f[0] != "nameserver" {
			continue
		}
		ip, err := netip.ParseAddr(f[1])
		if err != nil {
			continue
		}
		ip = ip.WithZone("")
		if ip.IsPrivate() || ip.IsLinkLocalUnicast() {
			out = append(out, ip)
		}
	}
	return out
}

// lanResolver is a resolver that asks only the LAN nameservers of
// /etc/resolv.conf, or nil when there are none.
func lanResolver() *net.Resolver {
	f, err := os.Open(resolvConf)
	if err != nil {
		return nil
	}
	defer f.Close()
	ns := lanNameservers(f)
	if len(ns) == 0 {
		return nil
	}
	server := netip.AddrPortFrom(ns[0], 53).String()
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, server)
		},
	}
}

// reverseNames looks up the names of ips with r.
func reverseNames(ctx context.Context, r *net.Resolver, ips []netip.Addr) map[netip.Addr]string {
	out := map[netip.Addr]string{}
	if r == nil || len(ips) == 0 {
		return out
	}
	var mu sync.Mutex
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(rdnsConcurrency)
	for _, ip := range ips {
		g.Go(func() error {
			lctx, cancel := context.WithTimeout(gctx, rdnsTimeout)
			defer cancel()
			names, err := r.LookupAddr(lctx, ip.String())
			if err != nil || len(names) == 0 {
				return nil
			}
			mu.Lock()
			out[ip] = strings.TrimSuffix(names[0], ".")
			mu.Unlock()
			return nil
		})
	}
	_ = g.Wait()
	return out
}
