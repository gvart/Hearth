// SPDX-License-Identifier: AGPL-3.0-only

// Package discovery finds the hosts on the hub's LAN that have no agent:
// an unprivileged ARP sweep fills the OS neighbour table, which gives each
// host's MAC (and so its vendor), and mDNS and LAN reverse DNS give names.
// Results are stored keyed by MAC (store.NetworkHosts), so a host that
// changes IP stays one host. Nothing leaves the LAN.
package discovery

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

// Event types published for hosts a scan finds.
const (
	// EventNew is a host no scan had found before.
	EventNew = "network.device.new"
	// EventReturned is a known host back after Config.AbsentAfter or more
	// unseen.
	EventReturned = "network.device.returned"
)

// Defaults.
const (
	DefaultInterval    = 5 * time.Minute
	DefaultAbsentAfter = time.Hour
	// actorID is the audit actor of scans: hub/discovery.
	actorID = "discovery"
)

// Hosts stores scan results: store.NetworkHosts.
type Hosts interface {
	RecordScan(ctx context.Context, at time.Time, absentAfter time.Duration, hosts []store.NetworkHost) (store.ScanResult, error)
}

// Policy decides on and audits each scan: *policy.Engine.
type Policy interface {
	Do(ctx context.Context, req policy.Request, fn func(context.Context) error) error
}

// Events receives the new and returned hosts of each scan, all the hosts of
// one type at once.
type Events interface {
	NetworkHosts(typ string, hosts []store.NetworkHost)
}

// Config holds the scanner's dependencies and settings.
type Config struct {
	// Subnets are swept on every scan; with Auto, so are the hub's own LANs
	// (see the Auto constant), looked up again on each scan.
	Subnets []netip.Prefix
	Auto    bool
	// Interval is the time between scans; DefaultInterval if zero.
	Interval time.Duration
	// AbsentAfter is how long a host must go unseen to count as returned;
	// DefaultAbsentAfter if zero.
	AbsentAfter time.Duration
	Hosts       Hosts
	Policy      Policy
	// Events may be nil.
	Events Events
	Log    *slog.Logger
}

// Scanner scans the configured subnets every Interval.
type Scanner struct {
	cfg Config
	log *slog.Logger
	now func() time.Time

	// The steps of a scan, replaced in tests.
	localNets func() ([]localNet, error)
	sweep     func(ctx context.Context, targets []netip.Addr) error
	neighbors func() ([]Neighbor, error)
	mdns      func(ctx context.Context, ifaces []net.Interface, ips []netip.Addr) (map[netip.Addr]string, error)
	rdns      func(ctx context.Context, ips []netip.Addr) map[netip.Addr]string
}

// New returns a scanner. Call Run to start scanning.
func New(cfg Config) *Scanner {
	if cfg.Interval <= 0 {
		cfg.Interval = DefaultInterval
	}
	if cfg.AbsentAfter <= 0 {
		cfg.AbsentAfter = DefaultAbsentAfter
	}
	log := cfg.Log
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Scanner{
		cfg: cfg, log: log, now: time.Now,
		localNets: localNets, sweep: sweep, neighbors: readNeighbors, mdns: mdnsNames,
		rdns: func(ctx context.Context, ips []netip.Addr) map[netip.Addr]string {
			return reverseNames(ctx, lanResolver(), ips)
		},
	}
}

// Run scans at once and then every Interval until ctx is done. A failed
// scan is logged; the next one runs on schedule.
func (s *Scanner) Run(ctx context.Context) error {
	t := time.NewTicker(s.cfg.Interval)
	defer t.Stop()
	for {
		if err := s.Scan(ctx); err != nil && ctx.Err() == nil {
			s.log.WarnContext(ctx, "network scan failed", "err", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}

// Scan runs one scan through policy (network.scan, one audit entry per
// scan), records what it found and publishes the new and returned hosts.
func (s *Scanner) Scan(ctx context.Context) error {
	nets, err := s.localNets()
	if err != nil {
		return err
	}
	subnets := slices.Clone(s.cfg.Subnets)
	if s.cfg.Auto {
		for _, p := range autoSubnets(nets) {
			if !slices.Contains(subnets, p) {
				subnets = append(subnets, p)
			}
		}
	}
	if len(subnets) == 0 {
		return errors.New("no subnet to scan: the hub has no private IPv4 address")
	}
	names := make([]string, len(subnets))
	for i, p := range subnets {
		names[i] = p.String()
	}
	// The policy engine encodes Detail after fn returns, so the counts
	// filled in below are audited with the scan.
	detail := map[string]any{"subnets": names}
	var res store.ScanResult
	err = s.cfg.Policy.Do(ctx, policy.Request{
		ActorKind: policy.ActorHub,
		ActorID:   actorID,
		Action:    policy.NetworkScan,
		Target:    strings.Join(names, ","),
		Detail:    detail,
	}, func(ctx context.Context) error {
		start := s.now()
		hosts, err := s.find(ctx, subnets, nets)
		if err != nil {
			return err
		}
		res, err = s.cfg.Hosts.RecordScan(ctx, start, s.cfg.AbsentAfter, hosts)
		if err != nil {
			return err
		}
		took := s.now().Sub(start)
		detail["hosts"], detail["new"], detail["returned"] = len(hosts), len(res.New), len(res.Returned)
		detail["duration_ms"] = took.Milliseconds()
		s.log.InfoContext(ctx, "network scan", "subnets", names, "hosts", len(hosts),
			"new", len(res.New), "returned", len(res.Returned), "took", took.Round(time.Millisecond))
		return nil
	})
	if err != nil {
		return fmt.Errorf("network scan: %w", err)
	}
	if s.cfg.Events != nil {
		s.cfg.Events.NetworkHosts(EventNew, res.New)
		s.cfg.Events.NetworkHosts(EventReturned, res.Returned)
	}
	return nil
}

// find sweeps subnets and names the hosts that answered.
func (s *Scanner) find(ctx context.Context, subnets []netip.Prefix, nets []localNet) ([]store.NetworkHost, error) {
	own := map[netip.Addr]bool{}
	var ifaces []net.Interface
	for _, n := range nets {
		own[n.addr] = true
		for _, p := range subnets {
			if p.Overlaps(n.prefix) && !slices.ContainsFunc(ifaces, func(i net.Interface) bool { return i.Index == n.iface.Index }) {
				ifaces = append(ifaces, n.iface)
			}
		}
	}
	if len(ifaces) == 0 {
		s.log.WarnContext(ctx, "no interface of the hub is on the subnets to scan; "+
			"the sweep only finds hosts on a directly attached network", "subnets", subnets)
	}
	var targets []netip.Addr
	for _, p := range subnets {
		for _, a := range hostsOf(p) {
			if !own[a] {
				targets = append(targets, a)
			}
		}
	}
	if err := s.sweep(ctx, targets); err != nil {
		return nil, err
	}
	neigh, err := s.neighbors()
	if err != nil {
		return nil, err
	}

	// One host per MAC: a MAC answering on several addresses (a router's
	// aliases) keeps the lowest.
	slices.SortFunc(neigh, func(a, b Neighbor) int { return a.IP.Compare(b.IP) })
	byMAC := map[string]bool{}
	var found []Neighbor
	for _, n := range neigh {
		mac := n.MAC.String()
		if byMAC[mac] || own[n.IP] || !slices.ContainsFunc(subnets, func(p netip.Prefix) bool { return p.Contains(n.IP) }) {
			continue
		}
		byMAC[mac] = true
		found = append(found, n)
	}
	ips := make([]netip.Addr, len(found))
	for i, n := range found {
		ips[i] = n.IP
	}

	names := map[netip.Addr]string{}
	if len(ips) > 0 && len(ifaces) > 0 {
		m, err := s.mdns(ctx, ifaces, ips)
		if err != nil && ctx.Err() == nil {
			s.log.DebugContext(ctx, "mdns", "err", err)
		}
		names = m
		if names == nil {
			names = map[netip.Addr]string{}
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var unnamed []netip.Addr
	for _, ip := range ips {
		if names[ip] == "" {
			unnamed = append(unnamed, ip)
		}
	}
	for ip, name := range s.rdns(ctx, unnamed) {
		names[ip] = name
	}

	hosts := make([]store.NetworkHost, 0, len(found))
	for _, n := range found {
		hosts = append(hosts, store.NetworkHost{
			MAC: n.MAC.String(), IP: n.IP.String(), Hostname: names[n.IP], Vendor: Vendor(n.MAC),
		})
	}
	return hosts, ctx.Err()
}
