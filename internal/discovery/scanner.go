// SPDX-License-Identifier: AGPL-3.0-only

// Package discovery finds the hosts on the hub's LAN that have no agent:
// an unprivileged ARP sweep fills the OS neighbour table, which gives each
// host's MAC (and so its vendor), and mDNS and LAN reverse DNS give names.
// A subnet the hub is not attached to can be swept by a device's agent
// instead (Config.From, Find). Results are stored keyed by MAC
// (store.NetworkHosts), so a host that changes IP stays one host. Nothing
// leaves the LAN.
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
	"sync"
	"time"
	"unicode/utf8"

	"github.com/gvart/hearth/internal/policy"
	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
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
	// AgentScanTimeout bounds a scan from a device; the hub waits a little
	// longer for the agent's answer.
	AgentScanTimeout = 2 * time.Minute
	agentScanGrace   = 10 * time.Second
)

// ErrScanRunning is returned by Scan and ScanAs while another scan by the hub
// is running: nothing is swept and nothing is audited.
var ErrScanRunning = errors.New("a network scan is already running")

// ErrNoSubnet is returned by Scan and ScanAs when there is nothing to sweep:
// no subnet is configured and the hub has no private IPv4 address.
var ErrNoSubnet = errors.New("no subnet to scan: the hub has no private IPv4 address")

// ErrScanSkipped is returned by ScanFrom for a scan it did not attempt: the
// device is unknown or its agent is not connected to this hub. Nothing is
// sent and nothing is audited; the next scan tries again.
var ErrScanSkipped = errors.New("network scan skipped")

// Hosts stores scan results: store.NetworkHosts.
type Hosts interface {
	RecordScanFrom(ctx context.Context, at time.Time, absentAfter time.Duration, scope store.ScanScope,
		hosts []store.NetworkHost) (store.ScanResult, error)
}

// Agents runs scans on the agents of devices: *hub.Agents.
type Agents interface {
	// CheckScan fails, with an error wrapping policy.ErrBeyondCeiling, when
	// the agent of device (an id, name or hostname) would not be sent a scan
	// of subnets: it is too old, or its ceiling does not allow them.
	CheckScan(ctx context.Context, device string, subnets []netip.Prefix) error
	// Scan has the agent of device sweep subnets within timeout, and returns
	// the device's id and the agent's answer.
	Scan(ctx context.Context, device string, subnets []netip.Prefix, timeout time.Duration) (string, *agentv1.ScanResult, error)
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
	// From are the subnets swept from devices, by device (an id, name or
	// hostname): its agent sweeps them, if its ceiling allows, for subnets
	// the hub is not attached to. Each device's scan is a scan of its own:
	// one policy decision and audit entry.
	From map[string][]netip.Prefix
	// Agents runs the scans of From; required with it.
	Agents Agents
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
	// vendor names a MAC's vendor; nil on an agent (see Find), which leaves
	// it to the hub.
	vendor func(net.HardwareAddr) string

	// running is held by the hub's own scan, scheduled or asked for, so
	// that one runs at a time.
	running sync.Mutex
}

// ScanSummary is what one scan found.
type ScanSummary struct {
	Hosts, New, Returned int
	Duration             time.Duration
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
		vendor: Vendor,
	}
}

// Find sweeps subnets from this host and names the hosts that answered, as a
// scan does, but records nothing, decides nothing and leaves the vendor
// empty: it is the agent's side of a scan from a device, within the agent's
// ceiling. Nothing of it stays in memory once it returns: the vendor table
// is the hub's to load.
func Find(ctx context.Context, subnets []netip.Prefix, log *slog.Logger) ([]store.NetworkHost, error) {
	s := New(Config{Log: log})
	s.vendor = nil
	nets, err := s.localNets()
	if err != nil {
		return nil, err
	}
	return s.find(ctx, subnets, nets)
}

// Run scans at once and then every Interval until ctx is done: the hub's
// subnets, if any, and those of each device in From, all at once, so a slow
// agent holds up no other scan. A failed scan is logged; the next one runs
// on schedule.
func (s *Scanner) Run(ctx context.Context) error {
	t := time.NewTicker(s.cfg.Interval)
	defer t.Stop()
	devices := make([]string, 0, len(s.cfg.From))
	for d := range s.cfg.From {
		devices = append(devices, d)
	}
	slices.Sort(devices)
	for {
		var wg sync.WaitGroup
		if len(s.cfg.Subnets) > 0 || s.cfg.Auto {
			wg.Go(func() {
				err := s.Scan(ctx)
				switch {
				case err == nil || ctx.Err() != nil:
				case errors.Is(err, ErrScanRunning):
					s.log.InfoContext(ctx, "network scan skipped", "err", err)
				default:
					s.log.WarnContext(ctx, "network scan failed", "err", err)
				}
			})
		}
		for _, d := range devices {
			wg.Go(func() {
				err := s.ScanFrom(ctx, d)
				switch {
				case err == nil || ctx.Err() != nil:
				case errors.Is(err, ErrScanSkipped):
					s.log.InfoContext(ctx, "network scan skipped", "from", d, "err", err)
				default:
					s.log.WarnContext(ctx, "network scan failed", "from", d, "err", err)
				}
			})
		}
		wg.Wait()
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}

// Scan runs one scan through policy (network.scan, one audit entry per
// scan), records what it found and publishes the new and returned hosts. It
// fails with ErrScanRunning while another scan by the hub runs.
func (s *Scanner) Scan(ctx context.Context) error {
	_, err := s.scan(ctx, policy.ActorHub, actorID, s.cfg.Auto, nil)
	return err
}

// ScanAs runs one scan as Scan does, asked for by an actor other than the
// hub's schedule (actorKind, actorID: the audit entry's actor): of the
// configured subnets or, when there are none, of the hub's own LANs.
// accepted, if not nil, is called once policy has allowed the scan, before
// anything is swept. It fails with ErrScanRunning while another scan by the
// hub runs.
func (s *Scanner) ScanAs(ctx context.Context, actorKind, actorID string, accepted func()) (ScanSummary, error) {
	return s.scan(ctx, actorKind, actorID, s.cfg.Auto || len(s.cfg.Subnets) == 0, accepted)
}

func (s *Scanner) scan(ctx context.Context, actorKind, actorID string, auto bool, accepted func()) (ScanSummary, error) {
	if !s.running.TryLock() {
		return ScanSummary{}, ErrScanRunning
	}
	defer s.running.Unlock()
	nets, err := s.localNets()
	if err != nil {
		return ScanSummary{}, err
	}
	subnets := slices.Clone(s.cfg.Subnets)
	if auto {
		for _, p := range autoSubnets(nets) {
			if !slices.Contains(subnets, p) {
				subnets = append(subnets, p)
			}
		}
	}
	if len(subnets) == 0 {
		return ScanSummary{}, ErrNoSubnet
	}
	names := make([]string, len(subnets))
	for i, p := range subnets {
		names[i] = p.String()
	}
	// The policy engine encodes Detail after fn returns, so the counts
	// filled in below are audited with the scan.
	detail := map[string]any{"subnets": names}
	var res store.ScanResult
	var sum ScanSummary
	err = s.cfg.Policy.Do(ctx, policy.Request{
		ActorKind: actorKind,
		ActorID:   actorID,
		Action:    policy.NetworkScan,
		Target:    strings.Join(names, ","),
		Detail:    detail,
		// The counts filled in below are what this entry is for.
		RecordOutcome: true,
	}, func(ctx context.Context) error {
		if accepted != nil {
			accepted()
		}
		start := s.now()
		hosts, err := s.find(ctx, subnets, nets)
		if err != nil {
			return err
		}
		res, err = s.cfg.Hosts.RecordScanFrom(ctx, start, s.cfg.AbsentAfter, store.ScanScope{Subnets: subnets}, hosts)
		if err != nil {
			return err
		}
		took := s.now().Sub(start)
		detail["hosts"], detail["new"], detail["returned"] = len(hosts), len(res.New), len(res.Returned)
		detail["duration_ms"] = took.Milliseconds()
		sum = ScanSummary{Hosts: len(hosts), New: len(res.New), Returned: len(res.Returned), Duration: took}
		s.log.InfoContext(ctx, "network scan", "actor", actorKind+"/"+actorID, "subnets", names, "hosts", len(hosts),
			"new", len(res.New), "returned", len(res.Returned), "took", took.Round(time.Millisecond))
		return nil
	})
	if err != nil {
		return ScanSummary{}, fmt.Errorf("network scan: %w", err)
	}
	if s.cfg.Events != nil {
		s.cfg.Events.NetworkHosts(EventNew, res.New)
		s.cfg.Events.NetworkHosts(EventReturned, res.Returned)
	}
	return sum, nil
}

// ScanFrom runs one scan of the subnets of device in From from its agent,
// through policy as Scan does: one network.scan decision and audit entry,
// with the device as "from" in its detail. A device that is unknown, or whose
// agent is not connected, is skipped without an audit entry: ScanFrom fails
// with ErrScanSkipped, having sent nothing. A scan the device's ceiling does
// not allow is denied, and audited, before anything is sent; one its agent
// refuses fails with an error wrapping policy.ErrBeyondCeiling. The hosts it
// finds are recorded with the device as their scanner.
func (s *Scanner) ScanFrom(ctx context.Context, device string) error {
	subnets := s.cfg.From[device]
	if len(subnets) == 0 || s.cfg.Agents == nil {
		return fmt.Errorf("network scan from %s: no subnet to scan from it", device)
	}
	names := make([]string, len(subnets))
	for i, p := range subnets {
		names[i] = p.String()
	}
	// A ceiling denial is the policy's to decide and audit, below; any other
	// reason not to send the scan means there is no agent to send it to.
	if err := s.cfg.Agents.CheckScan(ctx, device, subnets); err != nil && !errors.Is(err, policy.ErrDenied) {
		return fmt.Errorf("%w: from %s: %w", ErrScanSkipped, device, err)
	}
	detail := map[string]any{"subnets": names, "from": device}
	var res store.ScanResult
	err := s.cfg.Policy.Do(ctx, policy.Request{
		ActorKind:     policy.ActorHub,
		ActorID:       actorID,
		Action:        policy.NetworkScan,
		Target:        strings.Join(names, ","),
		Detail:        detail,
		RecordOutcome: true,
		// A scan beyond the ceiling the agent reported is denied, and
		// audited as such, without being sent.
		Precheck: func(ctx context.Context) error { return s.cfg.Agents.CheckScan(ctx, device, subnets) },
	}, func(ctx context.Context) error {
		start := s.now()
		ctx, cancel := context.WithTimeout(ctx, AgentScanTimeout+agentScanGrace)
		defer cancel()
		id, r, err := s.cfg.Agents.Scan(ctx, device, subnets, AgentScanTimeout)
		if err != nil {
			return err
		}
		if r.GetDenied() {
			return fmt.Errorf("device %s refused the scan: %s: %w", device, r.GetError(), policy.ErrBeyondCeiling)
		}
		if r.GetError() != "" {
			return fmt.Errorf("device %s: %s", device, r.GetError())
		}
		hosts := agentHosts(r.GetHosts(), subnets, s.vendor)
		res, err = s.cfg.Hosts.RecordScanFrom(ctx, start, s.cfg.AbsentAfter, store.ScanScope{ScannedBy: id, Subnets: subnets}, hosts)
		if err != nil {
			return err
		}
		took := s.now().Sub(start)
		detail["device_id"] = id
		detail["hosts"], detail["new"], detail["returned"] = len(hosts), len(res.New), len(res.Returned)
		detail["duration_ms"] = took.Milliseconds()
		s.log.InfoContext(ctx, "network scan", "from", device, "subnets", names, "hosts", len(hosts),
			"new", len(res.New), "returned", len(res.Returned), "took", took.Round(time.Millisecond))
		return nil
	})
	if err != nil {
		return fmt.Errorf("network scan from %s: %w", device, err)
	}
	if s.cfg.Events != nil {
		s.cfg.Events.NetworkHosts(EventNew, res.New)
		s.cfg.Events.NetworkHosts(EventReturned, res.Returned)
	}
	return nil
}

// agentHosts turns what an agent reported into hosts to record. The agent is
// not trusted to send sane data: a host whose MAC is not a usable unicast
// one, or whose IP is not in subnets, is dropped, as are repeats of a MAC and
// anything past MaxHosts; names are clipped. vendor, if set, names each.
func agentHosts(found []*agentv1.ScannedHost, subnets []netip.Prefix, vendor func(net.HardwareAddr) string) []store.NetworkHost {
	seen := map[string]bool{}
	var out []store.NetworkHost
	for _, f := range found {
		if len(out) == MaxHosts {
			break
		}
		mac, err := net.ParseMAC(f.GetMac())
		if err != nil || !usableMAC(mac) || seen[mac.String()] {
			continue
		}
		ip, err := netip.ParseAddr(f.GetIp())
		if err != nil || !ip.Is4() || !slices.ContainsFunc(subnets, func(p netip.Prefix) bool { return p.Contains(ip) }) {
			continue
		}
		seen[mac.String()] = true
		name := f.GetHostname()
		if !utf8.ValidString(name) {
			name = ""
		}
		h := store.NetworkHost{MAC: mac.String(), IP: ip.String(), Hostname: ClipText(strings.TrimSpace(name), maxTextLen)}
		if vendor != nil {
			h.Vendor = vendor(mac)
		}
		out = append(out, h)
	}
	return out
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
		s.log.WarnContext(ctx, "no interface of this host is on the subnets to scan; "+
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
		h := store.NetworkHost{MAC: n.MAC.String(), IP: n.IP.String(), Hostname: names[n.IP]}
		if s.vendor != nil {
			h.Vendor = s.vendor(n.MAC)
		}
		hosts = append(hosts, h)
	}
	return hosts, ctx.Err()
}
