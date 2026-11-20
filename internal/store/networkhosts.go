// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"
)

// networkHostsSchema is the schema version whose migration (00012) added the
// network_hosts table. Until a cluster migrates to it, scans are not
// recorded and no host is listed.
const networkHostsSchema = 12

// networkHostStateSchema is the schema version whose migration (00013) added
// network_hosts.state. Before it every host is unreviewed and none can be
// marked.
const networkHostStateSchema = 13

// networkHostSourcesSchema is the schema version whose migration (00014)
// added the sources, hostname_source and last_scan columns. Until a cluster
// migrates to it, imports are not recorded and hosts list no source.
const networkHostSourcesSchema = 14

// networkHostScannedBySchema is the schema version whose migration (00026)
// added network_hosts.scanned_by. Before it every host reads as found by the
// hub, and a scan from a device records no scanner.
const networkHostScannedBySchema = 26

// What the operator said about a host (NetworkHost.State). Known and ignored
// hosts never fire new-device alerts.
const (
	// HostUnreviewed is a host nobody has marked yet.
	HostUnreviewed = ""
	// HostKnown is a host the operator recognises as theirs.
	HostKnown = "known"
	// HostIgnored is a host the operator does not want to hear about.
	HostIgnored = "ignored"
)

// Where a network host was learned (NetworkHost.Sources) and which source
// gave its hostname (NetworkHost.HostnameSource).
const (
	// SourceScan is network discovery: the ARP sweep, with names from mDNS
	// and LAN reverse DNS.
	SourceScan = "scan"
	// SourcePihole is a Pi-hole's network table and DHCP leases.
	SourcePihole = "pihole"
	// SourceDHCP is a DHCP server's lease file (dnsmasq, ISC dhcpd).
	SourceDHCP = "dhcp"
	// SourceNetAlertX is a NetAlertX's device list.
	SourceNetAlertX = "netalertx"
)

// NetworkHost is a host network discovery found, keyed by its MAC address.
type NetworkHost struct {
	// MAC is lower-case and colon-separated.
	MAC string
	// IP is the address the host last answered on.
	IP       string
	Hostname string
	Vendor   string
	// FirstSeen is when it was first found, LastSeen when a scan or an
	// import last saw it.
	FirstSeen time.Time
	LastSeen  time.Time
	// State is HostUnreviewed, HostKnown or HostIgnored.
	State string
	// Sources are where the host was learned (SourceScan, SourcePihole,
	// SourceDHCP, SourceNetAlertX), sorted; none before schema 14.
	Sources []string
	// HostnameSource is the source that gave Hostname; "" if none did.
	HostnameSource string
	// ScannedBy is the id of the device whose agent last found the host in
	// a scan; "" when the hub did, or no scan found it.
	ScannedBy string
}

// NetworkHosts is the repository for hosts found by network discovery.
type NetworkHosts struct{ s *Store }

// NetworkHosts returns the network host repository.
func (s *Store) NetworkHosts() NetworkHosts { return NetworkHosts{s: s} }

// ScanResult is what recording a scan changed. Only scans count: a host an
// import added is new to the first scan that finds it, and an import never
// makes an absent host look returned or present.
type ScanResult struct {
	// New are hosts no scan had found before. The first scan recorded with
	// no scanned host stored is the baseline: its hosts are stored but none
	// is new.
	New []NetworkHost
	// Returned are known hosts no scan had found for at least the
	// absentAfter passed to RecordScan.
	Returned []NetworkHost
}

// RecordScan stores the hosts one scan by the hub at time at found, in one
// write: a known MAC gets the new IP, last_seen and any hostname or vendor
// found (an empty one keeps the stored value), so re-scans never duplicate a
// host. From schema 14 a hostname an import gave (see RecordImport) is kept.
// Before schema 12 it fails with ErrSchemaTooOld.
func (r NetworkHosts) RecordScan(ctx context.Context, at time.Time, absentAfter time.Duration, hosts []NetworkHost) (ScanResult, error) {
	return r.RecordScanFrom(ctx, at, absentAfter, ScanScope{}, hosts)
}

// ScanScope is what one scan covered: who swept which subnets.
type ScanScope struct {
	// ScannedBy is the id of the device whose agent ran the scan; "" for the
	// hub.
	ScannedBy string
	// Subnets are the subnets swept. The first scan to find hosts in them is
	// their baseline (see ScanResult.New); without subnets, the first scan
	// ever recorded is.
	Subnets []netip.Prefix
}

// RecordScanFrom stores the hosts a scan of scope found, as RecordScan does,
// and from schema 26 records scope.ScannedBy as the scanner of each.
func (r NetworkHosts) RecordScanFrom(ctx context.Context, at time.Time, absentAfter time.Duration, scope ScanScope,
	hosts []NetworkHost,
) (ScanResult, error) {
	cmd := RecordNetworkScan{
		At: toMillis(at), AbsentAfter: absentAfter.Milliseconds(), ScannedBy: scope.ScannedBy,
		Hosts: make([]ScannedHost, 0, len(hosts)),
	}
	for _, p := range scope.Subnets {
		cmd.Subnets = append(cmd.Subnets, p.String())
	}
	for _, h := range hosts {
		if h.MAC == "" || h.IP == "" {
			return ScanResult{}, errors.New("record network scan: every host needs a MAC and an IP")
		}
		cmd.Hosts = append(cmd.Hosts, ScannedHost{MAC: h.MAC, IP: h.IP, Hostname: h.Hostname, Vendor: h.Vendor})
	}
	res, err := r.s.apply(ctx, cmd)
	if err != nil {
		return ScanResult{}, fmt.Errorf("record network scan: %w", err)
	}
	return ScanResult{New: res.NewHosts, Returned: res.ReturnedHosts}, nil
}

// List returns every host, by IP address text then MAC. Before schema 12
// it returns none.
func (r NetworkHosts) List(ctx context.Context) ([]NetworkHost, error) {
	v, err := schemaVersion(ctx, r.s.db)
	if err != nil {
		return nil, fmt.Errorf("list network hosts: %w", err)
	}
	if v < networkHostsSchema {
		return nil, nil
	}
	rows, err := r.s.db.QueryContext(ctx, networkHostSelect(v)+` FROM network_hosts ORDER BY ip, mac`)
	if err != nil {
		return nil, fmt.Errorf("list network hosts: %w", err)
	}
	defer rows.Close()
	var out []NetworkHost
	for rows.Next() {
		h, err := scanNetworkHost(rows)
		if err != nil {
			return nil, fmt.Errorf("list network hosts: %w", err)
		}
		out = append(out, h)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list network hosts: %w", err)
	}
	return out, nil
}

// networkHostSelect is the SELECT list of a host at schema v, for
// scanNetworkHost: before schema 13 there is no state, and every host reads
// as unreviewed; before schema 14 no host has a source; before schema 26
// every host reads as found by the hub.
func networkHostSelect(v int64) string {
	switch {
	case v < networkHostStateSchema:
		return `SELECT mac, ip, hostname, vendor, first_seen, last_seen, '', '', '', ''`
	case v < networkHostSourcesSchema:
		return `SELECT mac, ip, hostname, vendor, first_seen, last_seen, state, '', '', ''`
	case v < networkHostScannedBySchema:
		return `SELECT mac, ip, hostname, vendor, first_seen, last_seen, state, sources, hostname_source, ''`
	}
	return `SELECT mac, ip, hostname, vendor, first_seen, last_seen, state, sources, hostname_source, scanned_by`
}

func scanNetworkHost(row interface{ Scan(...any) error }) (NetworkHost, error) {
	var (
		h           NetworkHost
		first, last int64
		sources     string
	)
	if err := row.Scan(&h.MAC, &h.IP, &h.Hostname, &h.Vendor, &first, &last, &h.State, &sources, &h.HostnameSource, &h.ScannedBy); err != nil {
		return NetworkHost{}, err
	}
	h.FirstSeen, h.LastSeen = fromMillis(first), fromMillis(last)
	h.Sources = splitSources(sources)
	return h, nil
}

func splitSources(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
}

// addSources returns the stored source set (comma-separated) with add
// included, sorted and comma-separated.
func addSources(stored string, add ...string) string {
	set := splitSources(stored)
	for _, a := range add {
		if a != "" && !slices.Contains(set, a) {
			set = append(set, a)
		}
	}
	slices.Sort(set)
	return strings.Join(set, ",")
}

// ScannedHost is one host in a RecordNetworkScan.
type ScannedHost struct {
	MAC      string `json:"mac"`
	IP       string `json:"ip"`
	Hostname string `json:"hostname,omitempty"`
	Vendor   string `json:"vendor,omitempty"`
}

// RecordNetworkScan upserts the hosts of one scan, keyed by MAC. Its result
// carries NewHosts and ReturnedHosts (see ScanResult).
type RecordNetworkScan struct {
	At int64 `json:"at"`
	// AbsentAfter is how long, in milliseconds, a known host must have gone
	// unseen to count as returned.
	AbsentAfter int64         `json:"absent_after"`
	Hosts       []ScannedHost `json:"hosts"`
	// ScannedBy is the id of the device whose agent ran the scan; "" for
	// the hub. Recorded from schema 26.
	ScannedBy string `json:"scanned_by,omitempty"`
	// Subnets are the CIDRs the scan swept: a host is new only if a scan
	// found another host in its subnet before (each subnet has its own
	// baseline). Entries without them (written before it was added) have
	// one baseline: the first scan ever recorded. A scan by a device never
	// moves a known host whose stored IP is outside them.
	Subnets []string `json:"subnets,omitempty"`
}

// Op implements Command.
func (RecordNetworkScan) Op() string { return "record_network_scan" }

func (RecordNetworkScan) minSchema() int64 { return networkHostsSchema }

func (c RecordNetworkScan) apply(ctx context.Context, tx *sql.Tx) (Result, error) {
	v, err := schemaVersion(ctx, tx)
	if err != nil {
		return Result{}, err
	}
	withSources := v >= networkHostSourcesSchema
	withScanner := v >= networkHostScannedBySchema
	// New, baseline and returned are about scans: what an import stored
	// (from schema 14) does not count.
	knownIPs, lastScan := `SELECT ip FROM network_hosts`, `SELECT last_seen, '', ip FROM network_hosts WHERE mac = ?`
	if withSources {
		knownIPs += ` WHERE (',' || sources || ',') LIKE '%,scan,%'`
		lastScan = `SELECT last_scan, sources, ip FROM network_hosts WHERE mac = ?`
	}
	subnets := c.subnets()
	inBaseline, err := c.baseline(ctx, tx, knownIPs, subnets)
	if err != nil {
		return Result{}, err
	}
	returning := "RETURNING" + strings.TrimPrefix(networkHostSelect(v), "SELECT")
	var res Result
	for _, h := range c.Hosts {
		var (
			last        int64
			sources, ip string
		)
		err := tx.QueryRowContext(ctx, lastScan, h.MAC).Scan(&last, &sources, &ip)
		isNew := errors.Is(err, sql.ErrNoRows)
		if err != nil && !isNew {
			return Result{}, err
		}
		if !isNew && c.ScannedBy != "" && len(subnets) > 0 && !within(subnets, ip) {
			// A device answers for its subnets only: a MAC known elsewhere
			// (the router's, say) is not its to move.
			continue
		}
		if withSources && !slices.Contains(splitSources(sources), SourceScan) {
			isNew = true
		}
		var row NetworkHost
		if withSources {
			// A name Pi-hole or a DHCP lease gave is kept: a scan only
			// replaces a name a scan found.
			nameSource := ""
			if h.Hostname != "" {
				nameSource = SourceScan
			}
			row, err = scanNetworkHost(tx.QueryRowContext(ctx, `
				INSERT INTO network_hosts (mac, ip, hostname, vendor, first_seen, last_seen, last_scan, sources, hostname_source)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
				ON CONFLICT (mac) DO UPDATE SET
					ip = excluded.ip,
					hostname = CASE WHEN excluded.hostname != '' AND hostname_source IN ('', 'scan')
						THEN excluded.hostname ELSE hostname END,
					hostname_source = CASE WHEN excluded.hostname != '' AND hostname_source IN ('', 'scan')
						THEN excluded.hostname_source ELSE hostname_source END,
					vendor = COALESCE(NULLIF(excluded.vendor, ''), vendor),
					last_seen = MAX(last_seen, excluded.last_seen),
					last_scan = MAX(last_scan, excluded.last_scan),
					sources = excluded.sources
				`+returning,
				h.MAC, h.IP, h.Hostname, h.Vendor, c.At, c.At, c.At, addSources(sources, SourceScan), nameSource))
		} else {
			row, err = scanNetworkHost(tx.QueryRowContext(ctx, `
				INSERT INTO network_hosts (mac, ip, hostname, vendor, first_seen, last_seen)
				VALUES (?, ?, ?, ?, ?, ?)
				ON CONFLICT (mac) DO UPDATE SET
					ip = excluded.ip,
					hostname = COALESCE(NULLIF(excluded.hostname, ''), hostname),
					vendor = COALESCE(NULLIF(excluded.vendor, ''), vendor),
					last_seen = MAX(last_seen, excluded.last_seen)
				`+returning,
				h.MAC, h.IP, h.Hostname, h.Vendor, c.At, c.At))
		}
		if err != nil {
			return Result{}, err
		}
		if withScanner {
			if _, err := tx.ExecContext(ctx, `UPDATE network_hosts SET scanned_by = ? WHERE mac = ?`, c.ScannedBy, h.MAC); err != nil {
				return Result{}, err
			}
			row.ScannedBy = c.ScannedBy
		}
		switch {
		case isNew && !inBaseline(h.IP):
			res.NewHosts = append(res.NewHosts, row)
		case !isNew && c.AbsentAfter > 0 && c.At-last >= c.AbsentAfter:
			res.ReturnedHosts = append(res.ReturnedHosts, row)
		}
		res.Count++
	}
	return res, nil
}

// subnets are the scan's subnets that parse.
func (c RecordNetworkScan) subnets() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range c.Subnets {
		if p, err := netip.ParsePrefix(s); err == nil {
			out = append(out, p.Masked())
		}
	}
	return out
}

// within reports whether ip lies in one of subnets.
func within(subnets []netip.Prefix, ip string) bool {
	a, err := netip.ParseAddr(ip)
	return err == nil && slices.ContainsFunc(subnets, func(p netip.Prefix) bool { return p.Contains(a) })
}

// baseline returns whether a host at an IP is in its subnet's baseline: no
// host knownIPs (a query for the addresses of the hosts a scan found) lists
// is in the same one of subnets. Without subnets, or for an IP in none of
// them, it is when there is no such host at all.
func (c RecordNetworkScan) baseline(ctx context.Context, tx *sql.Tx, knownIPs string, subnets []netip.Prefix) (func(ip string) bool, error) {
	rows, err := tx.QueryContext(ctx, knownIPs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	anyKnown := false
	known := map[netip.Prefix]bool{}
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			return nil, err
		}
		anyKnown = true
		if a, err := netip.ParseAddr(ip); err == nil {
			for _, p := range subnets {
				if p.Contains(a) {
					known[p] = true
				}
			}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return func(ip string) bool {
		if a, err := netip.ParseAddr(ip); err == nil {
			for _, p := range subnets {
				if p.Contains(a) {
					return !known[p]
				}
			}
		}
		return !anyKnown
	}, nil
}

// SetState marks the host with this MAC known, ignored or, with
// HostUnreviewed, neither. It fails with ErrNotFound if discovery never found
// that MAC, and before schema 13 with ErrSchemaTooOld.
func (r NetworkHosts) SetState(ctx context.Context, mac, state string) error {
	switch state {
	case HostUnreviewed, HostKnown, HostIgnored:
	default:
		return fmt.Errorf("set network host %s state: unknown state %q", mac, state)
	}
	if _, err := r.s.apply(ctx, SetNetworkHostState{MAC: mac, State: state}); err != nil {
		return fmt.Errorf("set network host %s state: %w", mac, err)
	}
	return nil
}

// SetNetworkHostState sets a host's state (HostUnreviewed, HostKnown or
// HostIgnored). It fails with ErrNotFound if there is no host with MAC.
type SetNetworkHostState struct {
	MAC   string `json:"mac"`
	State string `json:"state"`
}

// Op implements Command.
func (SetNetworkHostState) Op() string { return "set_network_host_state" }

func (SetNetworkHostState) minSchema() int64 { return networkHostStateSchema }

func (c SetNetworkHostState) apply(ctx context.Context, tx *sql.Tx) (Result, error) {
	res, err := tx.ExecContext(ctx, `UPDATE network_hosts SET state = ? WHERE mac = ?`, c.State, c.MAC)
	if err != nil {
		return Result{}, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return Result{}, err
	}
	if n == 0 {
		return Result{}, ErrNotFound
	}
	return Result{Count: int(n)}, nil
}

// ImportedHost is one host in a RecordNetworkImport: what Pi-hole and the
// DHCP lease files know of one MAC, merged.
type ImportedHost struct {
	MAC      string `json:"mac"`
	IP       string `json:"ip"`
	Hostname string `json:"hostname,omitempty"`
	// HostnameSource is the source that gave Hostname.
	HostnameSource string `json:"hostname_source,omitempty"`
	Vendor         string `json:"vendor,omitempty"`
	// Sources are the sources that know the host (SourcePihole,
	// SourceDHCP).
	Sources []string `json:"sources"`
	// Seen is when a source last saw the host, in Unix milliseconds; 0 if
	// no source says (a lease with only an expiry time).
	Seen int64 `json:"seen,omitempty"`
}

// RecordImport stores the hosts one import of Pi-hole and DHCP leases at
// time at found, in one write, merged with the scanned hosts by MAC. A name
// an import gives replaces the stored name, a scan's included; an empty one
// keeps it. A known host takes the import's IP only when the import saw it
// at least as recently as its last_seen, and its last_seen moves only with
// the Seen the import gives, so a lease alone never makes an absent host
// look present. An import publishes no events and leaves the host's state
// alone. Before schema 14 it fails with ErrSchemaTooOld.
func (r NetworkHosts) RecordImport(ctx context.Context, at time.Time, hosts []ImportedHost) error {
	for _, h := range hosts {
		if h.MAC == "" || h.IP == "" || len(h.Sources) == 0 {
			return errors.New("record network import: every host needs a MAC, an IP and a source")
		}
	}
	if _, err := r.s.apply(ctx, RecordNetworkImport{At: toMillis(at), Hosts: hosts}); err != nil {
		return fmt.Errorf("record network import: %w", err)
	}
	return nil
}

// RecordNetworkImport upserts the hosts of one import (see RecordImport).
type RecordNetworkImport struct {
	At    int64          `json:"at"`
	Hosts []ImportedHost `json:"hosts"`
}

// Op implements Command.
func (RecordNetworkImport) Op() string { return "record_network_import" }

func (RecordNetworkImport) minSchema() int64 { return networkHostSourcesSchema }

func (c RecordNetworkImport) apply(ctx context.Context, tx *sql.Tx) (Result, error) {
	for _, h := range c.Hosts {
		var (
			last    int64
			sources string
		)
		err := tx.QueryRowContext(ctx, `SELECT last_seen, sources FROM network_hosts WHERE mac = ?`, h.MAC).Scan(&last, &sources)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return Result{}, err
		}
		seen := h.Seen
		if seen == 0 {
			seen = c.At // first and last seen of a new host only
		}
		newer := h.Seen != 0 && h.Seen >= last
		nameSource := ""
		if h.Hostname != "" {
			nameSource = h.HostnameSource
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO network_hosts (mac, ip, hostname, vendor, first_seen, last_seen, sources, hostname_source)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT (mac) DO UPDATE SET
				ip = CASE WHEN ? THEN excluded.ip ELSE ip END,
				hostname = COALESCE(NULLIF(excluded.hostname, ''), hostname),
				hostname_source = CASE WHEN excluded.hostname != '' THEN excluded.hostname_source ELSE hostname_source END,
				vendor = COALESCE(NULLIF(vendor, ''), excluded.vendor),
				last_seen = MAX(last_seen, ?),
				sources = excluded.sources`,
			h.MAC, h.IP, h.Hostname, h.Vendor, seen, seen, addSources(sources, h.Sources...), nameSource,
			newer, h.Seen); err != nil {
			return Result{}, err
		}
	}
	return Result{Count: len(c.Hosts)}, nil
}
