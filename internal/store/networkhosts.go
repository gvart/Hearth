// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"database/sql"
	"encoding/json"
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

// networkHostServicesSchema is the schema version whose migration (00031)
// added network_hosts.services and gateway. Before it no host lists a
// service or is the gateway, and scans record neither.
const networkHostServicesSchema = 31

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
	// Services are the mDNS service types the host answers for, as
	// "_ipp._tcp", sorted; none before schema 31.
	Services []string
	// Gateway is whether the host is a default gateway of the scanner that
	// found it; false before schema 31.
	Gateway bool
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
		cmd.Hosts = append(cmd.Hosts, ScannedHost{
			MAC: h.MAC, IP: h.IP, Hostname: h.Hostname, Vendor: h.Vendor, Services: h.Services, Gateway: h.Gateway,
		})
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
// every host reads as found by the hub; before schema 31 no host has a
// service or is the gateway.
func networkHostSelect(v int64) string {
	switch {
	case v < networkHostStateSchema:
		return `SELECT mac, ip, hostname, vendor, first_seen, last_seen, '', '', '', '', '', 0`
	case v < networkHostSourcesSchema:
		return `SELECT mac, ip, hostname, vendor, first_seen, last_seen, state, '', '', '', '', 0`
	case v < networkHostScannedBySchema:
		return `SELECT mac, ip, hostname, vendor, first_seen, last_seen, state, sources, hostname_source, '', '', 0`
	case v < networkHostServicesSchema:
		return `SELECT mac, ip, hostname, vendor, first_seen, last_seen, state, sources, hostname_source, scanned_by, '', 0`
	}
	return `SELECT mac, ip, hostname, vendor, first_seen, last_seen, state, sources, hostname_source, scanned_by, services, gateway`
}

func scanNetworkHost(row interface{ Scan(...any) error }) (NetworkHost, error) {
	var (
		h                    NetworkHost
		first, last, gateway int64
		sources, services    string
	)
	if err := row.Scan(&h.MAC, &h.IP, &h.Hostname, &h.Vendor, &first, &last, &h.State, &sources, &h.HostnameSource,
		&h.ScannedBy, &services, &gateway); err != nil {
		return NetworkHost{}, err
	}
	h.FirstSeen, h.LastSeen = fromMillis(first), fromMillis(last)
	h.Sources = splitSources(sources)
	h.Services = decodeServices(services)
	h.Gateway = gateway != 0
	return h, nil
}

// decodeServices decodes the services column: a JSON array, or "" for
// none. A value that does not decode reads as none.
func decodeServices(s string) []string {
	var out []string
	if s != "" && json.Unmarshal([]byte(s), &out) != nil {
		return nil
	}
	return out
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
	// Services are the mDNS service types it answers for; none keeps the
	// stored ones. Recorded from schema 31.
	Services []string `json:"services,omitempty"`
	// Gateway is whether it is a default gateway of the scanner. Recorded
	// from schema 31.
	Gateway bool `json:"gateway,omitempty"`
}

// RecordNetworkScan upserts the hosts of one scan, keyed by MAC. Its result
// carries NewHosts and ReturnedHosts (see ScanResult).
type RecordNetworkScan struct {
	Stamp
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

func (c RecordNetworkScan) apply(ctx context.Context, w *writer) (Result, error) {
	withSources := w.schema >= networkHostSourcesSchema
	withScanner := w.schema >= networkHostScannedBySchema
	// New, baseline and returned are about scans: what an import stored
	// (from schema 14) does not count.
	knownIPs := `SELECT ip FROM network_hosts`
	if withSources {
		knownIPs += ` WHERE (',' || sources || ',') LIKE '%,scan,%'`
	}
	subnets := c.subnets()
	inBaseline, err := c.baseline(ctx, w.tx, knownIPs, subnets)
	if err != nil {
		return Result{}, err
	}
	withServices := w.schema >= networkHostServicesSchema
	if withServices {
		if err := c.clearOldGateways(ctx, w, subnets); err != nil {
			return Result{}, err
		}
	}
	var res Result
	for _, h := range c.Hosts {
		r, err := w.get(ctx, "network_hosts", h.MAC)
		if err != nil {
			return Result{}, err
		}
		isNew := r == nil
		var last int64
		if !isNew {
			last = r.int("last_seen")
			if withSources {
				last = r.int("last_scan")
			}
		}
		if !isNew && c.ScannedBy != "" && len(subnets) > 0 && !within(subnets, r.str("ip")) {
			// A device answers for its subnets only: a MAC known elsewhere
			// (the router's, say) is not its to move.
			continue
		}
		if withSources && !slices.Contains(splitSources(r.str("sources")), SourceScan) {
			isNew = true
		}
		if r == nil {
			r = newNetworkHostRow(w.schema, h.MAC, c.At)
		}
		r["ip"] = h.IP
		if h.Vendor != "" {
			r["vendor"] = h.Vendor
		}
		r["last_seen"] = max(r.int("last_seen"), c.At)
		if withSources {
			// A name Pi-hole or a DHCP lease gave is kept: a scan only
			// replaces a name a scan found.
			if h.Hostname != "" && (r.str("hostname_source") == "" || r.str("hostname_source") == SourceScan) {
				r["hostname"], r["hostname_source"] = h.Hostname, SourceScan
			}
			r["last_scan"] = max(r.int("last_scan"), c.At)
			r["sources"] = addSources(r.str("sources"), SourceScan)
		} else if h.Hostname != "" {
			r["hostname"] = h.Hostname
		}
		if withScanner {
			r["scanned_by"] = c.ScannedBy
		}
		if withServices {
			// Like a name, services a scan does not hear keep those an
			// earlier one did: mDNS answers are lossy.
			if len(h.Services) > 0 {
				b, err := json.Marshal(h.Services)
				if err != nil {
					return Result{}, err
				}
				r["services"] = string(b)
			}
			if h.Gateway {
				r["gateway"] = int64(1)
			}
		}
		if err := w.put(ctx, "network_hosts", r); err != nil {
			return Result{}, err
		}
		host := networkHostOf(r)
		switch {
		case isNew && !inBaseline(h.IP):
			res.NewHosts = append(res.NewHosts, host)
		case !isNew && c.AbsentAfter > 0 && c.At-last >= c.AbsentAfter:
			res.ReturnedHosts = append(res.ReturnedHosts, host)
		}
		res.Count++
	}
	return res, nil
}

// newNetworkHostRow is the row of a host first found at time at, with every
// column of schema v.
func newNetworkHostRow(v int64, mac string, at int64) row {
	r := row{"mac": mac, "ip": "", "hostname": "", "vendor": "", "first_seen": at, "last_seen": at}
	if v >= networkHostStateSchema {
		r["state"] = HostUnreviewed
	}
	if v >= networkHostSourcesSchema {
		r["sources"], r["hostname_source"], r["last_scan"] = "", "", int64(0)
	}
	if v >= networkHostScannedBySchema {
		r["scanned_by"] = ""
	}
	if v >= networkHostServicesSchema {
		r["services"], r["gateway"] = "", int64(0)
	}
	return r
}

// clearOldGateways unflags the hosts flagged as the gateway that this scan
// does not flag, in its subnets (or anywhere, for a scan without them), if
// it flags any: the scanner read its gateway, so a host it no longer names
// is not one. A scan that flags none (its scanner could not read its
// gateway, or it is a device's: agents do not report it) leaves the flags
// alone.
func (c RecordNetworkScan) clearOldGateways(ctx context.Context, w *writer, subnets []netip.Prefix) error {
	var flagged []string
	for _, h := range c.Hosts {
		if h.Gateway {
			flagged = append(flagged, h.MAC)
		}
	}
	if len(flagged) == 0 {
		return nil
	}
	rows, err := w.query(ctx, "network_hosts", `gateway != 0`, "")
	if err != nil {
		return err
	}
	for _, r := range rows {
		if slices.Contains(flagged, r.str("mac")) || (len(subnets) > 0 && !within(subnets, r.str("ip"))) {
			continue
		}
		r["gateway"] = int64(0)
		if err := w.put(ctx, "network_hosts", r); err != nil {
			return err
		}
	}
	return nil
}

// networkHostOf decodes a network_hosts row, as scanNetworkHost does the
// columns of networkHostSelect.
func networkHostOf(r row) NetworkHost {
	return NetworkHost{
		MAC: r.str("mac"), IP: r.str("ip"), Hostname: r.str("hostname"), Vendor: r.str("vendor"),
		FirstSeen: fromMillis(r.int("first_seen")), LastSeen: fromMillis(r.int("last_seen")),
		State: r.str("state"), Sources: splitSources(r.str("sources")), HostnameSource: r.str("hostname_source"),
		ScannedBy: r.str("scanned_by"), Services: decodeServices(r.str("services")), Gateway: r.int("gateway") != 0,
	}
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
	Stamp
	MAC   string `json:"mac"`
	State string `json:"state"`
}

// Op implements Command.
func (SetNetworkHostState) Op() string { return "set_network_host_state" }

func (SetNetworkHostState) minSchema() int64 { return networkHostStateSchema }

func (c SetNetworkHostState) apply(ctx context.Context, w *writer) (Result, error) {
	r, err := w.get(ctx, "network_hosts", c.MAC)
	if err != nil {
		return Result{}, err
	}
	if r == nil {
		return Result{}, ErrNotFound
	}
	r["state"] = c.State
	return Result{Count: 1}, w.put(ctx, "network_hosts", r)
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
	Stamp
	At    int64          `json:"at"`
	Hosts []ImportedHost `json:"hosts"`
}

// Op implements Command.
func (RecordNetworkImport) Op() string { return "record_network_import" }

func (RecordNetworkImport) minSchema() int64 { return networkHostSourcesSchema }

func (c RecordNetworkImport) apply(ctx context.Context, w *writer) (Result, error) {
	for _, h := range c.Hosts {
		r, err := w.get(ctx, "network_hosts", h.MAC)
		if err != nil {
			return Result{}, err
		}
		seen := h.Seen
		if seen == 0 {
			seen = c.At // first and last seen of a new host only
		}
		if r == nil {
			r = newNetworkHostRow(w.schema, h.MAC, seen)
			r["ip"], r["vendor"] = h.IP, h.Vendor
		} else {
			if h.Seen != 0 && h.Seen >= r.int("last_seen") {
				r["ip"] = h.IP
			}
			if r.str("vendor") == "" {
				r["vendor"] = h.Vendor
			}
			r["last_seen"] = max(r.int("last_seen"), h.Seen)
		}
		if h.Hostname != "" {
			r["hostname"], r["hostname_source"] = h.Hostname, h.HostnameSource
		}
		r["sources"] = addSources(r.str("sources"), h.Sources...)
		if err := w.put(ctx, "network_hosts", r); err != nil {
			return Result{}, err
		}
	}
	return Result{Count: len(c.Hosts)}, nil
}
