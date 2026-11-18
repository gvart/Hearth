// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// networkHostsSchema is the schema version whose migration (00013) added the
// network_hosts table. Until a cluster migrates to it, scans are not
// recorded and no host is listed.
const networkHostsSchema = 13

// NetworkHost is a host network discovery found, keyed by its MAC address.
type NetworkHost struct {
	// MAC is lower-case and colon-separated.
	MAC string
	// IP is the address the host last answered on.
	IP       string
	Hostname string
	Vendor   string
	// FirstSeen is the first scan that found it, LastSeen the latest.
	FirstSeen time.Time
	LastSeen  time.Time
}

// NetworkHosts is the repository for hosts found by network discovery.
type NetworkHosts struct{ s *Store }

// NetworkHosts returns the network host repository.
func (s *Store) NetworkHosts() NetworkHosts { return NetworkHosts{s: s} }

// ScanResult is what recording a scan changed.
type ScanResult struct {
	// New are hosts no scan had found before. The first scan recorded on an
	// empty table is the baseline: its hosts are stored but none is new.
	New []NetworkHost
	// Returned are known hosts no scan had found for at least the
	// absentAfter passed to RecordScan.
	Returned []NetworkHost
}

// RecordScan stores the hosts one scan at time at found, in one write: a
// known MAC gets the new IP, last_seen and any hostname or vendor found (an
// empty one keeps the stored value), so re-scans never duplicate a host.
// Before schema 13 it fails with ErrSchemaTooOld.
func (r NetworkHosts) RecordScan(ctx context.Context, at time.Time, absentAfter time.Duration, hosts []NetworkHost) (ScanResult, error) {
	cmd := RecordNetworkScan{At: toMillis(at), AbsentAfter: absentAfter.Milliseconds(), Hosts: make([]ScannedHost, 0, len(hosts))}
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

// List returns every host, by IP address text then MAC. Before schema 13
// it returns none.
func (r NetworkHosts) List(ctx context.Context) ([]NetworkHost, error) {
	v, err := schemaVersion(ctx, r.s.db)
	if err != nil {
		return nil, fmt.Errorf("list network hosts: %w", err)
	}
	if v < networkHostsSchema {
		return nil, nil
	}
	rows, err := r.s.db.QueryContext(ctx, networkHostSelect+` ORDER BY ip, mac`)
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

const networkHostSelect = `SELECT mac, ip, hostname, vendor, first_seen, last_seen FROM network_hosts`

func scanNetworkHost(row interface{ Scan(...any) error }) (NetworkHost, error) {
	var (
		h           NetworkHost
		first, last int64
	)
	if err := row.Scan(&h.MAC, &h.IP, &h.Hostname, &h.Vendor, &first, &last); err != nil {
		return NetworkHost{}, err
	}
	h.FirstSeen, h.LastSeen = fromMillis(first), fromMillis(last)
	return h, nil
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
}

// Op implements Command.
func (RecordNetworkScan) Op() string { return "record_network_scan" }

func (RecordNetworkScan) minSchema() int64 { return networkHostsSchema }

func (c RecordNetworkScan) apply(ctx context.Context, tx *sql.Tx) (Result, error) {
	var known int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM network_hosts`).Scan(&known); err != nil {
		return Result{}, err
	}
	baseline := known == 0
	var res Result
	for _, h := range c.Hosts {
		var last int64
		err := tx.QueryRowContext(ctx, `SELECT last_seen FROM network_hosts WHERE mac = ?`, h.MAC).Scan(&last)
		isNew := errors.Is(err, sql.ErrNoRows)
		if err != nil && !isNew {
			return Result{}, err
		}
		row, err := scanNetworkHost(tx.QueryRowContext(ctx, `
			INSERT INTO network_hosts (mac, ip, hostname, vendor, first_seen, last_seen)
			VALUES (?, ?, ?, ?, ?, ?)
			ON CONFLICT (mac) DO UPDATE SET
				ip = excluded.ip,
				hostname = COALESCE(NULLIF(excluded.hostname, ''), hostname),
				vendor = COALESCE(NULLIF(excluded.vendor, ''), vendor),
				last_seen = MAX(last_seen, excluded.last_seen)
			RETURNING mac, ip, hostname, vendor, first_seen, last_seen`,
			h.MAC, h.IP, h.Hostname, h.Vendor, c.At, c.At))
		if err != nil {
			return Result{}, err
		}
		switch {
		case isNew && !baseline:
			res.NewHosts = append(res.NewHosts, row)
		case !isNew && c.AbsentAfter > 0 && c.At-last >= c.AbsentAfter:
			res.ReturnedHosts = append(res.ReturnedHosts, row)
		}
	}
	res.Count = len(c.Hosts)
	return res, nil
}
