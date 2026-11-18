// SPDX-License-Identifier: AGPL-3.0-only

package discovery

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gvart/hearth/internal/store"
)

// LeaseFile is a DHCP server's lease file, read on every import: dnsmasq's
// (/var/lib/misc/dnsmasq.leases) or ISC dhcpd's (dhcpd.leases), told apart
// by their content. Only active leases are imported.
type LeaseFile struct {
	Path string
	now  func() time.Time
}

// Name implements Source.
func (LeaseFile) Name() string { return store.SourceDHCP }

// Target implements Source.
func (f LeaseFile) Target() string { return "dhcp:" + f.Path }

// Records implements Source.
func (f LeaseFile) Records(context.Context) ([]Record, error) {
	b, err := os.ReadFile(f.Path)
	if err != nil {
		return nil, fmt.Errorf("read lease file: %w", err)
	}
	now := time.Now()
	if f.now != nil {
		now = f.now()
	}
	text := string(b)
	if isISCLeases(text) {
		return ParseISCLeases(strings.NewReader(text), now)
	}
	return ParseDnsmasqLeases(strings.NewReader(text), now)
}

// isISCLeases reports whether text has an ISC dhcpd "lease <ip> {" block.
func isISCLeases(text string) bool {
	for line := range strings.Lines(text) {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "lease ") && strings.HasSuffix(line, "{") {
			return true
		}
	}
	return false
}

// ParseDnsmasqLeases reads a dnsmasq lease file: one IPv4 lease per line,
// "<expiry> <mac> <ip> <hostname|*> <client-id|*>", where expiry is a Unix
// time, 0 for an infinite lease. Leases expired at now, IPv6 leases and
// malformed lines are skipped.
func ParseDnsmasqLeases(r io.Reader, now time.Time) ([]Record, error) {
	var out []Record
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 4 || f[0] == "duid" {
			continue
		}
		exp, err := strconv.ParseInt(f[0], 10, 64)
		if err != nil || (exp != 0 && exp < now.Unix()) {
			continue
		}
		out = append(out, Record{MAC: f[1], IP: f[2], Hostname: f[3], Lease: true})
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read dnsmasq leases: %w", err)
	}
	return out, nil
}

// ParseISCLeases reads an ISC dhcpd lease file. dhcpd appends a new block
// whenever a lease changes, so the last block of an address wins. Leases
// whose binding state is not active or that ended before now are skipped;
// Seen is the client's last transaction (cltt), else the lease start.
func ParseISCLeases(r io.Reader, now time.Time) ([]Record, error) {
	type lease struct {
		ip, mac, name, state string
		ends, seen           time.Time
		endsKnown            bool
	}
	var (
		order []string
		byIP  = map[string]lease{}
		cur   lease
		in    bool
	)
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := sc.Text()
		if i := strings.IndexByte(line, '#'); i >= 0 && !strings.Contains(line[:i], `"`) {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if !in {
			if f := strings.Fields(line); len(f) == 3 && f[0] == "lease" && f[2] == "{" {
				in, cur = true, lease{ip: f[1]}
			}
			continue
		}
		if line == "}" {
			in = false
			if _, ok := byIP[cur.ip]; !ok {
				order = append(order, cur.ip)
			}
			byIP[cur.ip] = cur
			continue
		}
		f := strings.Fields(strings.TrimSuffix(line, ";"))
		if len(f) < 2 {
			continue
		}
		switch f[0] {
		case "starts":
			if t, ok := iscTime(f[1:]); ok && cur.seen.IsZero() {
				cur.seen = t
			}
		case "cltt":
			if t, ok := iscTime(f[1:]); ok {
				cur.seen = t
			}
		case "ends":
			cur.ends, cur.endsKnown = iscTime(f[1:])
		case "binding":
			if len(f) == 3 && f[1] == "state" {
				cur.state = f[2]
			}
		case "hardware":
			if len(f) == 3 {
				cur.mac = f[2]
			}
		case "client-hostname":
			cur.name = strings.Trim(strings.Join(f[1:], " "), `"`)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read dhcpd leases: %w", err)
	}
	var out []Record
	for _, ip := range order {
		l := byIP[ip]
		if l.mac == "" || (l.state != "" && l.state != "active") || (l.endsKnown && l.ends.Before(now)) {
			continue
		}
		out = append(out, Record{MAC: l.mac, IP: l.ip, Hostname: l.name, Lease: true, Seen: l.seen})
	}
	return out, nil
}

// iscTime reads a dhcpd lease time: "<weekday> YYYY/MM/DD HH:MM:SS" in
// UTC, or "epoch <unix>" (db-time-format local). "never" and anything else
// is not a time.
func iscTime(f []string) (time.Time, bool) {
	switch {
	case len(f) >= 2 && f[0] == "epoch":
		n, err := strconv.ParseInt(f[1], 10, 64)
		if err != nil {
			return time.Time{}, false
		}
		return time.Unix(n, 0).UTC(), true
	case len(f) >= 3:
		t, err := time.Parse("2006/01/02 15:04:05", f[1]+" "+f[2])
		if err != nil {
			return time.Time{}, false
		}
		return t, true
	}
	return time.Time{}, false
}
