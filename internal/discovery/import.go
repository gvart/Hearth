// SPDX-License-Identifier: AGPL-3.0-only

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
	"unicode/utf8"

	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

const (
	// maxTextLen clips an imported hostname or vendor, in bytes.
	maxTextLen = 255
	// maxHostsPerSource is the most records one source may return in one
	// import; a source past it fails as a whole and adds nothing.
	maxHostsPerSource = 4096
)

// Record is one host a lease source knows: a DHCP lease, or an entry of
// Pi-hole's network table.
type Record struct {
	// MAC is the host's hardware address in any form net.ParseMAC reads.
	MAC string
	// IP is its IPv4 address; records with another address are skipped.
	IP       string
	Hostname string
	Vendor   string
	// Lease marks a DHCP lease, whose hostname (the one the client sent,
	// or the one the DHCP server pins to it) wins over a name from a
	// network table, which is a reverse lookup.
	Lease bool
	// Seen is when the source last saw the host; zero if it does not say
	// (a lease with only an expiry time).
	Seen time.Time
}

// Source is something an Importer reads hosts from: a Pi-hole, a lease
// file.
type Source interface {
	// Name is its store source: store.SourcePihole or store.SourceDHCP.
	Name() string
	// Target names it in the audit log and logs. It holds no secret.
	Target() string
	// Records reads every host it knows.
	Records(ctx context.Context) ([]Record, error)
}

// IdleSource is a Source that can have nothing to give, such as the OpenWrt
// routers when none is adopted: an import leaves it out while it is idle,
// and an import of idle sources only neither runs nor is audited.
type IdleSource interface {
	Source
	Idle() bool
}

// ImportHosts stores import results: store.NetworkHosts.
type ImportHosts interface {
	RecordImport(ctx context.Context, at time.Time, hosts []store.ImportedHost) error
}

// ImportConfig holds the importer's dependencies and settings.
type ImportConfig struct {
	Sources []Source
	// Interval is the time between imports; DefaultInterval if zero.
	Interval time.Duration
	Hosts    ImportHosts
	Policy   Policy
	Log      *slog.Logger
}

// Importer reads the hosts its sources know every Interval and merges
// them into the network hosts by MAC (see store.NetworkHosts.RecordImport).
type Importer struct {
	cfg ImportConfig
	log *slog.Logger
	now func() time.Time
}

// NewImporter returns an importer. Call Run to start importing.
func NewImporter(cfg ImportConfig) *Importer {
	if cfg.Interval <= 0 {
		cfg.Interval = DefaultInterval
	}
	log := cfg.Log
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Importer{cfg: cfg, log: log, now: time.Now}
}

// Run imports at once and then every Interval until ctx is done. A failed
// import is logged; the next one runs on schedule.
func (im *Importer) Run(ctx context.Context) error {
	t := time.NewTicker(im.cfg.Interval)
	defer t.Stop()
	for {
		if err := im.Import(ctx); err != nil && ctx.Err() == nil {
			im.log.WarnContext(ctx, "network import failed", "err", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}

// Import reads every source through policy (network.import, one audit
// entry per import) and records what they know in one write. A source that
// fails is logged and skipped; the import fails only if every source does.
func (im *Importer) Import(ctx context.Context) error {
	var (
		sources []Source
		targets []string
	)
	for _, s := range im.cfg.Sources {
		if idle, ok := s.(IdleSource); ok && idle.Idle() {
			continue
		}
		sources, targets = append(sources, s), append(targets, s.Target())
	}
	if len(sources) == 0 {
		return nil
	}
	detail := map[string]any{"sources": targets}
	err := im.cfg.Policy.Do(ctx, policy.Request{
		ActorKind: policy.ActorHub,
		ActorID:   actorID,
		Action:    policy.NetworkImport,
		Target:    strings.Join(targets, ","),
		Detail:    detail,
		// What the import found is what this entry is for.
		RecordOutcome: true,
	}, func(ctx context.Context) error {
		start := im.now()
		var (
			read   []sourceRecords
			failed []string
			errs   []error
		)
		for _, s := range sources {
			recs, err := s.Records(ctx)
			if err != nil {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				im.log.WarnContext(ctx, "network import source failed", "source", s.Target(), "err", err)
				failed = append(failed, s.Target())
				errs = append(errs, fmt.Errorf("%s: %w", s.Target(), err))
				continue
			}
			if len(recs) > maxHostsPerSource {
				err := fmt.Errorf("too many hosts: %d, at most %d", len(recs), maxHostsPerSource)
				im.log.WarnContext(ctx, "network import source failed", "source", s.Target(), "err", err)
				failed = append(failed, s.Target())
				errs = append(errs, fmt.Errorf("%s: %w", s.Target(), err))
				continue
			}
			read = append(read, sourceRecords{name: s.Name(), recs: recs})
		}
		if len(read) == 0 {
			return errors.Join(errs...)
		}
		hosts := mergeRecords(read)
		if err := im.cfg.Hosts.RecordImport(ctx, start, hosts); err != nil {
			return err
		}
		took := im.now().Sub(start)
		detail["hosts"], detail["duration_ms"] = len(hosts), took.Milliseconds()
		if len(failed) > 0 {
			detail["failed"] = failed
		}
		im.log.InfoContext(ctx, "network import", "sources", targets, "hosts", len(hosts),
			"failed", len(failed), "took", took.Round(time.Millisecond))
		return nil
	})
	if err != nil {
		return fmt.Errorf("network import: %w", err)
	}
	return nil
}

type sourceRecords struct {
	name string
	recs []Record
}

// mergeRecords merges the records of every source into one host per MAC,
// sorted by MAC. Its IP is the one the most recent record gives (the first
// record's if none has a time); its hostname the first a lease gives, else
// the first any record gives; its vendor the first one given.
func mergeRecords(read []sourceRecords) []store.ImportedHost {
	type merged struct {
		h        store.ImportedHost
		seen     time.Time
		nameRank int
	}
	byMAC := map[string]*merged{}
	for _, sr := range read {
		for _, r := range sr.recs {
			mac, ok := hostMAC(r.MAC)
			if !ok {
				continue
			}
			ip, err := netip.ParseAddr(strings.TrimSpace(r.IP))
			if err != nil || !ip.Unmap().Is4() || ip.IsUnspecified() || ip.IsLoopback() {
				continue
			}
			m := byMAC[mac]
			if m == nil {
				m = &merged{h: store.ImportedHost{MAC: mac}}
				byMAC[mac] = m
			}
			if !slices.Contains(m.h.Sources, sr.name) {
				m.h.Sources = append(m.h.Sources, sr.name)
			}
			if m.h.IP == "" || r.Seen.After(m.seen) {
				m.h.IP = ip.Unmap().String()
			}
			if r.Seen.After(m.seen) {
				m.seen = r.Seen
			}
			rank := 1
			if r.Lease {
				rank = 2
			}
			if name := cleanName(r.Hostname); name != "" && rank > m.nameRank {
				m.h.Hostname, m.h.HostnameSource, m.nameRank = name, sr.name, rank
			}
			if m.h.Vendor == "" {
				m.h.Vendor = strings.TrimSpace(ClipText(r.Vendor, maxTextLen))
			}
		}
	}
	out := make([]store.ImportedHost, 0, len(byMAC))
	for _, m := range byMAC {
		if !m.seen.IsZero() {
			m.h.Seen = m.seen.UnixMilli()
		}
		slices.Sort(m.h.Sources)
		out = append(out, m.h)
	}
	slices.SortFunc(out, func(a, b store.ImportedHost) int { return strings.Compare(a.MAC, b.MAC) })
	return out
}

// hostMAC returns mac lower-case and colon-separated if it is a host's
// 6-byte unicast address: not all zeros, not multicast or broadcast.
func hostMAC(mac string) (string, bool) {
	hw, err := net.ParseMAC(strings.TrimSpace(mac))
	if err != nil || len(hw) != 6 || hw[0]&1 == 1 || slices.Equal(hw, make(net.HardwareAddr, 6)) {
		return "", false
	}
	return hw.String(), true
}

// cleanName returns a hostname clipped to maxTextLen and without the
// trailing dot, or "" for the "*" dnsmasq writes for a client that sent none.
func cleanName(name string) string {
	name = strings.TrimSuffix(strings.TrimSpace(ClipText(name, maxTextLen)), ".")
	if name == "*" {
		return ""
	}
	return name
}

// ClipText returns s cut to at most n bytes, never inside a UTF-8 character.
// Sources are not trusted to bound what they send.
func ClipText(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}
