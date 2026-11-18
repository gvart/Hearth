// SPDX-License-Identifier: AGPL-3.0-only

package automation

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// defaultCheckEvery is how often a synthetic check runs.
const defaultCheckEvery = 10 * time.Second

// checkTrigger fires when a synthetic check, run from the hub, has failed for
// a duration. It fires once per outage: again only after the check passed.
type checkTrigger struct {
	what   string // for Describe: "HTTP GET http://nas.lan" ...
	timing pollTiming
	probe  func(ctx context.Context) error
	clock  Clock
	log    *slog.Logger
}

func (t *checkTrigger) Describe() string {
	return fmt.Sprintf("fires when %s fails%s (checked every %s from the hub)", t.what, forText(t.timing.For), t.timing.Every)
}

func (t *checkTrigger) Watch(ctx context.Context, fire func()) error {
	return poller{clock: t.clock, every: t.timing.Every, hold: t.timing.For, bad: func(ctx context.Context) bool {
		pctx, cancel := context.WithTimeout(ctx, t.timing.Timeout)
		defer cancel()
		err := t.probe(pctx)
		if err != nil && ctx.Err() == nil {
			t.log.DebugContext(ctx, "check failed", "check", t.what, "err", err)
		}
		return err != nil
	}}.watch(ctx, fire)
}

// checkTiming builds a check's timing from its fields.
func checkTiming(every, hold, timeout time.Duration) (pollTiming, error) {
	t := pollTiming{Every: every, For: hold, Timeout: timeout}
	return t, t.check(defaultCheckEvery)
}

func buildHTTPCheck(p Params, deps TriggerDeps) (Trigger, error) {
	var cfg struct {
		URL     string        `yaml:"url"`
		Status  int           `yaml:"status"`
		Every   time.Duration `yaml:"every"`
		For     time.Duration `yaml:"for"`
		Timeout time.Duration `yaml:"timeout"`
	}
	if err := p.Decode(&cfg); err != nil {
		return nil, err
	}
	u, err := url.Parse(cfg.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, errors.New("url must be http(s)://host[:port][/path]")
	}
	if cfg.Status != 0 && (cfg.Status < 100 || cfg.Status > 599) {
		return nil, fmt.Errorf("status %d is not an HTTP status", cfg.Status)
	}
	timing, err := checkTiming(cfg.Every, cfg.For, cfg.Timeout)
	if err != nil {
		return nil, err
	}
	// A fresh connection per check: a pooled one could hide a server that
	// stopped accepting new ones.
	hc := &http.Client{Transport: &http.Transport{Proxy: http.ProxyFromEnvironment, DisableKeepAlives: true}}
	want := "a 2xx or 3xx status"
	if cfg.Status != 0 {
		want = fmt.Sprintf("status %d", cfg.Status)
	}
	return &checkTrigger{
		// u.Redacted keeps any password in the URL out of plans and logs.
		what:   fmt.Sprintf("HTTP GET %s (expecting %s)", u.Redacted(), want),
		timing: timing, clock: deps.Clock, log: deps.Log,
		probe: func(ctx context.Context) error {
			return probeHTTP(ctx, hc, cfg.URL, cfg.Status)
		},
	}, nil
}

// probeHTTP GETs rawURL and checks the status: want, or 2xx/3xx if want is 0.
func probeHTTP(ctx context.Context, hc *http.Client, rawURL string, want int) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	_ = resp.Body.Close()
	ok := resp.StatusCode == want || (want == 0 && resp.StatusCode >= 200 && resp.StatusCode < 400)
	if !ok {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	return nil
}

func buildTCPCheck(p Params, deps TriggerDeps) (Trigger, error) {
	var cfg struct {
		Address string        `yaml:"address"`
		Every   time.Duration `yaml:"every"`
		For     time.Duration `yaml:"for"`
		Timeout time.Duration `yaml:"timeout"`
	}
	if err := p.Decode(&cfg); err != nil {
		return nil, err
	}
	if host, port, err := net.SplitHostPort(cfg.Address); err != nil || host == "" || port == "" {
		return nil, errors.New("address must be host:port")
	}
	timing, err := checkTiming(cfg.Every, cfg.For, cfg.Timeout)
	if err != nil {
		return nil, err
	}
	return &checkTrigger{
		what:   "TCP connect to " + cfg.Address,
		timing: timing, clock: deps.Clock, log: deps.Log,
		probe: func(ctx context.Context) error {
			var d net.Dialer
			c, err := d.DialContext(ctx, "tcp", cfg.Address)
			if err != nil {
				return err
			}
			return c.Close()
		},
	}, nil
}

func buildDNSCheck(p Params, deps TriggerDeps) (Trigger, error) {
	var cfg struct {
		Name    string        `yaml:"name"`
		Server  string        `yaml:"server"`
		Every   time.Duration `yaml:"every"`
		For     time.Duration `yaml:"for"`
		Timeout time.Duration `yaml:"timeout"`
	}
	if err := p.Decode(&cfg); err != nil {
		return nil, err
	}
	name, err := dnsmessage.NewName(strings.TrimSuffix(cfg.Name, ".") + ".")
	if cfg.Name == "" || err != nil {
		return nil, errors.New("name must be a domain name")
	}
	server := cfg.Server
	if server == "" {
		return nil, errors.New("server is required: the DNS server to ask, host or host:port")
	}
	if _, _, err := net.SplitHostPort(server); err != nil {
		server = net.JoinHostPort(strings.Trim(server, "[]"), "53")
	}
	timing, err := checkTiming(cfg.Every, cfg.For, cfg.Timeout)
	if err != nil {
		return nil, err
	}
	return &checkTrigger{
		what:   fmt.Sprintf("DNS lookup of %s A at %s", cfg.Name, server),
		timing: timing, clock: deps.Clock, log: deps.Log,
		probe: func(ctx context.Context) error { return probeDNS(ctx, server, name) },
	}, nil
}

// probeDNS asks server, over UDP, for the A records of name, and requires a
// successful answer with at least one record. It asks the server directly,
// so /etc/hosts and the hub's own resolver play no part.
func probeDNS(ctx context.Context, server string, name dnsmessage.Name) error {
	var idb [2]byte
	_, _ = rand.Read(idb[:])
	id := binary.BigEndian.Uint16(idb[:])
	q, err := (&dnsmessage.Message{
		Header:    dnsmessage.Header{ID: id, RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}},
	}).Pack()
	if err != nil {
		return fmt.Errorf("pack dns query: %w", err)
	}
	var d net.Dialer
	c, err := d.DialContext(ctx, "udp", server)
	if err != nil {
		return err
	}
	defer c.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	}
	if _, err := c.Write(q); err != nil {
		return err
	}
	buf := make([]byte, 1500)
	for {
		n, err := c.Read(buf)
		if err != nil {
			return err
		}
		var m dnsmessage.Message
		if m.Unpack(buf[:n]) != nil || m.ID != id || !m.Response {
			continue // not the answer to this query
		}
		switch {
		case m.RCode != dnsmessage.RCodeSuccess:
			return fmt.Errorf("dns answer: %s", m.RCode)
		case len(m.Answers) == 0 && !m.Truncated:
			return errors.New("dns answer has no records")
		}
		return nil
	}
}
