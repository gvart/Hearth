// SPDX-License-Identifier: AGPL-3.0-only

// Package probe runs the network checks of the http, tcp and dns automation
// triggers. The hub runs them itself, and an agent runs them for the hub
// (from: <device>), with the same code so both behave the same.
package probe

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/net/dns/dnsmessage"

	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
)

// Run runs the check req describes, bounded by ctx, and returns why it
// failed, or nil when it passed. Errors never repeat an HTTP URL: it may
// carry credentials.
func Run(ctx context.Context, req *agentv1.ProbeRequest) error {
	switch p := req.GetProbe().(type) {
	case *agentv1.ProbeRequest_Http:
		return HTTP(ctx, p.Http.GetUrl(), int(p.Http.GetStatus()))
	case *agentv1.ProbeRequest_Tcp:
		return TCP(ctx, p.Tcp.GetAddress())
	case *agentv1.ProbeRequest_Dns:
		name, err := DNSName(p.Dns.GetName())
		if err != nil {
			return err
		}
		return DNS(ctx, p.Dns.GetServer(), name)
	}
	return errors.New("unknown probe")
}

// HTTP GETs rawURL and checks the status: want, or 2xx/3xx if want is 0. It
// opens a fresh connection: a pooled one could hide a server that stopped
// accepting new ones.
func HTTP(ctx context.Context, rawURL string, want int) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return stripURL(err)
	}
	hc := &http.Client{Transport: &http.Transport{Proxy: http.ProxyFromEnvironment, DisableKeepAlives: true}}
	resp, err := hc.Do(req)
	if err != nil {
		return stripURL(err)
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	_ = resp.Body.Close()
	ok := resp.StatusCode == want || (want == 0 && resp.StatusCode >= 200 && resp.StatusCode < 400)
	if !ok {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	return nil
}

// stripURL unwraps a url.Error, which repeats the full URL, password and
// all.
func stripURL(err error) error {
	var uerr *url.Error
	if errors.As(err, &uerr) {
		return uerr.Err
	}
	return err
}

// TCP opens a TCP connection to address (host:port) and closes it.
func TCP(ctx context.Context, address string) error {
	var d net.Dialer
	c, err := d.DialContext(ctx, "tcp", address)
	if err != nil {
		return err
	}
	return c.Close()
}

// DNSName parses a domain name, with or without its final dot.
func DNSName(s string) (dnsmessage.Name, error) {
	name, err := dnsmessage.NewName(strings.TrimSuffix(s, ".") + ".")
	if s == "" || err != nil {
		return dnsmessage.Name{}, errors.New("name must be a domain name")
	}
	return name, nil
}

// DNS asks server (host:port), over UDP, for the A records of name, and
// requires a successful answer with at least one record. It asks the server
// directly, so /etc/hosts and the local resolver play no part.
func DNS(ctx context.Context, server string, name dnsmessage.Name) error {
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
