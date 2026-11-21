// SPDX-License-Identifier: AGPL-3.0-only

package discovery

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/net/ipv4"
)

// mDNS names hosts with "legacy unicast" queries (RFC 6762 section 6.7):
// sent to the mDNS group from an ordinary ephemeral port, they are answered
// by unicast to that port. The hub so needs neither port 5353 (which avahi
// or mDNSResponder hold) nor any privilege, and never answers anything
// itself. One round of queries asks:
//
//   - the reverse name of every address the sweep found
//     (171.2.168.192.in-addr.arpa PTR), which avahi and mDNSResponder answer
//     with the host's .local name;
//   - the service browse (_services._dns-sd._udp.local) and a few common
//     service types, whose answers carry the A records of their hosts, and
//     tell which services each host offers (see Classify).
const (
	mdnsGroup = "224.0.0.251:5353"
	// mdnsWait is how long answers are collected.
	mdnsWait = 2 * time.Second
	// mdnsMaxQuestions per message keeps each one well under 1500 bytes.
	mdnsMaxQuestions = 32
	// mdnsMaxServices caps the service types kept for one host: what
	// answers is not trusted, and is stored and replicated.
	mdnsMaxServices = 32
)

var mdnsBrowse = []string{
	"_services._dns-sd._udp", "_workstation._tcp", "_device-info._tcp", "_ssh._tcp", "_sftp-ssh._tcp",
	"_smb._tcp", "_afpovertcp._tcp", "_adisk._tcp", "_nfs._tcp", "_http._tcp", "_airplay._tcp", "_raop._tcp",
	"_googlecast._tcp", "_spotify-connect._tcp", "_sonos._tcp", "_amzn-wplay._tcp", "_androidtvremote2._tcp",
	"_ipp._tcp", "_ipps._tcp", "_printer._tcp", "_pdl-datastream._tcp", "_uscan._tcp", "_hap._tcp",
	"_companion-link._tcp", "_apple-mobdev2._tcp", "_esphomelib._tcp", "_home-assistant._tcp", "_matter._tcp",
	"_hue._tcp", "_shelly._tcp",
}

// mdnsHost is what mDNS said of one address.
type mdnsHost struct {
	// Name is its .local name; "" if none was heard.
	Name string
	// Services are the service types it answers for, as "_ipp._tcp",
	// sorted.
	Services []string
}

// mdnsNames asks, on each of ifaces, for the names and services of ips, and
// returns what it heard of each of them by address. Each interface gets a
// socket of its own, all at once: on one socket switched between interfaces
// (a Mac's en0, then a VM bridge), every answer was lost.
func mdnsNames(ctx context.Context, ifaces []net.Interface, ips []netip.Addr) (map[netip.Addr]mdnsHost, error) {
	msgs, err := mdnsQueries(ips)
	if err != nil {
		return nil, err
	}
	group, err := net.ResolveUDPAddr("udp4", mdnsGroup)
	if err != nil {
		return nil, fmt.Errorf("mdns: %w", err)
	}
	ans := newMDNSAnswers()
	var (
		mu   sync.Mutex
		sent atomic.Bool
		wg   sync.WaitGroup
	)
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagMulticast == 0 {
			continue
		}
		wg.Go(func() {
			ok := mdnsAsk(ctx, ifc, group, msgs, func(msg []byte, from netip.Addr) {
				mu.Lock()
				defer mu.Unlock()
				ans.parse(msg, from)
			})
			if ok {
				sent.Store(true)
			}
		})
	}
	wg.Wait()
	if !sent.Load() {
		return nil, errors.New("mdns: no interface to query on")
	}
	return ans.hosts(ips), ctx.Err()
}

// mdnsAsk sends msgs to group on ifc and hands each answer to got until
// mdnsWait has passed or ctx is done. It reports whether it sent anything.
func mdnsAsk(ctx context.Context, ifc net.Interface, group *net.UDPAddr, msgs [][]byte, got func([]byte, netip.Addr)) bool {
	conn, err := net.ListenUDP("udp4", nil)
	if err != nil {
		return false
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.SetReadDeadline(time.Now()) })
	defer stop()
	pc := ipv4.NewPacketConn(conn)
	_ = pc.SetMulticastTTL(255)
	_ = pc.SetMulticastLoopback(false)
	if pc.SetMulticastInterface(&ifc) != nil {
		return false
	}
	sent := false
	for _, m := range msgs {
		if _, err := conn.WriteToUDP(m, group); err == nil {
			sent = true
		}
	}
	if !sent {
		return false
	}
	_ = conn.SetReadDeadline(time.Now().Add(mdnsWait))
	buf := make([]byte, 9000)
	for ctx.Err() == nil {
		n, from, err := conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			break // the deadline
		}
		got(buf[:n], from.Addr().Unmap())
	}
	return true
}

// mdnsQueries builds the query messages for one round.
func mdnsQueries(ips []netip.Addr) ([][]byte, error) {
	var qs []dnsmessage.Question
	for _, t := range mdnsBrowse {
		qs = append(qs, dnsmessage.Question{Name: dnsmessage.MustNewName(t + ".local."), Type: dnsmessage.TypePTR, Class: dnsmessage.ClassINET})
	}
	for _, ip := range ips {
		name, err := dnsmessage.NewName(reverseName(ip))
		if err != nil {
			continue
		}
		qs = append(qs, dnsmessage.Question{Name: name, Type: dnsmessage.TypePTR, Class: dnsmessage.ClassINET})
	}
	var out [][]byte
	for len(qs) > 0 {
		n := min(len(qs), mdnsMaxQuestions)
		b, err := (&dnsmessage.Message{Questions: qs[:n]}).Pack()
		if err != nil {
			return nil, fmt.Errorf("mdns: %w", err)
		}
		out = append(out, b)
		qs = qs[n:]
	}
	return out, nil
}

// reverseName is ip's in-addr.arpa name: 171.2.168.192.in-addr.arpa.
func reverseName(ip netip.Addr) string {
	b := ip.As4()
	return fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa.", b[3], b[2], b[1], b[0])
}

// parseReverseName is the inverse of reverseName.
func parseReverseName(name string) (netip.Addr, bool) {
	s, ok := strings.CutSuffix(strings.ToLower(name), ".in-addr.arpa.")
	if !ok {
		return netip.Addr{}, false
	}
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return netip.Addr{}, false
	}
	var b [4]byte
	for i, p := range parts {
		v, err := strconv.ParseUint(p, 10, 8)
		if err != nil {
			return netip.Addr{}, false
		}
		b[3-i] = byte(v)
	}
	return netip.AddrFrom4(b), true
}

// mdnsAnswers collects the answers of one round, from every message: the
// records a host's services resolve through may come in different ones.
type mdnsAnswers struct {
	// ptr are the names reverse (PTR) answers gave, a the names of A
	// records, by address, first heard.
	ptr, a map[netip.Addr]string
	// addrs are the addresses of A records by (lower-case) name.
	addrs map[string][]netip.Addr
	// instances are the service instances heard, by (lower-case) name.
	instances map[string]*mdnsInstance
	// types are the service types an address listed in answer to the
	// service browse (_services._dns-sd._udp).
	types map[netip.Addr][]string
}

// mdnsInstance is one service instance, as nas._smb._tcp.local of type
// _smb._tcp.
type mdnsInstance struct {
	// typ is "" until the PTR naming the instance is heard.
	typ string
	// target is the host its SRV record names; "" if none was heard.
	target string
	// from is the address that answered with it.
	from netip.Addr
}

func newMDNSAnswers() *mdnsAnswers {
	return &mdnsAnswers{
		ptr: map[netip.Addr]string{}, a: map[netip.Addr]string{}, addrs: map[string][]netip.Addr{},
		instances: map[string]*mdnsInstance{}, types: map[netip.Addr][]string{},
	}
}

// parse records the answers of msg, received from the address from.
func (m *mdnsAnswers) parse(msg []byte, from netip.Addr) {
	var p dnsmessage.Parser
	h, err := p.Start(msg)
	if err != nil || !h.Response {
		return
	}
	if err := p.SkipAllQuestions(); err != nil {
		return
	}
	for {
		rh, err := p.AnswerHeader()
		if err != nil {
			break
		}
		m.record(&p, rh, from, p.SkipAnswer)
	}
	if p.SkipAllAuthorities() != nil {
		return
	}
	for {
		rh, err := p.AdditionalHeader()
		if err != nil {
			break
		}
		m.record(&p, rh, from, p.SkipAdditional)
	}
}

// record reads the record whose header is rh, in the section skip skips.
func (m *mdnsAnswers) record(p *dnsmessage.Parser, rh dnsmessage.ResourceHeader, from netip.Addr, skip func() error) {
	owner := dnsName(rh.Name)
	switch rh.Type {
	case dnsmessage.TypePTR:
		r, err := p.PTRResource()
		if err != nil {
			return
		}
		if ip, ok := parseReverseName(rh.Name.String()); ok {
			setName(m.ptr, ip, r.PTR.String())
			return
		}
		target := dnsName(r.PTR)
		if owner == "_services._dns-sd._udp.local" {
			if t, ok := serviceType(target); ok && from.IsValid() && !slices.Contains(m.types[from], t) {
				m.types[from] = append(m.types[from], t)
			}
			return
		}
		// A service PTR: _ssh._tcp.local -> nas._ssh._tcp.local.
		t, ok := serviceType(owner)
		if !ok || !strings.HasSuffix(target, "."+owner) {
			return
		}
		switch in := m.instances[target]; {
		case in == nil:
			m.instances[target] = &mdnsInstance{typ: t, from: from}
		case in.typ == "":
			in.typ = t
		}
	case dnsmessage.TypeSRV:
		r, err := p.SRVResource()
		if err != nil {
			return
		}
		switch in := m.instances[owner]; {
		case in == nil:
			// The SRV may come before the PTR that names its instance.
			m.instances[owner] = &mdnsInstance{target: dnsName(r.Target), from: from}
		case in.target == "":
			in.target = dnsName(r.Target)
		}
	case dnsmessage.TypeA:
		r, err := p.AResource()
		if err != nil {
			return
		}
		ip := netip.AddrFrom4(r.A)
		setName(m.a, ip, rh.Name.String())
		if !slices.Contains(m.addrs[owner], ip) {
			m.addrs[owner] = append(m.addrs[owner], ip)
		}
	default:
		_ = skip()
	}
}

// hosts returns what was heard of each of ips: its reverse name, else the
// name of an A record for it, and the service types it answers for. An
// instance's type goes to the addresses its SRV target resolves to or,
// without them, to the address that answered with it; a type an address
// listed in answer to the service browse goes to that address.
func (m *mdnsAnswers) hosts(ips []netip.Addr) map[netip.Addr]mdnsHost {
	services := map[netip.Addr][]string{}
	add := func(ip netip.Addr, t string) {
		if !slices.Contains(services[ip], t) {
			services[ip] = append(services[ip], t)
		}
	}
	for _, in := range m.instances {
		if in.typ == "" {
			continue // an SRV without the PTR of its instance
		}
		if to := m.addrs[in.target]; len(to) > 0 {
			for _, ip := range to {
				add(ip, in.typ)
			}
		} else if in.from.IsValid() {
			add(in.from, in.typ)
		}
	}
	for ip, ts := range m.types {
		for _, t := range ts {
			add(ip, t)
		}
	}
	out := map[netip.Addr]mdnsHost{}
	for _, ip := range ips {
		name := m.ptr[ip]
		if name == "" {
			name = m.a[ip]
		}
		s := services[ip]
		slices.Sort(s)
		if len(s) > mdnsMaxServices {
			s = s[:mdnsMaxServices]
		}
		if name != "" || len(s) > 0 {
			out[ip] = mdnsHost{Name: name, Services: s}
		}
	}
	return out
}

// dnsName is n in lower case, without its final dot.
func dnsName(n dnsmessage.Name) string {
	return strings.ToLower(strings.TrimSuffix(n.String(), "."))
}

// serviceType returns the DNS-SD service type of name, "_ipp._tcp" of
// "_ipp._tcp.local", if it is one: an underscore and a label of at most 15
// letters, digits and hyphens (RFC 6335), then _tcp or _udp.
func serviceType(name string) (string, bool) {
	s, ok := strings.CutSuffix(name, ".local")
	if !ok {
		return "", false
	}
	svc, proto, ok := strings.Cut(s, ".")
	if !ok || (proto != "_tcp" && proto != "_udp") || len(svc) < 2 || len(svc) > 16 || svc[0] != '_' {
		return "", false
	}
	for _, c := range svc[1:] {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			return "", false
		}
	}
	return s, true
}

func setName(m map[netip.Addr]string, ip netip.Addr, name string) {
	name = strings.TrimSuffix(name, ".")
	if _, ok := m[ip]; !ok && name != "" {
		m[ip] = name
	}
}
