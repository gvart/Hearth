// SPDX-License-Identifier: AGPL-3.0-only

package discovery

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
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
//     service types, whose answers carry the A records of their hosts.
const (
	mdnsGroup = "224.0.0.251:5353"
	// mdnsWait is how long answers are collected.
	mdnsWait = 2 * time.Second
	// mdnsMaxQuestions per message keeps each one well under 1500 bytes.
	mdnsMaxQuestions = 32
)

var mdnsBrowse = []string{
	"_services._dns-sd._udp", "_workstation._tcp", "_device-info._tcp", "_ssh._tcp", "_sftp-ssh._tcp",
	"_smb._tcp", "_afpovertcp._tcp", "_http._tcp", "_airplay._tcp", "_raop._tcp", "_googlecast._tcp",
	"_ipp._tcp", "_printer._tcp", "_hap._tcp", "_companion-link._tcp", "_spotify-connect._tcp",
	"_esphomelib._tcp", "_home-assistant._tcp",
}

// mdnsNames asks, on each of ifaces, for the names of ips, and returns the
// names it heard by address.
func mdnsNames(ctx context.Context, ifaces []net.Interface, ips []netip.Addr) (map[netip.Addr]string, error) {
	msgs, err := mdnsQueries(ips)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp4", nil)
	if err != nil {
		return nil, fmt.Errorf("mdns: %w", err)
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.SetReadDeadline(time.Now()) })
	defer stop()
	group, err := net.ResolveUDPAddr("udp4", mdnsGroup)
	if err != nil {
		return nil, fmt.Errorf("mdns: %w", err)
	}
	pc := ipv4.NewPacketConn(conn)
	_ = pc.SetMulticastTTL(255)
	_ = pc.SetMulticastLoopback(false)
	sent := false
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagMulticast == 0 || pc.SetMulticastInterface(&ifc) != nil {
			continue
		}
		for _, m := range msgs {
			if _, err := conn.WriteToUDP(m, group); err == nil {
				sent = true
			}
		}
	}
	if !sent {
		return nil, errors.New("mdns: no interface to query on")
	}

	ptr, a := map[netip.Addr]string{}, map[netip.Addr]string{}
	_ = conn.SetReadDeadline(time.Now().Add(mdnsWait))
	buf := make([]byte, 9000)
	for ctx.Err() == nil {
		n, _, err := conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			break // the deadline
		}
		parseMDNS(buf[:n], ptr, a)
	}
	for ip, name := range a {
		if _, ok := ptr[ip]; !ok {
			ptr[ip] = name
		}
	}
	return ptr, ctx.Err()
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

// parseMDNS records the reverse (PTR) answers of msg into ptr and its A
// records into a, keeping the first name heard for each address.
func parseMDNS(msg []byte, ptr, a map[netip.Addr]string) {
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
		readRecord(&p, rh, ptr, a, p.SkipAnswer)
	}
	if p.SkipAllAuthorities() != nil {
		return
	}
	for {
		rh, err := p.AdditionalHeader()
		if err != nil {
			break
		}
		readRecord(&p, rh, ptr, a, p.SkipAdditional)
	}
}

// readRecord reads the record whose header is rh, in the section skip
// skips.
func readRecord(p *dnsmessage.Parser, rh dnsmessage.ResourceHeader, ptr, a map[netip.Addr]string, skip func() error) {
	switch rh.Type {
	case dnsmessage.TypePTR:
		r, err := p.PTRResource()
		if err != nil {
			return
		}
		if ip, ok := parseReverseName(rh.Name.String()); ok {
			setName(ptr, ip, r.PTR.String())
		}
	case dnsmessage.TypeA:
		r, err := p.AResource()
		if err != nil {
			return
		}
		setName(a, netip.AddrFrom4(r.A), rh.Name.String())
	default:
		_ = skip()
	}
}

func setName(m map[netip.Addr]string, ip netip.Addr, name string) {
	name = strings.TrimSuffix(name, ".")
	if _, ok := m[ip]; !ok && name != "" {
		m[ip] = name
	}
}
