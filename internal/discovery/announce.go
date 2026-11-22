// SPDX-License-Identifier: AGPL-3.0-only

package discovery

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/net/ipv4"
)

// LANName is the name the web UI answers at on the LAN: one master
// announces it over mDNS with its LAN addresses (Announcer), and every
// master's certificate names it. Agents never use it.
const LANName = "hearth.local"

const (
	// announceTTL is the TTL of the A records announced, in seconds: short,
	// so a client that missed a new master's announcement asks again soon.
	announceTTL = 10
	// announceRetry is how long Run waits before it tries to listen again.
	announceRetry = 30 * time.Second
	// mdnsPort is the mDNS port; responses come from it (RFC 6762 §11).
	mdnsPort = 5353
	// classCacheFlush is the cache-flush bit of a record's class (§10.2),
	// and the unicast-response bit of a question's.
	classCacheFlush = 1 << 15
	// typeNSEC is the NSEC record type, which says the name has no record
	// of the other types asked (§6.1).
	typeNSEC dnsmessage.Type = 47
)

// Announcer answers mDNS queries for Name with this host's LAN addresses,
// next to the OS responder (mDNSResponder, avahi): its socket shares port
// 5353 (SO_REUSEADDR, and SO_REUSEPORT where the OS has it). It answers A
// queries only, on the interfaces LANAddrs counts, each with the addresses
// of the interface the query came in on.
type Announcer struct {
	Name string
	Log  *slog.Logger
}

// Run announces Name until ctx is done, then says goodbye (a record of TTL
// 0) so clients drop it at once. It retries every announceRetry while it
// cannot listen (no LAN interface yet at boot), and returns nil when ctx is
// done: a hub without mDNS keeps running.
func (a *Announcer) Run(ctx context.Context) error {
	for {
		err := a.serve(ctx)
		if ctx.Err() != nil {
			return nil
		}
		a.Log.WarnContext(ctx, "mDNS: not announcing "+a.Name+", retrying", "err", err, "in", announceRetry)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(announceRetry):
		}
	}
}

// serve listens and answers until ctx is done or the socket fails.
func (a *Announcer) serve(ctx context.Context) error {
	ifaces, err := lanIfaces()
	if err != nil {
		return err
	}
	if len(ifaces) == 0 {
		return fmt.Errorf("no LAN interface")
	}
	name, err := dnsmessage.NewName(strings.TrimSuffix(a.Name, ".") + ".")
	if err != nil {
		return fmt.Errorf("mdns name %q: %w", a.Name, err)
	}
	group := &net.UDPAddr{IP: net.IPv4(224, 0, 0, 251), Port: mdnsPort}
	conn, err := net.ListenMulticastUDP("udp4", &ifaces[0], group)
	if err != nil {
		return fmt.Errorf("listen on mDNS port: %w", err)
	}
	defer conn.Close()
	pc := ipv4.NewPacketConn(conn)
	for _, ifc := range ifaces[1:] {
		if err := pc.JoinGroup(&ifc, group); err != nil {
			a.Log.WarnContext(ctx, "mDNS: join group", "iface", ifc.Name, "err", err)
		}
	}
	// On, so the responder of this very host hears the answers too.
	_ = pc.SetMulticastLoopback(true)
	_ = pc.SetMulticastTTL(255)
	if err := pc.SetControlMessage(ipv4.FlagInterface, true); err != nil {
		return fmt.Errorf("mdns: %w", err)
	}
	s := &mdnsSender{pc: pc, group: group}
	addrs := map[string][]netip.Addr{}
	for _, ifc := range ifaces {
		addrs[ifc.Name] = ifaceLANAddrs(ifc)
	}
	a.Log.InfoContext(ctx, "mDNS: announcing "+a.Name, "addrs", addrs)

	// Announce twice, a second apart (§8.3), so caches holding another
	// master's addresses flush them; say goodbye when done.
	announce := func(ttl uint32) {
		for _, ifc := range ifaces {
			if msg, err := lanNameAnnouncement(name, ifaceLANAddrs(ifc), ttl); err == nil {
				s.multicast(&ifc, msg)
			}
		}
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.SetReadDeadline(time.Now()) })
	defer stop()
	var wg sync.WaitGroup
	defer wg.Wait()
	wg.Go(func() {
		for range 2 {
			announce(announceTTL)
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Second):
			}
		}
	})
	defer func() {
		announce(0)
		a.Log.InfoContext(context.WithoutCancel(ctx), "mDNS: stopped announcing "+a.Name)
	}()

	byIndex := map[int]net.Interface{}
	for _, ifc := range ifaces {
		byIndex[ifc.Index] = ifc
	}
	buf := make([]byte, 9000)
	for {
		n, cm, src, err := pc.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("read mDNS: %w", err)
		}
		from, ok := src.(*net.UDPAddr)
		if !ok || cm == nil {
			continue
		}
		ifc, ok := byIndex[cm.IfIndex]
		if !ok {
			continue
		}
		legacy := from.Port != mdnsPort
		reply, err := lanNameReply(buf[:n], name, ifaceLANAddrs(ifc), legacy)
		if err != nil || reply == nil {
			continue
		}
		if legacy {
			s.unicast(reply, from)
		} else {
			s.multicast(&ifc, reply)
		}
	}
}

// mdnsSender writes on the shared socket: the multicast interface is set
// before each write, so writes take turns.
type mdnsSender struct {
	mu    sync.Mutex
	pc    *ipv4.PacketConn
	group *net.UDPAddr
}

func (s *mdnsSender) multicast(ifc *net.Interface, msg []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pc.SetMulticastInterface(ifc) == nil {
		_, _ = s.pc.WriteTo(msg, nil, s.group)
	}
}

func (s *mdnsSender) unicast(msg []byte, to *net.UDPAddr) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, _ = s.pc.WriteTo(msg, nil, to)
}

// lanIfaces are the multicast interfaces holding a LAN address (LANAddrs).
func lanIfaces() ([]net.Interface, error) {
	nets, err := localNets()
	if err != nil {
		return nil, err
	}
	lan := lanAddrs(nets)
	var out []net.Interface
	for _, n := range nets {
		if n.iface.Flags&net.FlagMulticast == 0 || !slices.Contains(lan, n.addr) ||
			slices.ContainsFunc(out, func(x net.Interface) bool { return x.Index == n.iface.Index }) {
			continue
		}
		out = append(out, n.iface)
	}
	return out, nil
}

// ifaceLANAddrs are the LAN addresses of ifc now: an address DHCP changes
// is answered with its new value.
func ifaceLANAddrs(ifc net.Interface) []netip.Addr {
	nets, err := localNets()
	if err != nil {
		return nil
	}
	var out []netip.Addr
	for _, a := range lanAddrs(nets) {
		if slices.ContainsFunc(nets, func(n localNet) bool { return n.addr == a && n.iface.Index == ifc.Index }) {
			out = append(out, a)
		}
	}
	return out
}

// lanNameReply is the answer to the mDNS message msg if it asks for name's
// A record (or any record of name), with addrs; nil if it asks nothing of
// name, is a response, or addrs is empty. A query from a port other than
// 5353 (legacy, RFC 6762 §6.7) gets a unicast-style answer: its ID and
// questions, no cache-flush bit. A question for another type of name (AAAA)
// gets an NSEC record saying name has only A records, so the client does
// not wait for one.
func lanNameReply(msg []byte, name dnsmessage.Name, addrs []netip.Addr, legacy bool) ([]byte, error) {
	if len(addrs) == 0 {
		return nil, nil
	}
	var p dnsmessage.Parser
	h, err := p.Start(msg)
	if err != nil {
		return nil, err
	}
	if h.Response || h.OpCode != 0 {
		return nil, nil
	}
	qs, err := p.AllQuestions()
	if err != nil {
		return nil, err
	}
	var asked []dnsmessage.Question
	wantA, other := false, false
	for _, q := range qs {
		if !strings.EqualFold(q.Name.String(), name.String()) || q.Class&^classCacheFlush != dnsmessage.ClassINET {
			continue
		}
		asked = append(asked, q)
		switch q.Type {
		case dnsmessage.TypeA, dnsmessage.TypeALL:
			wantA = true
		default:
			other = true
		}
	}
	if len(asked) == 0 {
		return nil, nil
	}
	rh := dnsmessage.Header{Response: true, Authoritative: true}
	ttl := uint32(announceTTL)
	class := dnsmessage.ClassINET | classCacheFlush
	if legacy {
		rh.ID = h.ID
		class = dnsmessage.ClassINET
	}
	b := dnsmessage.NewBuilder(nil, rh)
	b.EnableCompression()
	if legacy {
		if err := b.StartQuestions(); err != nil {
			return nil, err
		}
		for _, q := range asked {
			if err := b.Question(q); err != nil {
				return nil, err
			}
		}
	}
	if err := b.StartAnswers(); err != nil {
		return nil, err
	}
	if wantA {
		if err := addARecords(&b, name, class, ttl, addrs); err != nil {
			return nil, err
		}
	}
	if other {
		if err := addNSEC(&b, name, class, ttl); err != nil {
			return nil, err
		}
	}
	if !wantA {
		// The A records ride along as additional records (§6.2).
		if err := b.StartAdditionals(); err != nil {
			return nil, err
		}
		if err := addARecords(&b, name, class, ttl, addrs); err != nil {
			return nil, err
		}
	}
	return b.Finish()
}

// lanNameAnnouncement is an unsolicited response announcing name's A
// records with addrs (§8.3), or, with ttl 0, their goodbye (§10.1); an
// error if addrs is empty.
func lanNameAnnouncement(name dnsmessage.Name, addrs []netip.Addr, ttl uint32) ([]byte, error) {
	if len(addrs) == 0 {
		return nil, fmt.Errorf("no address")
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{Response: true, Authoritative: true})
	b.EnableCompression()
	if err := b.StartAnswers(); err != nil {
		return nil, err
	}
	if err := addARecords(&b, name, dnsmessage.ClassINET|classCacheFlush, ttl, addrs); err != nil {
		return nil, err
	}
	return b.Finish()
}

func addARecords(b *dnsmessage.Builder, name dnsmessage.Name, class dnsmessage.Class, ttl uint32, addrs []netip.Addr) error {
	for _, a := range addrs {
		if !a.Is4() {
			continue
		}
		rh := dnsmessage.ResourceHeader{Name: name, Class: class, TTL: ttl}
		if err := b.AResource(rh, dnsmessage.AResource{A: a.As4()}); err != nil {
			return err
		}
	}
	return nil
}

// addNSEC adds an NSEC record saying name has A records only (§6.1): the
// next name is name itself, the bitmap window 0 holds type A (bit 1).
func addNSEC(b *dnsmessage.Builder, name dnsmessage.Name, class dnsmessage.Class, ttl uint32) error {
	var data []byte
	for _, label := range strings.Split(strings.TrimSuffix(name.String(), "."), ".") {
		n := len(label)
		if n == 0 || n > 63 {
			return fmt.Errorf("mdns name %q: bad label", name)
		}
		data = append(data, byte(n))
		data = append(data, label...)
	}
	data = append(data, 0, 0, 1, 0x40)
	rh := dnsmessage.ResourceHeader{Name: name, Class: class, TTL: ttl}
	return b.UnknownResource(rh, dnsmessage.UnknownResource{Type: typeNSEC, Data: data})
}
