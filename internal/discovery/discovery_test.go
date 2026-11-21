// SPDX-License-Identifier: AGPL-3.0-only

package discovery

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

func mustMAC(t *testing.T, s string) net.HardwareAddr {
	t.Helper()
	m, err := net.ParseMAC(s)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestVendor(t *testing.T) {
	tests := map[string]string{
		"2c:cf:67:12:34:56": "Raspberry Pi", // Pi 5
		"b8:27:eb:12:34:56": "Raspberry Pi",
		"00:11:32:12:34:56": "Synology",
		"3e:2e:f9:12:34:56": "", // locally administered: a randomized address
		"ff:ff:ff:ff:ff:ff": "",
	}
	for mac, want := range tests {
		if got := Vendor(mustMAC(t, mac)); got != want {
			t.Errorf("Vendor(%s) = %q, want %q", mac, got, want)
		}
	}
	tbl, err := loadVendors()
	if err != nil {
		t.Fatal(err)
	}
	if len(tbl.ouis) < 30_000 || !slices.IsSorted(tbl.ouis) {
		t.Errorf("table has %d OUIs (sorted: %v); want the whole MA-L registry", len(tbl.ouis), slices.IsSorted(tbl.ouis))
	}
}

func TestParseVendorsRejectsCorruptTables(t *testing.T) {
	for name, b := range map[string][]byte{"not gzip": []byte("nope"), "empty": nil} {
		if _, err := parseVendors(b); err == nil {
			t.Errorf("%s: parseVendors succeeded", name)
		}
	}
}

func TestParseProcARP(t *testing.T) {
	const in = `IP address       HW type     Flags       HW address            Mask     Device
192.168.2.1      0x1         0x2         aa:bb:cc:dd:ee:01     *        eth0
192.168.2.171    0x1         0x2         2c:cf:67:00:00:01     *        eth0
192.168.2.99     0x1         0x0         00:00:00:00:00:00     *        eth0
192.168.2.98     0x1         0x2         00:00:00:00:00:00     *        eth0
192.168.2.255    0x1         0x6         ff:ff:ff:ff:ff:ff     *        eth0
garbage
`
	got, err := parseProcARP(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].IP.String() != "192.168.2.1" || got[1].MAC.String() != "2c:cf:67:00:00:01" {
		t.Fatalf("parseProcARP = %v; want the two complete unicast entries", got)
	}
}

func TestParseSubnets(t *testing.T) {
	subnets, auto, err := ParseSubnets([]string{"192.168.2.7/24", " auto ", "10.0.0.0/30", "192.168.2.0/24", ""})
	if err != nil {
		t.Fatal(err)
	}
	if !auto || len(subnets) != 2 || subnets[0].String() != "192.168.2.0/24" || subnets[1].String() != "10.0.0.0/30" {
		t.Fatalf("ParseSubnets = %v, %v", subnets, auto)
	}
	for _, bad := range [][]string{
		{"192.168.2.0"},
		{"fd00::/64"},
		{"10.0.0.0/8"},
		{"10.0.0.1/32"},
		{"10.0.0.0/22", "10.1.0.0/24"}, // 1022 + 254 addresses
	} {
		if _, _, err := ParseSubnets(bad); err == nil {
			t.Errorf("ParseSubnets(%v) succeeded", bad)
		}
	}
	if _, _, err := ParseSubnets([]string{"10.0.0.0/22"}); err != nil {
		t.Errorf("ParseSubnets(/22) = %v, want it allowed", err)
	}
}

func TestHostsOf(t *testing.T) {
	h := hostsOf(netip.MustParsePrefix("192.168.2.0/24"))
	if len(h) != 254 || h[0].String() != "192.168.2.1" || h[253].String() != "192.168.2.254" {
		t.Fatalf("hostsOf(/24) = %d addresses from %v to %v", len(h), h[0], h[len(h)-1])
	}
}

func TestAutoSubnets(t *testing.T) {
	nets := []localNet{
		{addr: netip.MustParseAddr("192.168.2.10"), prefix: netip.MustParsePrefix("192.168.2.0/24")},
		{addr: netip.MustParseAddr("10.1.2.3"), prefix: netip.MustParsePrefix("10.0.0.0/8")},
		{addr: netip.MustParseAddr("100.64.1.2"), prefix: netip.MustParsePrefix("100.64.0.0/10")}, // CGNAT/tailnet: not private
		{addr: netip.MustParseAddr("192.168.2.11"), prefix: netip.MustParsePrefix("192.168.2.0/24")},
	}
	got := autoSubnets(nets)
	want := []netip.Prefix{netip.MustParsePrefix("192.168.2.0/24"), netip.MustParsePrefix("10.1.2.0/24")}
	if !slices.Equal(got, want) {
		t.Fatalf("autoSubnets = %v, want %v", got, want)
	}
}

func TestReverseName(t *testing.T) {
	ip := netip.MustParseAddr("192.168.2.171")
	n := reverseName(ip)
	if n != "171.2.168.192.in-addr.arpa." {
		t.Fatalf("reverseName = %s", n)
	}
	if got, ok := parseReverseName(strings.ToUpper(n)); !ok || got != ip {
		t.Fatalf("parseReverseName(%s) = %v, %v", n, got, ok)
	}
	for _, bad := range []string{"pi.local.", "1.2.3.in-addr.arpa.", "300.2.168.192.in-addr.arpa."} {
		if _, ok := parseReverseName(bad); ok {
			t.Errorf("parseReverseName(%s) succeeded", bad)
		}
	}
}

func TestMDNSQueriesSplit(t *testing.T) {
	ips := hostsOf(netip.MustParsePrefix("192.168.2.0/26"))
	msgs, err := mdnsQueries(ips)
	if err != nil {
		t.Fatal(err)
	}
	total := 0
	for _, m := range msgs {
		var msg dnsmessage.Message
		if err := msg.Unpack(m); err != nil {
			t.Fatal(err)
		}
		if len(msg.Questions) > mdnsMaxQuestions || len(m) > 1400 {
			t.Errorf("message with %d questions, %d bytes", len(msg.Questions), len(m))
		}
		total += len(msg.Questions)
	}
	if total != len(mdnsBrowse)+len(ips) {
		t.Errorf("%d questions, want %d", total, len(mdnsBrowse)+len(ips))
	}
}

func TestParseMDNS(t *testing.T) {
	name := func(s string) dnsmessage.Name { return dnsmessage.MustNewName(s) }
	msg := dnsmessage.Message{
		Header: dnsmessage.Header{Response: true, Authoritative: true},
		Questions: []dnsmessage.Question{
			{Name: name("171.2.168.192.in-addr.arpa."), Type: dnsmessage.TypePTR, Class: dnsmessage.ClassINET},
		},
		Answers: []dnsmessage.Resource{
			{
				Header: dnsmessage.ResourceHeader{Name: name("171.2.168.192.in-addr.arpa."), Type: dnsmessage.TypePTR, Class: dnsmessage.ClassINET},
				Body:   &dnsmessage.PTRResource{PTR: name("pi5.local.")},
			},
			{
				Header: dnsmessage.ResourceHeader{Name: name("_ssh._tcp.local."), Type: dnsmessage.TypePTR, Class: dnsmessage.ClassINET},
				Body:   &dnsmessage.PTRResource{PTR: name("nas._ssh._tcp.local.")},
			},
		},
		Additionals: []dnsmessage.Resource{
			{
				Header: dnsmessage.ResourceHeader{Name: name("nas._ssh._tcp.local."), Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET},
				Body:   &dnsmessage.TXTResource{TXT: []string{"x=y"}},
			},
			{
				Header: dnsmessage.ResourceHeader{Name: name("nas.local."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET},
				Body:   &dnsmessage.AResource{A: [4]byte{192, 168, 2, 20}},
			},
		},
	}
	b, err := msg.Pack()
	if err != nil {
		t.Fatal(err)
	}
	pi, nas := netip.MustParseAddr("192.168.2.171"), netip.MustParseAddr("192.168.2.20")
	ans := newMDNSAnswers()
	ans.parse(b, pi)
	got := ans.hosts([]netip.Addr{pi, nas})
	// The Pi answered the NAS's _ssh._tcp PTR: whose it is comes from the
	// SRV and A records, which come later, in another message.
	if got[pi].Name != "pi5.local" || got[nas].Name != "nas.local" || len(got[pi].Services) != 1 {
		t.Fatalf("hosts = %+v; want both names, and the NAS's service on the Pi until its SRV is heard", got)
	}
	srv := dnsmessage.Message{
		Header: dnsmessage.Header{Response: true},
		Answers: []dnsmessage.Resource{
			{
				Header: dnsmessage.ResourceHeader{Name: name("NAS._ssh._tcp.local."), Type: dnsmessage.TypeSRV, Class: dnsmessage.ClassINET},
				Body:   &dnsmessage.SRVResource{Port: 22, Target: name("nas.local.")},
			},
			{
				Header: dnsmessage.ResourceHeader{Name: name("_services._dns-sd._udp.local."), Type: dnsmessage.TypePTR, Class: dnsmessage.ClassINET},
				Body:   &dnsmessage.PTRResource{PTR: name("_smb._tcp.local.")},
			},
			{
				Header: dnsmessage.ResourceHeader{Name: name("_services._dns-sd._udp.local."), Type: dnsmessage.TypePTR, Class: dnsmessage.ClassINET},
				Body:   &dnsmessage.PTRResource{PTR: name("_Not A Type._tcp.local.")},
			},
			{
				// The instance is not of the type the PTR is for.
				Header: dnsmessage.ResourceHeader{Name: name("_ipp._tcp.local."), Type: dnsmessage.TypePTR, Class: dnsmessage.ClassINET},
				Body:   &dnsmessage.PTRResource{PTR: name("nas._ssh._tcp.local.")},
			},
		},
	}
	b, err = srv.Pack()
	if err != nil {
		t.Fatal(err)
	}
	ans.parse(b, nas)
	got = ans.hosts([]netip.Addr{pi, nas})
	if !slices.Equal(got[nas].Services, []string{"_smb._tcp", "_ssh._tcp"}) || len(got[pi].Services) != 0 {
		t.Errorf("hosts = %+v; want the NAS's services on the NAS, sorted, and none on the Pi", got)
	}
	if _, ok := ans.hosts([]netip.Addr{netip.MustParseAddr("192.168.2.99")})[nas]; ok {
		t.Error("hosts returned an address not asked for")
	}

	// A query is not an answer.
	msg.Response = false
	b, _ = msg.Pack()
	ans = newMDNSAnswers()
	ans.parse(b, pi)
	if got := ans.hosts([]netip.Addr{pi, nas}); len(got) != 0 {
		t.Errorf("took names from a query: %v", got)
	}
	ans.parse([]byte("garbage"), pi) // must not panic
}

func TestMDNSCapsServices(t *testing.T) {
	ip := netip.MustParseAddr("192.168.2.5")
	ans := newMDNSAnswers()
	for i := range mdnsMaxServices + 10 {
		ans.types[ip] = append(ans.types[ip], fmt.Sprintf("_s%02d._tcp", i))
	}
	if got := ans.hosts([]netip.Addr{ip})[ip].Services; len(got) != mdnsMaxServices {
		t.Errorf("%d services kept; want %d", len(got), mdnsMaxServices)
	}
}

func TestServiceType(t *testing.T) {
	cases := map[string]string{
		"_ipp._tcp.local":              "_ipp._tcp",
		"_sleep-proxy._udp.local":      "_sleep-proxy._udp",
		"_ipp._tcp":                    "",
		"_ipp._sctp.local":             "",
		"ipp._tcp.local":               "",
		"_a-very-long-name._tcp.local": "",
		"_sub._ipp._tcp.local":         "",
		"_x y._tcp.local":              "",
	}
	for in, want := range cases {
		if got, ok := serviceType(in); got != want || ok != (want != "") {
			t.Errorf("serviceType(%q) = %q, %v; want %q", in, got, ok, want)
		}
	}
}

func TestParseProcRoute(t *testing.T) {
	const table = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n" +
		"eth0\t00000000\t0102A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n" +
		"eth0\t0002A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n" +
		"wg0\t00000000\t00000000\t0001\t0\t0\t50\t00000000\t0\t0\t0\n" + // a default with no gateway
		"eth1\t00000000\t010AA8C0\t0003\t0\t0\t200\t00000000\t0\t0\t0\n" +
		"eth0\t00000000\t0102A8C0\t0003\t0\t0\t300\t00000000\t0\t0\t0\n" // a repeat
	got, err := parseProcRoute(strings.NewReader(table))
	want := []netip.Addr{netip.MustParseAddr("192.168.2.1"), netip.MustParseAddr("192.168.10.1")}
	if err != nil || !slices.Equal(got, want) {
		t.Errorf("parseProcRoute = %v, %v; want %v", got, err, want)
	}
}

func TestLANNameservers(t *testing.T) {
	const conf = `# generated
nameserver 192.168.2.1
nameserver 8.8.8.8
nameserver 127.0.0.53
nameserver fe80::1%en0
search lan
`
	got := lanNameservers(strings.NewReader(conf))
	want := []netip.Addr{netip.MustParseAddr("192.168.2.1"), netip.MustParseAddr("fe80::1")}
	if !slices.Equal(got, want) {
		t.Fatalf("lanNameservers = %v, want %v (public and loopback resolvers excluded)", got, want)
	}
}

type recordedEvent struct {
	typ string
	mac string
}

type events []recordedEvent

func (e *events) NetworkHosts(typ string, hosts []store.NetworkHost) {
	for _, h := range hosts {
		*e = append(*e, recordedEvent{typ, h.MAC})
	}
}

// fakeScanner is a scanner whose network steps return neigh, as the OS
// neighbour table would after a sweep.
func fakeScanner(t *testing.T, st *store.Store, pol Policy, ev Events, neigh *[]Neighbor) (*Scanner, *[][]netip.Addr) {
	t.Helper()
	s := New(Config{
		Subnets: []netip.Prefix{netip.MustParsePrefix("192.168.2.0/24")},
		Hosts:   st.NetworkHosts(), Policy: pol, Events: ev,
	})
	var swept [][]netip.Addr
	s.localNets = func() ([]localNet, error) {
		return []localNet{{
			iface: net.Interface{Index: 2, Name: "eth0", Flags: net.FlagUp | net.FlagMulticast},
			addr:  netip.MustParseAddr("192.168.2.10"), prefix: netip.MustParsePrefix("192.168.2.0/24"),
		}}, nil
	}
	s.sweep = func(_ context.Context, targets []netip.Addr) error {
		swept = append(swept, targets)
		return nil
	}
	s.neighbors = func() ([]Neighbor, error) { return *neigh, nil }
	s.mdns = func(_ context.Context, _ []net.Interface, ips []netip.Addr) (map[netip.Addr]mdnsHost, error) {
		out := map[netip.Addr]mdnsHost{}
		for _, ip := range ips {
			if ip.String() == "192.168.2.171" || ip.String() == "192.168.2.172" {
				out[ip] = mdnsHost{Name: "pi5.local", Services: []string{"_ssh._tcp", "_workstation._tcp"}}
			}
		}
		return out, nil
	}
	s.gateways = func() ([]netip.Addr, error) { return []netip.Addr{netip.MustParseAddr("192.168.2.1")}, nil }
	s.rdns = func(_ context.Context, ips []netip.Addr) map[netip.Addr]string {
		out := map[netip.Addr]string{}
		for _, ip := range ips {
			if ip.String() == "192.168.2.1" {
				out[ip] = "router.lan"
			}
		}
		return out
	}
	return s, &swept
}

func openStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(t.Context(), filepath.Join(t.TempDir(), "hearth.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func TestScanRecordsHostsKeyedByMAC(t *testing.T) {
	ctx := t.Context()
	st := openStore(t)
	var ev events
	neigh := []Neighbor{
		{IP: netip.MustParseAddr("192.168.2.171"), MAC: mustMAC(t, "2c:cf:67:00:00:01")},
		{IP: netip.MustParseAddr("192.168.2.1"), MAC: mustMAC(t, "00:11:32:00:00:02")},
		{IP: netip.MustParseAddr("192.168.2.2"), MAC: mustMAC(t, "00:11:32:00:00:02")}, // an alias of the router
		{IP: netip.MustParseAddr("10.9.9.9"), MAC: mustMAC(t, "00:11:32:00:00:09")},    // another subnet
	}
	s, swept := fakeScanner(t, st, policy.New(st.Audit()), &ev, &neigh)

	if err := s.Scan(ctx); err != nil {
		t.Fatal(err)
	}
	if len(*swept) != 1 || len((*swept)[0]) != 253 || slices.Contains((*swept)[0], netip.MustParseAddr("192.168.2.10")) {
		t.Fatalf("swept %d addresses; want the /24 without the hub's own", len((*swept)[0]))
	}
	if len(ev) != 0 {
		t.Errorf("baseline scan published %v; want nothing", ev)
	}

	// The Pi moves to .172 and a phone joins; scan again.
	neigh = []Neighbor{
		{IP: netip.MustParseAddr("192.168.2.172"), MAC: mustMAC(t, "2c:cf:67:00:00:01")},
		{IP: netip.MustParseAddr("192.168.2.1"), MAC: mustMAC(t, "00:11:32:00:00:02")},
		{IP: netip.MustParseAddr("192.168.2.30"), MAC: mustMAC(t, "3e:00:00:00:00:03")},
	}
	if err := s.Scan(ctx); err != nil {
		t.Fatal(err)
	}
	if len(ev) != 1 || ev[0] != (recordedEvent{EventNew, "3e:00:00:00:00:03"}) {
		t.Errorf("rescan published %v; want the phone as new", ev)
	}

	hosts, err := st.NetworkHosts().List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]store.NetworkHost{}
	for _, h := range hosts {
		if _, dup := got[h.MAC]; dup {
			t.Fatalf("duplicate host %s", h.MAC)
		}
		got[h.MAC] = h
	}
	if len(got) != 3 {
		t.Fatalf("hosts = %+v; want 3, one per MAC", hosts)
	}
	if pi := got["2c:cf:67:00:00:01"]; pi.IP != "192.168.2.172" || pi.Hostname != "pi5.local" || pi.Vendor != "Raspberry Pi" {
		t.Errorf("Pi = %+v; want the new IP, its mDNS name and vendor", pi)
	}
	if pi := got["2c:cf:67:00:00:01"]; !slices.Equal(pi.Services, []string{"_ssh._tcp", "_workstation._tcp"}) || pi.Gateway {
		t.Errorf("Pi = %+v; want its mDNS services, and not the gateway", pi)
	}
	if r := got["00:11:32:00:00:02"]; r.IP != "192.168.2.1" || r.Hostname != "router.lan" || r.Vendor != "Synology" || !r.Gateway {
		t.Errorf("router = %+v; want the lowest of its addresses, its reverse DNS name", r)
	}

	// One audit entry per scan, with the counts.
	entries, err := st.Audit().List(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("audit has %d entries; want one per scan", len(entries))
	}
	e := entries[0]
	if e.ActorKind != policy.ActorHub || e.Action != string(policy.NetworkScan) || e.Decision != policy.Allow ||
		e.Result != "ok" || e.Target != "192.168.2.0/24" {
		t.Errorf("audit entry = %+v", e)
	}
	var detail map[string]any
	if err := json.Unmarshal(e.Detail, &detail); err != nil {
		t.Fatal(err)
	}
	if detail["hosts"] != float64(3) || detail["new"] != float64(1) {
		t.Errorf("audit detail = %v; want the scan's counts", detail)
	}
}

func TestScanDeniedByPolicyDoesNothing(t *testing.T) {
	st := openStore(t)
	cfg := policy.Config{Classes: map[policy.Class]policy.Mode{policy.Read: policy.ModeDeny}}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	neigh := []Neighbor{{IP: netip.MustParseAddr("192.168.2.171"), MAC: mustMAC(t, "2c:cf:67:00:00:01")}}
	s, swept := fakeScanner(t, st, policy.NewWithConfig(st.Audit(), nil, cfg), nil, &neigh)
	if err := s.Scan(t.Context()); !errors.Is(err, policy.ErrDenied) {
		t.Fatalf("Scan = %v, want ErrDenied", err)
	}
	if len(*swept) != 0 {
		t.Error("a denied scan swept the network")
	}
	if hosts, _ := st.NetworkHosts().List(t.Context()); len(hosts) != 0 {
		t.Errorf("a denied scan recorded %v", hosts)
	}
	entries, _ := st.Audit().List(t.Context(), 10)
	if len(entries) != 1 || entries[0].Decision != policy.Deny {
		t.Errorf("audit = %+v; want one denial", entries)
	}
}

func TestRunStopsWithContext(t *testing.T) {
	st := openStore(t)
	var neigh []Neighbor
	s, _ := fakeScanner(t, st, policy.New(st.Audit()), nil, &neigh)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop")
	}
}
