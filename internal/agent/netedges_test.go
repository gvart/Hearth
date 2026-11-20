// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"testing"
	"testing/fstest"

	"google.golang.org/protobuf/proto"

	"github.com/gvart/hearth/internal/discovery"
	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
)

// procAddr formats addr:port as /proc/net/tcp does on this machine: each
// 32-bit word of the address as a host-order integer, then the port, in hex.
func procAddr(s string) string {
	ap := netip.MustParseAddrPort(s)
	b := ap.Addr().AsSlice()
	var out strings.Builder
	for i := 0; i < len(b); i += 4 {
		fmt.Fprintf(&out, "%08X", binary.NativeEndian.Uint32(b[i:]))
	}
	return fmt.Sprintf("%s:%04X", out.String(), ap.Port())
}

func tcpLine(local, remote, state string) string {
	return fmt.Sprintf("   0: %s %s %s 00000000:00000000 00:00000000 00000000  1000        0 830497 2 00000000c809b9b9 22 4 30 10 -1",
		procAddr(local), procAddr(remote), state)
}

const tcpHeader = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode"

func TestParseProcAddr(t *testing.T) {
	if binary.NativeEndian.Uint16([]byte{1, 0}) != 1 {
		t.Skip("the literal fixtures below are little-endian")
	}
	tests := map[string]string{
		// Captured on a Raspberry Pi (aarch64), addresses replaced.
		"0100007F:0016": "127.0.0.1:22",
		"0A0200C0:8634": "192.0.2.10:34356",
		"00000000:1D13": "0.0.0.0:7443",
		// tcp6: ::1, and ::ffff:192.0.2.10, which comes back as IPv4.
		"00000000000000000000000001000000:0016": "[::1]:22",
		"0000000000000000FFFF00000A0200C0:01BB": "192.0.2.10:443",
		"B80D0120000000000000000001000000:0050": "[2001:db8::1]:80",
	}
	for in, want := range tests {
		got, ok := parseProcAddr(in)
		if !ok || got.String() != want {
			t.Errorf("parseProcAddr(%q) = %v, %v; want %s", in, got, ok, want)
		}
	}
	for _, bad := range []string{"", "0100007F", "0100007F:", "0100007F:XYZ", "01007F:0016", "0100007F:10000", "zz00007F:0016"} {
		if got, ok := parseProcAddr(bad); ok {
			t.Errorf("parseProcAddr(%q) = %v, want refused", bad, got)
		}
	}
}

func TestTCPTableConnections(t *testing.T) {
	tcp := strings.Join([]string{
		tcpHeader,
		tcpLine("0.0.0.0:22", "0.0.0.0:0", "0A"), // listens on 22
		tcpLine("192.0.2.5:22", "192.0.2.20:50001", "01"), // inbound ssh, two sockets
		tcpLine("192.0.2.5:22", "192.0.2.20:50002", "01"),
		tcpLine("192.0.2.5:40000", "192.0.2.10:7443", "01"), // outbound to the hub, two sockets
		tcpLine("192.0.2.5:40001", "192.0.2.10:7443", "01"),
		tcpLine("192.0.2.5:40002", "192.0.2.30:443", "06"), // TIME_WAIT: not established
		tcpLine("127.0.0.1:40003", "127.0.0.1:5432", "01"), // loopback: skipped
		"   9: garbage line",
	}, "\n")
	tcp6 := strings.Join([]string{
		tcpHeader,
		tcpLine("[::]:8080", "[::]:0", "0A"),
		tcpLine("[2001:db8::5]:8080", "[2001:db8::9]:51000", "01"),            // inbound on 8080
		tcpLine("[::ffff:192.0.2.5]:40010", "[::ffff:192.0.2.10]:7443", "01"), // mapped: joins the IPv4 group
		tcpLine("[::1]:40011", "[::1]:8080", "01"),
	}, "\n")
	fsys := fstest.MapFS{"tcp": {Data: []byte(tcp)}, "tcp6": {Data: []byte(tcp6)}}
	arp := []discovery.Neighbor{{IP: netip.MustParseAddr("192.0.2.1"), MAC: net.HardwareAddr{0xaa, 0xbb, 0xcc, 0, 0, 1}}}

	got, err := collectNetEdges(fsys, func() ([]discovery.Neighbor, error) { return arp, nil })
	if err != nil {
		t.Fatal(err)
	}
	want := &agentv1.NetEdges{
		Neighbors: []*agentv1.Neighbor{{Ip: "192.0.2.1", Mac: "aa:bb:cc:00:00:01"}},
		Connections: []*agentv1.Connection{
			{PeerIp: "192.0.2.10", Port: 7443, Count: 3},
			{PeerIp: "192.0.2.20", Port: 22, Inbound: true, Count: 2},
			{PeerIp: "2001:db8::9", Port: 8080, Inbound: true, Count: 1},
		},
	}
	if !proto.Equal(got, want) {
		t.Errorf("collectNetEdges =\n%v\nwant\n%v", got, want)
	}
}

func TestCollectNetEdgesWithoutIPv6(t *testing.T) {
	fsys := fstest.MapFS{"tcp": {Data: []byte(tcpHeader + "\n" + tcpLine("192.0.2.5:40000", "192.0.2.10:7443", "01"))}}
	got, err := collectNetEdges(fsys, func() ([]discovery.Neighbor, error) { return nil, nil })
	if err != nil || len(got.GetConnections()) != 1 {
		t.Fatalf("collectNetEdges without tcp6 = %v, %v; want the one IPv4 connection", got, err)
	}
	want := errors.New("no neighbour table")
	if _, err := collectNetEdges(fsys, func() ([]discovery.Neighbor, error) { return nil, want }); !errors.Is(err, want) {
		t.Errorf("collectNetEdges with a failing neighbour table = %v, want %v", err, want)
	}
}

// One report never grows past its caps, however many sockets the device
// holds.
func TestCollectNetEdgesCaps(t *testing.T) {
	lines := []string{tcpHeader}
	var arp []discovery.Neighbor
	for i := range maxConnections + 50 {
		peer := netip.AddrFrom4([4]byte{10, 1, byte(i >> 8), byte(i)})
		lines = append(lines, tcpLine("192.0.2.5:40000", netip.AddrPortFrom(peer, 443).String(), "01"))
		arp = append(arp, discovery.Neighbor{IP: peer, MAC: net.HardwareAddr{2, 0, 0, 0, byte(i >> 8), byte(i)}})
	}
	fsys := fstest.MapFS{"tcp": {Data: []byte(strings.Join(lines, "\n"))}}
	got, err := collectNetEdges(fsys, func() ([]discovery.Neighbor, error) { return arp, nil })
	if err != nil {
		t.Fatal(err)
	}
	if len(got.GetConnections()) != maxConnections || len(got.GetNeighbors()) != maxNeighbors {
		t.Errorf("report holds %d connections and %d neighbours, want %d and %d",
			len(got.GetConnections()), len(got.GetNeighbors()), maxConnections, maxNeighbors)
	}
}
