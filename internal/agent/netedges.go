// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"bufio"
	"cmp"
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"slices"
	"time"

	"github.com/gvart/hearth/internal/discovery"
	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
)

const (
	// defaultNetEdgesInterval is how often an agent whose ceiling allows it
	// reports its network edges.
	defaultNetEdgesInterval = time.Minute
	// netEdgesFirst is how long after the stream opens the first report
	// goes out.
	netEdgesFirst = 5 * time.Second
	// maxNeighbors and maxConnections bound one report.
	maxNeighbors   = 512
	maxConnections = 512
	// maxGroups bounds the connection groups one read keeps before the
	// report is cut to maxConnections, and maxListeners the listening
	// sockets: a host with a hundred thousand sockets costs no more.
	maxGroups    = 4 * maxConnections
	maxListeners = 4096
)

// TCP states in /proc/net/tcp (include/net/tcp_states.h).
const (
	tcpEstablished = 0x01
	tcpListen      = 0x0A
)

// tcpTables names the files of /proc/net read for connections.
var tcpTables = []string{"tcp", "tcp6"}

// connKey groups established connections: by peer and service port.
type connKey struct {
	ip      netip.Addr
	port    uint16
	inbound bool
}

// tcpTable is what one read of /proc/net/tcp and tcp6 keeps.
type tcpTable struct {
	// listen are the listening sockets by local address and port; wild are
	// the ports listened on on every address (0.0.0.0 or ::).
	listen map[netip.AddrPort]bool
	wild   map[uint16]bool
	// groups counts the established connections of each group.
	groups map[connKey]uint32
	// dropped counts the connections of groups beyond maxGroups.
	dropped int
}

func newTCPTable() *tcpTable {
	return &tcpTable{listen: map[netip.AddrPort]bool{}, wild: map[uint16]bool{}, groups: map[connKey]uint32{}}
}

// procTCPLine is the fields of a /proc/net/tcp or tcp6 line:
//
//	sl  local_address rem_address   st tx_queue ...
//	 0: 00000000:0016 00000000:0000 0A 00000000:00000000 ...
//	 2: 8302A8C0:8634 7C02A8C0:4435 01 00000000:00000000 ...
//
// Addresses are hex 32-bit words in host byte order, ports and the state hex.
// ok is false for the header and malformed lines.
func procTCPLine(line []byte) (local, remote netip.AddrPort, state uint8, ok bool) {
	var f [4][]byte
	n := 0
	for i := 0; i < len(line) && n < len(f); {
		for i < len(line) && (line[i] == ' ' || line[i] == '\t') {
			i++
		}
		j := i
		for j < len(line) && line[j] != ' ' && line[j] != '\t' {
			j++
		}
		if j > i {
			f[n] = line[i:j]
			n++
		}
		i = j
	}
	if n < len(f) || len(f[3]) != 2 {
		return local, remote, 0, false
	}
	st, ok := parseHex(f[3])
	if !ok {
		return local, remote, 0, false
	}
	local, ok = parseProcAddr(f[1])
	if !ok {
		return local, remote, 0, false
	}
	remote, ok = parseProcAddr(f[2])
	return local, remote, uint8(st), ok //nolint:gosec // two hex digits
}

// parseHex parses up to 8 hex digits.
func parseHex(b []byte) (uint32, bool) {
	if len(b) == 0 || len(b) > 8 {
		return 0, false
	}
	var v uint32
	for _, c := range b {
		var d byte
		switch {
		case c >= '0' && c <= '9':
			d = c - '0'
		case c >= 'A' && c <= 'F':
			d = c - 'A' + 10
		case c >= 'a' && c <= 'f':
			d = c - 'a' + 10
		default:
			return 0, false
		}
		v = v<<4 | uint32(d)
	}
	return v, true
}

// parseProcAddr parses an address of /proc/net/tcp (8 hex digits) or tcp6
// (32), with its port. An IPv4-mapped IPv6 address comes back as IPv4.
func parseProcAddr(s []byte) (netip.AddrPort, bool) {
	i := slices.Index(s, ':')
	if i < 0 || len(s)-i-1 > 4 {
		return netip.AddrPort{}, false
	}
	port, ok := parseHex(s[i+1:])
	if !ok {
		return netip.AddrPort{}, false
	}
	h := s[:i]
	if len(h) != 8 && len(h) != 32 {
		return netip.AddrPort{}, false
	}
	// Each 32-bit word was printed as a host-order integer: write it back
	// in host order to get the bytes in network order.
	var b [16]byte
	for w := 0; w < len(h)/8; w++ {
		v, ok := parseHex(h[w*8 : w*8+8])
		if !ok {
			return netip.AddrPort{}, false
		}
		binary.NativeEndian.PutUint32(b[w*4:], v)
	}
	addr := netip.AddrFrom16(b)
	if len(h) == 8 {
		addr = netip.AddrFrom4([4]byte(b[:4]))
	}
	return netip.AddrPortFrom(addr.Unmap(), uint16(port)), true //nolint:gosec // four hex digits
}

// scan calls each with every parsed line of the tables in procNet. A table
// that does not exist (no IPv6) is skipped.
func scanTCPTables(procNet fs.FS, each func(local, remote netip.AddrPort, state uint8)) error {
	for _, name := range tcpTables {
		f, err := procNet.Open(name)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			if local, remote, st, ok := procTCPLine(sc.Bytes()); ok {
				each(local, remote, st)
			}
		}
		err = sc.Err()
		_ = f.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

// readTCP reads the connections of procNet in two passes: the listening
// sockets first, then the established connections, each grouped at once.
// A connection whose local address and port are listened on (or whose port
// is listened on on every address) is inbound, keyed by that port; any other
// is outbound, keyed by the peer's port. A peer's ephemeral ports never make
// new groups, and no more than maxGroups are kept.
func readTCP(procNet fs.FS) (*tcpTable, error) {
	t := newTCPTable()
	err := scanTCPTables(procNet, func(local, _ netip.AddrPort, st uint8) {
		if st != tcpListen || len(t.listen)+len(t.wild) >= maxListeners {
			return
		}
		if local.Addr().IsUnspecified() {
			t.wild[local.Port()] = true
		} else {
			t.listen[local] = true
		}
	})
	if err != nil {
		return nil, err
	}
	err = scanTCPTables(procNet, func(local, remote netip.AddrPort, st uint8) {
		if st != tcpEstablished || remote.Addr().IsLoopback() || remote.Addr().IsUnspecified() {
			return
		}
		k := connKey{ip: remote.Addr(), port: remote.Port()}
		if t.wild[local.Port()] || t.listen[local] {
			k = connKey{ip: remote.Addr(), port: local.Port(), inbound: true}
		}
		if n, ok := t.groups[k]; ok || len(t.groups) < maxGroups {
			t.groups[k] = n + 1
			return
		}
		t.dropped++
	})
	if err != nil {
		return nil, err
	}
	return t, nil
}

// connections is the report of t: sorted, at most maxConnections.
func (t *tcpTable) connections() []*agentv1.Connection {
	keys := make([]connKey, 0, len(t.groups))
	for k := range t.groups {
		keys = append(keys, k)
	}
	slices.SortFunc(keys, func(a, b connKey) int {
		if c := a.ip.Compare(b.ip); c != 0 {
			return c
		}
		if c := cmp.Compare(a.port, b.port); c != 0 {
			return c
		}
		switch {
		case a.inbound == b.inbound:
			return 0
		case a.inbound:
			return 1
		}
		return -1
	})
	if len(keys) > maxConnections {
		keys = keys[:maxConnections]
	}
	out := make([]*agentv1.Connection, 0, len(keys))
	for _, k := range keys {
		out = append(out, &agentv1.Connection{PeerIp: k.ip.String(), Port: uint32(k.port), Inbound: k.inbound, Count: t.groups[k]})
	}
	return out
}

// bothNeighbors reads the IPv4 neighbours of v4, then the IPv6 ones of v6.
// A host whose IPv6 table cannot be read (IPv6 off) still reports its IPv4
// neighbours.
func bothNeighbors(v4, v6 func() ([]discovery.Neighbor, error)) func() ([]discovery.Neighbor, error) {
	return func() ([]discovery.Neighbor, error) {
		nb, err := v4()
		if err != nil {
			return nil, err
		}
		if nb6, err := v6(); err == nil {
			nb = append(nb, nb6...)
		}
		return nb, nil
	}
}

// collectNetEdges reads the device's network edges: the neighbours
// neighbors returns and the connections of tcp and tcp6 in procNet (Linux's
// /proc/net). Nothing is kept between calls.
func collectNetEdges(procNet fs.FS, neighbors func() ([]discovery.Neighbor, error)) (*agentv1.NetEdges, error) {
	t, err := readTCP(procNet)
	if err != nil {
		return nil, fmt.Errorf("read tcp connections: %w", err)
	}
	nb, err := neighbors()
	if err != nil {
		return nil, err
	}
	out := &agentv1.NetEdges{Connections: t.connections(), ConnectionsDropped: uint32(min(int64(t.dropped), 1<<31))} //nolint:gosec // capped
	for _, n := range nb[:min(len(nb), maxNeighbors)] {
		out.Neighbors = append(out.Neighbors, &agentv1.Neighbor{Ip: n.IP.String(), Mac: n.MAC.String()})
	}
	return out, nil
}
