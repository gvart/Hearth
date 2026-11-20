// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"bufio"
	"cmp"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/netip"
	"slices"
	"strconv"
	"strings"
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
)

// TCP states in /proc/net/tcp (include/net/tcp_states.h).
const (
	tcpEstablished = 0x01
	tcpListen      = 0x0A
)

// tcpTable is what one read of /proc/net/tcp and tcp6 keeps: the ports
// listened on and the established connections, grouped by peer.
type tcpTable struct {
	listen map[uint16]bool
	// conns counts established connections by remote address and port.
	conns map[netip.AddrPort]uint32
	// local is each group's local port, for telling inbound from outbound
	// once every listening port is known; 0 when the group's connections
	// use more than one local port (outbound, ephemeral ports).
	local map[netip.AddrPort]uint16
}

func newTCPTable() *tcpTable {
	return &tcpTable{listen: map[uint16]bool{}, conns: map[netip.AddrPort]uint32{}, local: map[netip.AddrPort]uint16{}}
}

// parseProcTCP adds the sockets of one /proc/net/tcp or /proc/net/tcp6 to t:
//
//	sl  local_address rem_address   st tx_queue ...
//	 0: 00000000:0016 00000000:0000 0A 00000000:00000000 ...
//	 2: 8302A8C0:8634 7C02A8C0:4435 01 00000000:00000000 ...
//
// Addresses are hex 32-bit words in host byte order, ports hex. Only
// listening and established sockets count; malformed lines are skipped.
func (t *tcpTable) parseProcTCP(r io.Reader) error {
	sc := bufio.NewScanner(r)
	for first := true; sc.Scan(); first = false {
		if first {
			continue
		}
		f := strings.Fields(sc.Text())
		if len(f) < 4 {
			continue
		}
		st, err := strconv.ParseUint(f[3], 16, 8)
		if err != nil || (st != tcpListen && st != tcpEstablished) {
			continue
		}
		local, ok := parseProcAddr(f[1])
		if !ok {
			continue
		}
		if st == tcpListen {
			t.listen[local.Port()] = true
			continue
		}
		remote, ok := parseProcAddr(f[2])
		if !ok || remote.Addr().IsLoopback() || remote.Addr().IsUnspecified() {
			continue
		}
		n := t.conns[remote]
		switch {
		case n == 0:
			t.local[remote] = local.Port()
		case t.local[remote] != local.Port():
			t.local[remote] = 0
		}
		t.conns[remote] = n + 1
	}
	return sc.Err()
}

// parseProcAddr parses an address of /proc/net/tcp (8 hex digits) or tcp6
// (32), with its port. An IPv4-mapped IPv6 address comes back as IPv4.
func parseProcAddr(s string) (netip.AddrPort, bool) {
	h, p, ok := strings.Cut(s, ":")
	if !ok {
		return netip.AddrPort{}, false
	}
	port, err := strconv.ParseUint(p, 16, 16)
	if err != nil {
		return netip.AddrPort{}, false
	}
	raw, err := hex.DecodeString(h)
	if err != nil || (len(raw) != 4 && len(raw) != 16) {
		return netip.AddrPort{}, false
	}
	// Each 32-bit word was printed as a host-order integer: write it back
	// in host order to get the bytes in network order.
	b := make([]byte, len(raw))
	for i := 0; i < len(raw); i += 4 {
		binary.NativeEndian.PutUint32(b[i:], binary.BigEndian.Uint32(raw[i:]))
	}
	addr, _ := netip.AddrFromSlice(b)
	return netip.AddrPortFrom(addr.Unmap(), uint16(port)), true
}

// connections summarises t: connections to the same peer and port, or from
// the same peer to the same listening port, are one Connection with a count.
// A connection whose local port is listened on is inbound, keyed by that
// port, so a peer's ephemeral ports never make new entries. The list is
// sorted and holds at most maxConnections.
func (t *tcpTable) connections() []*agentv1.Connection {
	type key struct {
		ip      netip.Addr
		port    uint16
		inbound bool
	}
	groups := map[key]uint32{}
	for remote, n := range t.conns {
		k := key{ip: remote.Addr(), port: remote.Port()}
		if lp := t.local[remote]; lp != 0 && t.listen[lp] {
			k = key{ip: remote.Addr(), port: lp, inbound: true}
		}
		groups[k] += n
	}
	keys := make([]key, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	slices.SortFunc(keys, func(a, b key) int {
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
		out = append(out, &agentv1.Connection{PeerIp: k.ip.String(), Port: uint32(k.port), Inbound: k.inbound, Count: groups[k]})
	}
	return out
}

// collectNetEdges reads the device's network edges: the neighbours
// neighbors returns and the connections of tcp and tcp6 in procNet (Linux's
// /proc/net). A table that does not exist (no IPv6) is skipped. Nothing is
// kept between calls.
func collectNetEdges(procNet fs.FS, neighbors func() ([]discovery.Neighbor, error)) (*agentv1.NetEdges, error) {
	t := newTCPTable()
	for _, name := range []string{"tcp", "tcp6"} {
		f, err := procNet.Open(name)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("read tcp connections: %w", err)
		}
		err = t.parseProcTCP(f)
		_ = f.Close()
		if err != nil {
			return nil, fmt.Errorf("read tcp connections: %w", err)
		}
	}
	nb, err := neighbors()
	if err != nil {
		return nil, err
	}
	out := &agentv1.NetEdges{Connections: t.connections()}
	for _, n := range nb[:min(len(nb), maxNeighbors)] {
		out.Neighbors = append(out.Neighbors, &agentv1.Neighbor{Ip: n.IP.String(), Mac: n.MAC.String()})
	}
	return out, nil
}
