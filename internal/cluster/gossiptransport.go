// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/memberlist"
	"github.com/hashicorp/raft"

	"github.com/gvart/hearth/internal/pki"
)

// The first byte a gossip connection's dialer sends says what it carries.
const (
	// gossipPackets: length-prefixed memberlist packets, one way, until the
	// dialer closes the connection.
	gossipPackets byte = 'p'
	// gossipStream: one memberlist stream (push/pull, join, TCP ping).
	gossipStream byte = 's'
	// gossipVerify: nothing; the dialer only wanted the handshake, to learn
	// which hub owns the address (see verifyOwner).
	gossipVerify byte = 'v'
	// gossipReplica: replication requests of a sharded cluster (replicate.go),
	// served by MembershipConfig.Replica.
	gossipReplica byte = 'r'
)

const (
	// maxGossipPacket bounds a packet frame; memberlist's packets are about
	// a UDP datagram (UDPBufferSize, 1400 bytes by default).
	maxGossipPacket = 64 << 10
	// gossipQueueLen is how many packets wait for one peer before new ones
	// are dropped, as a full UDP socket buffer would drop them.
	gossipQueueLen = 64
	// gossipIdle closes a peer's packet connection, and ends its sender,
	// after this long without packets.
	gossipIdle = 30 * time.Second
	// gossipHandshakeTimeout bounds the TLS handshake and the first byte of
	// an accepted connection.
	gossipHandshakeTimeout = 10 * time.Second
	// verifyRetry spaces out verification dials to one address.
	verifyRetry = time.Second
)

// gossipTransport is a memberlist.Transport over TCP with mutual TLS, so
// membership needs no UDP and no shared gossip key: both ends present a hub
// node certificate from the hub CA, and the same check as the Raft transport
// (a revoked hub certificate is refused) runs on every handshake.
//
// memberlist's packets, which it would send over UDP, go over one TLS
// connection per peer that a sender goroutine owns. WriteTo never blocks
// memberlist's probe and gossip loops: it queues the packet and drops it when
// the peer's queue is full, as UDP would. Streams are one TLS connection each.
type gossipTransport struct {
	stream      *tlsStream
	ip          net.IP
	port        int
	dialTimeout time.Duration
	log         *slog.Logger

	packetCh chan *memberlist.Packet
	streamCh chan net.Conn

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// mu guards peers, the packet queues by address, and closed.
	mu     sync.Mutex
	peers  map[string]chan []byte
	closed bool

	// seen is when a packet or stream last arrived from each hub node ID,
	// as its certificate names it.
	seenMu sync.Mutex
	seen   map[string]time.Time

	// owners maps a gossip address (ip:port) to the hub node ID whose
	// certificate the member there presented when this transport last
	// dialed it; verifying and verifyTried track verification dials.
	ownMu       sync.Mutex
	owners      map[string]string
	verifying   map[string]bool
	verifyTried map[string]time.Time

	// replica serves gossipReplica connections; nil refuses them.
	replica atomic.Pointer[func(net.Conn, string)]
}

var _ memberlist.Transport = (*gossipTransport)(nil)

// newGossipTransport serves gossip on ln, or on a new listener on listen
// when ln is nil. advertise is the host:port other members dial; its host is
// resolved to an IP, which memberlist requires. cert returns the hub node
// certificate to present at each handshake, so a hub CA rotation reaches new
// connections; check refuses peers, as the Raft transport's does.
func newGossipTransport(ctx context.Context, ln net.Listener, listen, advertise string, cert func() *tls.Certificate,
	ca *pki.CA, check peerCheck, dialTimeout time.Duration, log *slog.Logger,
) (*gossipTransport, error) {
	if ln == nil {
		var err error
		if ln, err = (&net.ListenConfig{}).Listen(ctx, "tcp", listen); err != nil {
			return nil, fmt.Errorf("gossip listen on %s: %w", listen, err)
		}
	}
	if advertise == "" {
		advertise = ln.Addr().String()
	}
	ip, port, err := resolveAdvertise(ctx, advertise)
	if err != nil {
		_ = ln.Close()
		return nil, err
	}
	s := &tlsStream{advertise: advertiseAddr(advertise), conns: map[*trackedConn]struct{}{}}
	s.Listener = tls.NewListener(ln, serverTLSFunc(cert, ca, check))
	s.client = clientTLSFunc(cert, ca, check)
	t := &gossipTransport{
		stream: s, ip: ip, port: port, dialTimeout: dialTimeout, log: log,
		packetCh: make(chan *memberlist.Packet), streamCh: make(chan net.Conn),
		peers: map[string]chan []byte{}, seen: map[string]time.Time{},
		owners: map[string]string{}, verifying: map[string]bool{}, verifyTried: map[string]time.Time{},
	}
	t.ctx, t.cancel = context.WithCancel(context.Background())
	t.wg.Go(t.accept)
	return t, nil
}

// resolveAdvertise returns the IP and port of a host:port, resolving a host
// name. An unspecified IP cannot be dialed by other members.
func resolveAdvertise(ctx context.Context, advertise string) (net.IP, int, error) {
	host, portStr, err := net.SplitHostPort(advertise)
	if err != nil {
		return nil, 0, fmt.Errorf("gossip advertise address %q: %w", advertise, err)
	}
	port, err := net.LookupPort("tcp", portStr)
	if err != nil {
		return nil, 0, fmt.Errorf("gossip advertise address %q: %w", advertise, err)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
		if err != nil || len(ips) == 0 {
			return nil, 0, fmt.Errorf("gossip advertise address %q: resolve %s: %w", advertise, host, err)
		}
		// A host name often maps to a loopback address too (127.0.1.1 in
		// Debian's /etc/hosts), which other members cannot dial. Prefer
		// IPv4, which every member can reach on a typical LAN.
		for _, x := range ips {
			if !x.IsLoopback() && (ip == nil || ip.To4() == nil && x.To4() != nil) {
				ip = x
			}
		}
		if ip == nil {
			return nil, 0, fmt.Errorf("gossip advertise address %q: %s resolves only to loopback; set --gossip-advertise",
				advertise, host)
		}
	}
	if ip.IsUnspecified() {
		return nil, 0, fmt.Errorf("gossip advertise address %q: set an address other members can dial", advertise)
	}
	return ip, port, nil
}

// FinalAdvertiseAddr returns the resolved advertise address; memberlist's own
// settings are ignored.
func (t *gossipTransport) FinalAdvertiseAddr(string, int) (net.IP, int, error) {
	return t.ip, t.port, nil
}

// PacketCh returns the packets received.
func (t *gossipTransport) PacketCh() <-chan *memberlist.Packet { return t.packetCh }

// StreamCh returns the streams accepted.
func (t *gossipTransport) StreamCh() <-chan net.Conn { return t.streamCh }

// WriteTo queues a packet for addr and returns at once. A packet that does
// not fit the peer's queue, or cannot be delivered, is dropped: memberlist
// treats packets as unreliable.
func (t *gossipTransport) WriteTo(b []byte, addr string) (time.Time, error) {
	if len(b) > maxGossipPacket {
		return time.Time{}, fmt.Errorf("gossip packet of %d bytes exceeds %d", len(b), maxGossipPacket)
	}
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return time.Time{}, errors.New("gossip transport shut down")
	}
	q, ok := t.peers[addr]
	if !ok {
		q = make(chan []byte, gossipQueueLen)
		t.peers[addr] = q
		t.wg.Go(func() { t.send(addr, q) })
	}
	t.mu.Unlock()
	select {
	case q <- bytes.Clone(b):
	default:
		t.log.Debug("gossip queue full; dropping a packet", "peer", addr)
	}
	return time.Now(), nil
}

// send delivers the packets queued for addr over one connection, dialing it
// when needed. It ends once the queue stays empty for gossipIdle.
func (t *gossipTransport) send(addr string, q chan []byte) {
	var conn net.Conn
	closeConn := func() {
		if conn != nil {
			_ = conn.Close()
			conn = nil
		}
	}
	defer closeConn()
	idle := time.NewTimer(gossipIdle)
	defer idle.Stop()
	for {
		select {
		case <-t.ctx.Done():
			return
		case <-idle.C:
			t.mu.Lock()
			if len(q) == 0 {
				delete(t.peers, addr)
				t.mu.Unlock()
				return
			}
			t.mu.Unlock()
			idle.Reset(gossipIdle)
		case b := <-q:
			idle.Reset(gossipIdle)
			frame := make([]byte, 0, 5+len(b))
			if conn == nil {
				c, err := t.stream.Dial(raft.ServerAddress(addr), t.dialTimeout)
				if err != nil {
					t.log.Debug("gossip dial failed; dropping queued packets", "peer", addr, "err", err)
					drain(q)
					continue
				}
				conn = c
				t.recordOwner(addr, c)
				frame = append(frame, gossipPackets)
			}
			frame = binary.BigEndian.AppendUint32(frame, uint32(len(b))) //nolint:gosec // len(b) <= maxGossipPacket
			frame = append(frame, b...)
			_ = conn.SetWriteDeadline(time.Now().Add(t.dialTimeout))
			if _, err := conn.Write(frame); err != nil {
				t.log.Debug("gossip write failed", "peer", addr, "err", err)
				closeConn()
			}
		}
	}
}

func drain(q chan []byte) {
	for {
		select {
		case <-q:
		default:
			return
		}
	}
}

// DialTimeout opens a stream to addr.
func (t *gossipTransport) DialTimeout(addr string, timeout time.Duration) (net.Conn, error) {
	c, err := t.stream.Dial(raft.ServerAddress(addr), timeout)
	if err != nil {
		return nil, err
	}
	t.recordOwner(addr, c)
	_ = c.SetWriteDeadline(time.Now().Add(timeout))
	if _, err := c.Write([]byte{gossipStream}); err != nil {
		_ = c.Close()
		return nil, err
	}
	_ = c.SetWriteDeadline(time.Time{})
	return c, nil
}

func (t *gossipTransport) accept() {
	for {
		c, err := t.stream.Accept()
		if err != nil {
			if t.ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			t.log.Warn("gossip accept failed", "err", err)
			select {
			case <-t.ctx.Done():
				return
			case <-time.After(50 * time.Millisecond):
			}
			continue
		}
		t.wg.Go(func() { t.serve(c) })
	}
}

// serve authenticates an accepted connection, then hands it to memberlist as
// a stream or reads packets from it.
func (t *gossipTransport) serve(c net.Conn) {
	_ = c.SetDeadline(time.Now().Add(gossipHandshakeTimeout))
	var kind [1]byte
	if _, err := io.ReadFull(c, kind[:]); err != nil { // runs the handshake
		t.log.Debug("gossip connection refused", "remote", c.RemoteAddr(), "err", err)
		_ = c.Close()
		return
	}
	_ = c.SetDeadline(time.Time{})
	peer := peerID(c)
	switch kind[0] {
	case gossipStream:
		t.markSeen(peer)
		select {
		case t.streamCh <- c:
		case <-t.ctx.Done():
			_ = c.Close()
		}
	case gossipPackets:
		t.readPackets(c, peer)
	case gossipReplica:
		h := t.replica.Load()
		if h == nil {
			_ = c.Close()
			return
		}
		t.markSeen(peer)
		(*h)(c, peer)
	case gossipVerify:
		_ = c.Close()
	default:
		_ = c.Close()
	}
}

func (t *gossipTransport) readPackets(c net.Conn, peer string) {
	defer func() { _ = c.Close() }()
	var hdr [4]byte
	for {
		// The sender closes an idle connection after gossipIdle.
		_ = c.SetReadDeadline(time.Now().Add(2 * gossipIdle))
		if _, err := io.ReadFull(c, hdr[:]); err != nil {
			return
		}
		n := binary.BigEndian.Uint32(hdr[:])
		if n == 0 || n > maxGossipPacket {
			t.log.Debug("gossip packet size out of range; closing", "peer", peer, "size", n)
			return
		}
		buf := make([]byte, n)
		if _, err := io.ReadFull(c, buf); err != nil {
			return
		}
		now := time.Now()
		t.markSeen(peer)
		select {
		case t.packetCh <- &memberlist.Packet{Buf: buf, From: c.RemoteAddr(), Timestamp: now}:
		case <-t.ctx.Done():
			return
		}
	}
}

// peerID is the hub node ID of an authenticated connection's peer.
func peerID(c net.Conn) string {
	tc, ok := c.(*trackedConn)
	if !ok {
		return ""
	}
	p := tc.peer.Load()
	if p == nil {
		return ""
	}
	id, _ := pki.HubNodeID(p)
	return id
}

func (t *gossipTransport) markSeen(id string) {
	if id == "" {
		return
	}
	t.seenMu.Lock()
	t.seen[id] = time.Now()
	t.seenMu.Unlock()
}

// lastSeen is when a packet or stream last arrived from hub id; zero if none
// did.
func (t *gossipTransport) lastSeen(id string) time.Time {
	t.seenMu.Lock()
	defer t.seenMu.Unlock()
	return t.seen[id]
}

// recordOwner records the hub that answered a dial to addr.
func (t *gossipTransport) recordOwner(addr string, c net.Conn) {
	if id := peerID(c); id != "" {
		t.ownMu.Lock()
		t.owners[addr] = id
		t.ownMu.Unlock()
	}
}

// ownerOf is the hub node ID that last answered at addr, if any did.
func (t *gossipTransport) ownerOf(addr string) (string, bool) {
	t.ownMu.Lock()
	defer t.ownMu.Unlock()
	id, ok := t.owners[addr]
	return id, ok
}

// verifyOwner dials addr, unless a dial already answered, and returns the
// hub node ID of the certificate the member there presented.
func (t *gossipTransport) verifyOwner(addr string) (string, error) {
	if id, ok := t.ownerOf(addr); ok {
		return id, nil
	}
	c, err := t.stream.Dial(raft.ServerAddress(addr), t.dialTimeout)
	if err != nil {
		return "", err
	}
	defer func() { _ = c.Close() }()
	t.recordOwner(addr, c)
	_ = c.SetWriteDeadline(time.Now().Add(t.dialTimeout))
	_, _ = c.Write([]byte{gossipVerify})
	id, ok := t.ownerOf(addr)
	if !ok {
		return "", fmt.Errorf("gossip peer at %s presented no hub certificate", addr)
	}
	return id, nil
}

// verifyLater verifies addr's owner in the background, at most once per
// verifyRetry, so a caller that must not block (memberlist's alive handler
// runs under its node lock) finds it known next time.
func (t *gossipTransport) verifyLater(addr string) {
	t.ownMu.Lock()
	if t.verifying[addr] || time.Since(t.verifyTried[addr]) < verifyRetry {
		t.ownMu.Unlock()
		return
	}
	t.verifying[addr], t.verifyTried[addr] = true, time.Now()
	t.ownMu.Unlock()
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return
	}
	t.wg.Go(func() {
		if _, err := t.verifyOwner(addr); err != nil {
			t.log.Debug("verify the owner of a gossip address", "addr", addr, "err", err)
		}
		t.ownMu.Lock()
		delete(t.verifying, addr)
		t.ownMu.Unlock()
	})
}

// closeRevoked closes the open connections of peers whose certificate
// revoked reports as revoked; see tlsStream.closeRevoked.
func (t *gossipTransport) closeRevoked(revoked func(*x509.Certificate) bool) int {
	return t.stream.closeRevoked(revoked)
}

// Shutdown stops the listener, the senders and every open connection.
func (t *gossipTransport) Shutdown() error {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return nil
	}
	t.closed = true
	t.mu.Unlock()
	t.cancel()
	err := t.stream.Close()
	t.stream.closeAll()
	t.wg.Wait()
	return err
}

// closeAll closes every open connection of s, authenticated or not.
func (s *tlsStream) closeAll() {
	s.mu.Lock()
	conns := make([]*trackedConn, 0, len(s.conns))
	for c := range s.conns {
		conns = append(conns, c)
	}
	s.mu.Unlock()
	for _, c := range conns {
		_ = c.Close()
	}
}
