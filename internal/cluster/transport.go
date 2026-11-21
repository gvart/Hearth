// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gvart/hearth/internal/pki"
)

// tlsStream is a stream layer over TCP with mutual TLS: both ends present a
// hub node certificate from the hub CA that is not revoked. The gossip and
// the replication share it (gossiptransport.go).
type tlsStream struct {
	net.Listener
	advertise advertiseAddr
	client    *tls.Config

	// conns are the open connections, both accepted and dialed, so the
	// ones of a revoked peer can be closed (see closeRevoked).
	mu    sync.Mutex
	conns map[*trackedConn]struct{}
}

// advertiseAddr is the address other hubs dial, kept as given (a host name
// stays a host name).
type advertiseAddr string

func (a advertiseAddr) Network() string { return "tcp" }
func (a advertiseAddr) String() string  { return string(a) }

// peerCheck refuses a peer's hub node certificate, for example a revoked
// one. nil accepts every hub certificate from the CA.
type peerCheck func(*x509.Certificate) error

// Addr is the advertised address, the one peers dial.
func (s *tlsStream) Addr() net.Addr { return s.advertise }

// Accept waits for a peer's connection. The TLS handshake, and with it the
// peer's authentication, runs on its first read.
func (s *tlsStream) Accept() (net.Conn, error) {
	c, err := s.Listener.Accept()
	if err != nil {
		return nil, err
	}
	tc, err := s.trackConn(c, "")
	if err != nil {
		return nil, err
	}
	return tc, nil
}

func (s *tlsStream) trackConn(c net.Conn, dialed string) (*trackedConn, error) {
	tc, ok := c.(*tls.Conn)
	if !ok {
		_ = c.Close()
		return nil, errors.New("cluster transport: not a TLS connection")
	}
	return s.track(tc, dialed), nil
}

// Dial opens a mutually authenticated connection to a peer.
func (s *tlsStream) Dial(addr string, timeout time.Duration) (net.Conn, error) {
	d := &tls.Dialer{NetDialer: &net.Dialer{Timeout: timeout}, Config: s.client}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	c, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	tc, err := s.trackConn(c, addr)
	if err != nil {
		return nil, err
	}
	tc.recordPeer() // DialContext completed the handshake
	return tc, nil
}

// trackedConn is an open connection of the stream; closing it forgets it.
type trackedConn struct {
	*tls.Conn
	s *tlsStream
	// peer is the peer's certificate once the handshake is done. It is
	// recorded by the connection's own reader (or the dialer), never read
	// with ConnectionState from elsewhere: that waits for a handshake in
	// progress, which a silent peer can stall indefinitely.
	peer atomic.Pointer[x509.Certificate]
	// dialed is the address this hub dialed; empty for an accepted connection.
	dialed string
}

func (s *tlsStream) track(c *tls.Conn, dialed string) *trackedConn {
	tc := &trackedConn{Conn: c, s: s, dialed: dialed}
	s.mu.Lock()
	s.conns[tc] = struct{}{}
	s.mu.Unlock()
	return tc
}

// Read records the peer certificate after the handshake, which the first
// read of an accepted connection performs.
func (c *trackedConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 && c.peer.Load() == nil {
		c.recordPeer()
	}
	return n, err
}

func (c *trackedConn) recordPeer() {
	if cs := c.ConnectionState(); len(cs.PeerCertificates) > 0 {
		c.peer.Store(cs.PeerCertificates[0])
	}
}

func (c *trackedConn) Close() error {
	c.s.mu.Lock()
	delete(c.s.conns, c)
	c.s.mu.Unlock()
	return c.Conn.Close()
}

// dialedPeers returns the certificates the peer at addr presented on the
// open connections this hub dialed to it.
func (s *tlsStream) dialedPeers(addr string) []*x509.Certificate {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*x509.Certificate
	for c := range s.conns {
		if p := c.peer.Load(); p != nil && c.dialed == addr {
			out = append(out, p)
		}
	}
	return out
}

// closeRevoked closes every open connection whose peer certificate revoked
// reports as revoked, and returns how many it closed. A handshake only
// checks the certificate once, so this is how a revocation reaches
// connections that were already open.
func (s *tlsStream) closeRevoked(revoked func(*x509.Certificate) bool) int {
	s.mu.Lock()
	conns := make([]*trackedConn, 0, len(s.conns))
	for c := range s.conns {
		conns = append(conns, c)
	}
	s.mu.Unlock()
	n := 0
	for _, c := range conns {
		// A connection without a recorded peer has not finished its
		// handshake, which checks the certificate itself.
		if p := c.peer.Load(); p != nil && revoked(p) {
			_ = c.Close()
			n++
		}
	}
	return n
}

// serverTLSFunc accepts only clients with a hub node certificate from ca that
// check accepts, and presents the certificate cert returns at each handshake. The CAs it trusts are ca's at each handshake, so a hub CA
// rotation reaches new connections without a restart.
func serverTLSFunc(cert func() *tls.Certificate, ca *pki.CA, check peerCheck) *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			return &tls.Config{
				MinVersion:   tls.VersionTLS13,
				Certificates: []tls.Certificate{*cert()},
				ClientAuth:   tls.RequireAndVerifyClientCert,
				ClientCAs:    ca.Pool(),
				VerifyConnection: func(cs tls.ConnectionState) error {
					return requireHubCert(ca, cs.PeerCertificates, check)
				},
			}, nil
		},
	}
}

// clientTLSFunc dials peers by address, often an IP, so there is no host name
// to check: the peer is authenticated by its CA-issued hub node certificate.
// It presents the certificate cert returns at each handshake, and trusts ca's
// CAs at each handshake.
func clientTLSFunc(cert func() *tls.Certificate, ca *pki.CA, check peerCheck) *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return cert(), nil
		},
		// Standard verification is replaced, not skipped: VerifyConnection
		// verifies the chain against the hub CA and requires a hub identity.
		InsecureSkipVerify: true, //nolint:gosec // see VerifyConnection
		VerifyConnection: func(cs tls.ConnectionState) error {
			if err := verifyChain(ca, cs, ""); err != nil {
				return err
			}
			return requireHubCert(ca, cs.PeerCertificates, check)
		},
	}
}

// verifyChain verifies a server's certificate chain against the CAs ca
// trusts now and, when not empty, its host name dnsName.
func verifyChain(ca *pki.CA, cs tls.ConnectionState, dnsName string) error {
	if len(cs.PeerCertificates) == 0 {
		return errors.New("peer presented no certificate")
	}
	inter := x509.NewCertPool()
	for _, c := range cs.PeerCertificates[1:] {
		inter.AddCert(c)
	}
	if _, err := cs.PeerCertificates[0].Verify(x509.VerifyOptions{
		Roots:         ca.Pool(),
		Intermediates: inter,
		DNSName:       dnsName,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		return fmt.Errorf("verify peer certificate: %w", err)
	}
	return nil
}

// requireHubCert requires a hub node certificate issued by a CA that ca
// trusts now, and that check accepts. The issuer is checked here as well
// because a resumed TLS session skips chain verification but not
// VerifyConnection: a session from before a hub CA rotation finished must
// not outlive it.
func requireHubCert(ca *pki.CA, chain []*x509.Certificate, check peerCheck) error {
	if len(chain) == 0 {
		return errors.New("peer presented no certificate")
	}
	id, err := pki.HubNodeID(chain[0])
	if err != nil {
		return fmt.Errorf("peer is not a hub: %w", err)
	}
	if ca.IssuerOf(chain[0]) == nil {
		return fmt.Errorf("peer hub %s: its certificate is not from a trusted hub CA", id)
	}
	if check != nil {
		if err := check(chain[0]); err != nil {
			return fmt.Errorf("peer hub %s refused: %w", id, err)
		}
	}
	return nil
}
