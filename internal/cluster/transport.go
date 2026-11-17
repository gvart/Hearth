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
	"time"

	"github.com/hashicorp/raft"

	"github.com/gvart/hearth/internal/pki"
)

// tlsStream is a raft.StreamLayer over TCP with mutual TLS: both ends present
// a hub node certificate from the hub CA that is not revoked.
type tlsStream struct {
	net.Listener
	advertise advertiseAddr
	client    *tls.Config

	// conns are the open connections, both accepted and dialed, so the
	// ones of a revoked peer can be closed (see closeRevoked).
	mu    sync.Mutex
	conns map[*trackedConn]struct{}
}

var _ raft.StreamLayer = (*tlsStream)(nil)

// advertiseAddr is the address other hubs dial, kept as given (a host name
// stays a host name).
type advertiseAddr string

func (a advertiseAddr) Network() string { return "tcp" }
func (a advertiseAddr) String() string  { return string(a) }

// peerCheck refuses a peer's hub node certificate, for example a revoked
// one. nil accepts every hub certificate from the CA.
type peerCheck func(*x509.Certificate) error

func listenTLS(ctx context.Context, listen, advertise string, cert tls.Certificate, ca *pki.CA, check peerCheck) (*tlsStream, error) {
	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", listen)
	if err != nil {
		return nil, fmt.Errorf("raft listen on %s: %w", listen, err)
	}
	if advertise == "" {
		advertise = ln.Addr().String()
	}
	if _, _, err := net.SplitHostPort(advertise); err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("advertise address %q: %w", advertise, err)
	}
	return &tlsStream{
		Listener:  tls.NewListener(ln, serverTLS(cert, ca, check)),
		advertise: advertiseAddr(advertise),
		client:    clientTLS(cert, ca, check),
		conns:     map[*trackedConn]struct{}{},
	}, nil
}

// Addr is the advertised address: raft hands it to peers.
func (s *tlsStream) Addr() net.Addr { return s.advertise }

// Accept waits for a peer's connection. The TLS handshake, and with it the
// peer's authentication, runs on its first read.
func (s *tlsStream) Accept() (net.Conn, error) {
	c, err := s.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return s.trackConn(c)
}

func (s *tlsStream) trackConn(c net.Conn) (net.Conn, error) {
	tc, ok := c.(*tls.Conn)
	if !ok {
		_ = c.Close()
		return nil, errors.New("raft transport: not a TLS connection")
	}
	return s.track(tc), nil
}

// Dial opens a mutually authenticated connection to a peer.
func (s *tlsStream) Dial(addr raft.ServerAddress, timeout time.Duration) (net.Conn, error) {
	d := &tls.Dialer{NetDialer: &net.Dialer{Timeout: timeout}, Config: s.client}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	c, err := d.DialContext(ctx, "tcp", string(addr))
	if err != nil {
		return nil, err
	}
	return s.trackConn(c)
}

// trackedConn is an open connection of the stream; closing it forgets it.
type trackedConn struct {
	*tls.Conn
	s *tlsStream
}

func (s *tlsStream) track(c *tls.Conn) *trackedConn {
	tc := &trackedConn{Conn: c, s: s}
	s.mu.Lock()
	s.conns[tc] = struct{}{}
	s.mu.Unlock()
	return tc
}

func (c *trackedConn) Close() error {
	c.s.mu.Lock()
	delete(c.s.conns, c)
	c.s.mu.Unlock()
	return c.Conn.Close()
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
		// ConnectionState waits for a handshake in progress; one that has
		// not started yet is checked by the handshake itself.
		cs := c.ConnectionState()
		if cs.HandshakeComplete && len(cs.PeerCertificates) > 0 && revoked(cs.PeerCertificates[0]) {
			_ = c.Close()
			n++
		}
	}
	return n
}

func caPool(ca *pki.CA) *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert())
	return pool
}

// serverTLS accepts only clients with a hub node certificate from ca that
// check accepts.
func serverTLS(cert tls.Certificate, ca *pki.CA, check peerCheck) *tls.Config {
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caPool(ca),
		VerifyConnection: func(cs tls.ConnectionState) error {
			return requireHubCert(cs.PeerCertificates, check)
		},
	}
}

// clientTLS dials peers by address, often an IP, so there is no host name to
// check: the peer is authenticated by its CA-issued hub node certificate.
func clientTLS(cert tls.Certificate, ca *pki.CA, check peerCheck) *tls.Config {
	pool := caPool(ca)
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		// Standard verification is replaced, not skipped: VerifyConnection
		// verifies the chain against the hub CA and requires a hub identity.
		InsecureSkipVerify: true, //nolint:gosec // see VerifyConnection
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("peer presented no certificate")
			}
			inter := x509.NewCertPool()
			for _, c := range cs.PeerCertificates[1:] {
				inter.AddCert(c)
			}
			if _, err := cs.PeerCertificates[0].Verify(x509.VerifyOptions{
				Roots:         pool,
				Intermediates: inter,
				KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			}); err != nil {
				return fmt.Errorf("verify peer certificate: %w", err)
			}
			return requireHubCert(cs.PeerCertificates, check)
		},
	}
}

func requireHubCert(chain []*x509.Certificate, check peerCheck) error {
	if len(chain) == 0 {
		return errors.New("peer presented no certificate")
	}
	id, err := pki.HubNodeID(chain[0])
	if err != nil {
		return fmt.Errorf("peer is not a hub: %w", err)
	}
	if check != nil {
		if err := check(chain[0]); err != nil {
			return fmt.Errorf("peer hub %s refused: %w", id, err)
		}
	}
	return nil
}
