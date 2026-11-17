// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/hashicorp/raft"

	"github.com/gvart/hearth/internal/pki"
)

// tlsStream is a raft.StreamLayer over TCP with mutual TLS: both ends present
// a hub node certificate from the hub CA.
type tlsStream struct {
	net.Listener
	advertise advertiseAddr
	client    *tls.Config
}

var _ raft.StreamLayer = (*tlsStream)(nil)

// advertiseAddr is the address other hubs dial, kept as given (a host name
// stays a host name).
type advertiseAddr string

func (a advertiseAddr) Network() string { return "tcp" }
func (a advertiseAddr) String() string  { return string(a) }

func listenTLS(ctx context.Context, listen, advertise string, cert tls.Certificate, ca *pki.CA) (*tlsStream, error) {
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
		Listener:  tls.NewListener(ln, serverTLS(cert, ca)),
		advertise: advertiseAddr(advertise),
		client:    clientTLS(cert, ca),
	}, nil
}

// Addr is the advertised address: raft hands it to peers.
func (s *tlsStream) Addr() net.Addr { return s.advertise }

// Dial opens a mutually authenticated connection to a peer.
func (s *tlsStream) Dial(addr raft.ServerAddress, timeout time.Duration) (net.Conn, error) {
	d := &tls.Dialer{NetDialer: &net.Dialer{Timeout: timeout}, Config: s.client}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return d.DialContext(ctx, "tcp", string(addr))
}

func caPool(ca *pki.CA) *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert())
	return pool
}

// serverTLS accepts only clients with a hub node certificate from ca.
func serverTLS(cert tls.Certificate, ca *pki.CA) *tls.Config {
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caPool(ca),
		VerifyConnection: func(cs tls.ConnectionState) error {
			return requireHubCert(cs.PeerCertificates)
		},
	}
}

// clientTLS dials peers by address, often an IP, so there is no host name to
// check: the peer is authenticated by its CA-issued hub node certificate.
func clientTLS(cert tls.Certificate, ca *pki.CA) *tls.Config {
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
			return requireHubCert(cs.PeerCertificates)
		},
	}
}

func requireHubCert(chain []*x509.Certificate) error {
	if len(chain) == 0 {
		return errors.New("peer presented no certificate")
	}
	if _, err := pki.HubNodeID(chain[0]); err != nil {
		return fmt.Errorf("peer is not a hub: %w", err)
	}
	return nil
}
