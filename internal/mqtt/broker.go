// SPDX-License-Identifier: AGPL-3.0-only

package mqtt

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	mochi "github.com/mochi-mqtt/server/v2"
	"github.com/mochi-mqtt/server/v2/listeners"

	"github.com/gvart/hearth/internal/pki"
)

// connectTimeout bounds how long a new connection may take to finish its TLS
// handshake and send CONNECT. After that the client's keepalive applies.
const connectTimeout = 10 * time.Second

// CertChecker tells whether the hub issued a client certificate to a device
// and has not revoked it (store.Certs).
type CertChecker interface {
	Check(ctx context.Context, serial, deviceID string) error
}

// Config configures a Broker.
type Config struct {
	// Listener is a bound TCP listener. The broker serves TLS on it and
	// closes it when it stops.
	Listener net.Listener
	// CA is the hub CA: device certificates it issued authenticate devices.
	CA *pki.CA
	// ServerCert returns the hub's current TLS server certificate.
	ServerCert func() *tls.Certificate
	// Clients is who may connect, and to which topics.
	Clients *Clients
	// Certs checks a device certificate is known and not revoked.
	Certs CertChecker
	Log   *slog.Logger
}

// Broker is the embedded MQTT broker.
type Broker struct {
	srv   *mochi.Server
	auth  *authHook
	ln    net.Listener
	conns *connListener
}

// New returns a broker serving on cfg.Listener once Run is called. The caller
// must call Run, which closes the listener when it returns.
func New(cfg Config) (*Broker, error) {
	srv := mochi.New(&mochi.Options{Logger: cfg.Log})
	auth := newAuthHook(srv, cfg)
	if err := srv.AddHook(auth, nil); err != nil {
		return nil, fmt.Errorf("mqtt: add auth hook: %w", err)
	}
	conns := &connListener{Listener: cfg.Listener, conns: map[*trackedConn]struct{}{}}
	ln := tls.NewListener(conns, TLSConfig(cfg.CA, cfg.ServerCert))
	if err := srv.AddListener(listeners.NewNet("mqtts", ln)); err != nil {
		return nil, fmt.Errorf("mqtt: add listener: %w", err)
	}
	return &Broker{srv: srv, auth: auth, ln: ln, conns: conns}, nil
}

// Addr is the address the broker listens on.
func (b *Broker) Addr() net.Addr { return b.ln.Addr() }

// Run serves MQTT until ctx is done, then disconnects every client and
// returns once their connections have ended.
func (b *Broker) Run(ctx context.Context) error {
	b.auth.ctx = ctx
	if err := b.srv.Serve(); err != nil {
		_ = b.ln.Close()
		return fmt.Errorf("mqtt: serve: %w", err)
	}
	<-ctx.Done()
	// Connected clients are disconnected by Close; this ends the rest.
	b.conns.stop()
	if err := b.srv.Close(); err != nil {
		return fmt.Errorf("mqtt: close: %w", err)
	}
	return nil
}

// TLSConfig is the broker's TLS configuration: the hub's server certificate,
// and an optional client certificate, which must come from the hub CA. TLS
// 1.2 is allowed, as small MQTT devices such as an ESP8266 lack 1.3.
func TLSConfig(ca *pki.CA, serverCert func() *tls.Certificate) *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			return &tls.Config{
				MinVersion:   tls.VersionTLS12,
				Certificates: []tls.Certificate{*serverCert()},
				ClientAuth:   tls.VerifyClientCertIfGiven,
				ClientCAs:    ca.Pool(),
				// A resumed session skips chain verification: one from
				// before a hub CA rotation finished must not outlive it.
				VerifyConnection: func(cs tls.ConnectionState) error {
					if len(cs.PeerCertificates) > 0 && ca.IssuerOf(cs.PeerCertificates[0]) == nil {
						return errors.New("client certificate is not from a trusted hub CA")
					}
					return nil
				},
			}, nil
		},
	}
}

// connListener gives each connection connectTimeout to finish its TLS
// handshake and CONNECT, so a silent client cannot hold a connection open;
// the broker sets the keepalive deadline after CONNECT. It tracks the
// connections it accepted, so stop can end those that never got that far:
// the broker waits for every connection before it stops.
type connListener struct {
	net.Listener
	mu      sync.Mutex
	conns   map[*trackedConn]struct{}
	stopped bool
}

type trackedConn struct {
	net.Conn
	l *connListener
}

func (c *trackedConn) Close() error {
	c.l.mu.Lock()
	delete(c.l.conns, c)
	c.l.mu.Unlock()
	return c.Conn.Close()
}

func (l *connListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	tc := &trackedConn{Conn: c, l: l}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.stopped {
		_ = c.SetDeadline(time.Now())
	} else {
		_ = c.SetDeadline(time.Now().Add(connectTimeout))
		l.conns[tc] = struct{}{}
	}
	return tc, nil
}

// stop ends every open connection's reads and writes now.
func (l *connListener) stop() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.stopped = true
	for c := range l.conns {
		_ = c.SetDeadline(time.Now())
	}
}
