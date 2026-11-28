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
	"github.com/mochi-mqtt/server/v2/packets"

	"github.com/gvart/hearth/internal/pki"
)

// The one binary is also the agent, so mochi's package initialisation runs on
// every device. mochi/packets builds TPacketData, its own test fixtures
// (about 370 KB of heap), in a non-test file; nothing outside its tests reads
// it. Dropping it lets the agent's first GC reclaim that heap (issue #145).
func init() { packets.TPacketData = nil }

// connectTimeout bounds how long a new connection may take to finish its TLS
// handshake and send CONNECT. After that the client's keepalive applies.
const connectTimeout = 10 * time.Second

// MaxPacketSize is the largest MQTT packet the broker reads, CONNECT
// included. mochi allocates a packet's declared size before it reads it, so
// without a bound one unauthenticated client could make the hub allocate
// 256 MB. Sensor readings and commands are far smaller.
const MaxPacketSize = 256 << 10

// DefaultRecheck is how often the broker re-checks the certificates of the
// devices connected to it.
const DefaultRecheck = 30 * time.Second

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
	// Recheck is how often connected devices' certificates are checked
	// again, so a revoked device or one of a retired hub CA is dropped
	// (default DefaultRecheck).
	Recheck time.Duration
	// Bridge, if set, connects the broker to a remote broker, with the
	// rules of the clients file's bridge section.
	Bridge *BridgeConfig
	// Protocol, if set, receives the Device Protocol messages of the
	// devices connected to the broker, and lets the hub publish their
	// commands (PublishCommand).
	Protocol ProtocolSink
	Log      *slog.Logger
}

// Broker is the embedded MQTT broker.
type Broker struct {
	srv     *mochi.Server
	auth    *authHook
	ln      net.Listener
	conns   *connListener
	serve   *serveListener
	recheck time.Duration
	bridge  *bridge
}

// New returns a broker serving on cfg.Listener once Run is called. The caller
// must call Run, which closes the listener when it returns.
func New(cfg Config) (*Broker, error) {
	caps := mochi.NewDefaultServerCapabilities()
	caps.MaximumPacketSize = MaxPacketSize
	// mochi checks a publish's topic against the ACL before it resolves a
	// topic alias, so aliases are off: a publish carrying one is refused.
	caps.TopicAliasMaximum = 0
	cfg.Log = slog.New(redactPackets{cfg.Log.Handler()})
	// The bridge publishes and subscribes through the inline client, and the
	// hub publishes Device Protocol commands through it.
	inline := cfg.Bridge != nil || cfg.Protocol != nil
	srv := mochi.New(&mochi.Options{Logger: cfg.Log, Capabilities: caps, InlineClient: inline})
	auth := newAuthHook(srv, cfg)
	if err := srv.AddHook(auth, nil); err != nil {
		return nil, fmt.Errorf("mqtt: add auth hook: %w", err)
	}
	conns := &connListener{Listener: cfg.Listener, conns: map[*trackedConn]struct{}{}}
	ln := tls.NewListener(conns, TLSConfig(cfg.CA, cfg.ServerCert))
	serve := &serveListener{ln: ln, served: make(chan struct{})}
	if err := srv.AddListener(serve); err != nil {
		return nil, fmt.Errorf("mqtt: add listener: %w", err)
	}
	recheck := cfg.Recheck
	if recheck <= 0 {
		recheck = DefaultRecheck
	}
	b := &Broker{srv: srv, auth: auth, ln: ln, conns: conns, serve: serve, recheck: recheck}
	if cfg.Bridge != nil {
		br, err := newBridge(srv, cfg.Bridge, cfg.Clients, cfg.Log)
		if err != nil {
			return nil, err
		}
		b.bridge = br
	}
	return b, nil
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
	var wg sync.WaitGroup
	if b.bridge != nil {
		wg.Go(func() { b.bridge.run(ctx) })
	}
	t := time.NewTicker(b.recheck)
	defer t.Stop()
	for ctx.Err() == nil {
		select {
		case <-t.C:
			b.auth.recheck(ctx)
		case <-ctx.Done():
		}
	}
	wg.Wait()
	// mochi's Close waits for its clients on a WaitGroup that each new
	// connection adds to, so a connection accepted during Close races with
	// it. Stop accepting, close every connection and wait for mochi to be
	// done with each before Close.
	b.serve.stop()
	b.conns.stop()
	b.serve.handlers.Wait()
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
// connections it accepted, so stop can end them all: the broker waits for
// every connection before it stops.
type connListener struct {
	net.Listener
	mu    sync.Mutex
	conns map[*trackedConn]struct{}
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
	_ = c.SetDeadline(time.Now().Add(connectTimeout))
	l.mu.Lock()
	l.conns[tc] = struct{}{}
	l.mu.Unlock()
	return tc, nil
}

// stop closes every open connection. A deadline would not end a connected
// client's: mochi moves it before each read.
func (l *connListener) stop() {
	l.mu.Lock()
	defer l.mu.Unlock()
	for c := range l.conns {
		_ = c.Conn.Close()
	}
}

// serveListener hands mochi the connections accepted on ln, as mochi's
// listeners.Net does, but tracks the goroutine serving each one so the broker
// can wait for them all to end before it closes the mochi server.
type serveListener struct {
	ln       net.Listener
	log      *slog.Logger
	served   chan struct{} // closed when Serve returns
	handlers sync.WaitGroup
}

func (l *serveListener) ID() string       { return "mqtts" }
func (l *serveListener) Address() string  { return l.ln.Addr().String() }
func (l *serveListener) Protocol() string { return l.ln.Addr().Network() }

func (l *serveListener) Init(log *slog.Logger) error {
	l.log = log
	return nil
}

func (l *serveListener) Serve(establish listeners.EstablishFn) {
	defer close(l.served)
	for {
		c, err := l.ln.Accept()
		if err != nil {
			return
		}
		l.handlers.Go(func() {
			if err := establish(l.ID(), c); err != nil {
				l.log.Warn("", "error", err)
			}
		})
	}
}

// Close is called by mochi's Server.Close, after stop.
func (l *serveListener) Close(closeClients listeners.CloseFn) {
	closeClients(l.ID())
	_ = l.ln.Close()
}

// stop closes ln and waits for Serve to return, so no connection is handed
// to mochi after it.
func (l *serveListener) stop() {
	_ = l.ln.Close()
	<-l.served
}

// redactPackets drops mochi's "pk" and "packet" log attributes: a logged
// packet can be a CONNECT with its password, or a message's payload.
type redactPackets struct{ slog.Handler }

func redacted(a slog.Attr) bool { return a.Key == "pk" || a.Key == "packet" }

func (h redactPackets) Handle(ctx context.Context, r slog.Record) error {
	out := slog.NewRecord(r.Time, r.Level, r.Message, r.PC)
	r.Attrs(func(a slog.Attr) bool {
		if !redacted(a) {
			out.AddAttrs(a)
		}
		return true
	})
	return h.Handler.Handle(ctx, out)
}

func (h redactPackets) WithAttrs(as []slog.Attr) slog.Handler {
	kept := make([]slog.Attr, 0, len(as))
	for _, a := range as {
		if !redacted(a) {
			kept = append(kept, a)
		}
	}
	return redactPackets{h.Handler.WithAttrs(kept)}
}

func (h redactPackets) WithGroup(name string) slog.Handler {
	return redactPackets{h.Handler.WithGroup(name)}
}
