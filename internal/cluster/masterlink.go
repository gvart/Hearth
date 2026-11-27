// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"
)

// The masters of an AP cluster call each other over HTTP carried on the
// gossip port's mutual TLS (gossipMaster connections): a call on one master
// that needs a device's agent stream is forwarded to the master holding it.
// Both ends present hub node certificates of the cluster CA; a request is
// served only when the member that sent it is a live master and, as the
// roles on the gossip are a member's own word, proved on the connection that
// it holds the hub CA key (#382).

// MasterLink serves and makes the HTTP calls between masters.
type MasterLink struct {
	self    string
	dial    func(ctx context.Context, id string) (net.Conn, error)
	members func() []MemberInfo
	key     MasterKey
	log     *slog.Logger

	ln        *connListener
	handler   http.Handler
	transport *http.Transport
}

// NewMasterLink returns the link of master self: dial opens a gossipMaster
// connection to a member, members lists the members, and h serves what
// other masters ask; key proves this member holds the hub CA key on each
// connection it opens, and checks the proofs of those it accepts.
func NewMasterLink(self string, dial func(ctx context.Context, id string) (net.Conn, error),
	members func() []MemberInfo, key MasterKey, h http.Handler, log *slog.Logger,
) *MasterLink {
	l := &MasterLink{self: self, dial: dial, members: members, key: key, handler: h, log: log, ln: newConnListener()}
	l.transport = &http.Transport{
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			c, err := l.dial(ctx, host)
			if err != nil {
				return nil, err
			}
			if err := l.hello(c); err != nil {
				_ = c.Close()
				return nil, fmt.Errorf("master link to %s: %w", host, err)
			}
			return c, nil
		},
		MaxIdleConnsPerHost: 4,
		IdleConnTimeout:     replicaIdle,
	}
	return l
}

// masterPeerKey carries the id of the master a request came from.
type masterPeerKey struct{}

// MasterPeer returns the id of the master that sent the request ctx belongs
// to, on a MasterLink's handler.
func MasterPeer(ctx context.Context) string {
	id, _ := ctx.Value(masterPeerKey{}).(string)
	return id
}

// Accept hands c, a gossipMaster connection from peer, to the server. Pass
// it as MembershipConfig.Master.
func (l *MasterLink) Accept(c net.Conn, peer string) {
	if !l.isMaster(peer) {
		l.log.Warn("refused a master call from a member that is not a live master", "peer", peer)
		_ = c.Close()
		return
	}
	if !l.proved(c) {
		l.log.Warn("refused a master call from a member that did not prove it holds the hub CA key", "peer", peer)
		_ = c.Close()
		return
	}
	// The dialer checks this member too: a call meant for a master must
	// not reach a member that only says it is one.
	if err := l.sendHello(c, proofMasterLinkServer); err != nil {
		_ = c.Close()
		return
	}
	if !l.ln.put(peerConn{Conn: c, peer: peer}) {
		_ = c.Close()
	}
}

// What each end of a master link connection signs, with the connection's
// binding: different labels, so one end cannot hand back the other's proof.
const (
	proofMasterLink       = "hearth ap master link: the dialer holds the hub CA key\x00"
	proofMasterLinkServer = "hearth ap master link: the server holds the hub CA key\x00"
)

// masterHello is the first frame of a master link connection, before HTTP.
type masterHello struct {
	Proof []byte `json:"proof,omitempty"`
}

// hello sends, on c, the proof that this member holds the hub CA key, and
// checks the member that answers proves it too.
func (l *MasterLink) hello(c net.Conn) error {
	if err := l.sendHello(c, proofMasterLink); err != nil {
		return err
	}
	if !l.readHello(c, proofMasterLinkServer) {
		return errors.New("the member did not prove it holds the hub CA key: it is no master")
	}
	return nil
}

// sendHello sends, on c, this member's proof for side.
func (l *MasterLink) sendHello(c net.Conn, side string) error {
	var h masterHello
	if b := bindingOf(c); len(b) > 0 {
		h.Proof, _ = l.key.Prove(append([]byte(side), b...))
	}
	if h.Proof == nil {
		return errors.New("this member does not hold the hub CA key")
	}
	_ = c.SetWriteDeadline(time.Now().Add(replicaDialTimeout))
	defer func() { _ = c.SetWriteDeadline(time.Time{}) }()
	return writeFrame(c, h)
}

// proved reads the dialer's hello from c and checks its proof.
func (l *MasterLink) proved(c net.Conn) bool { return l.readHello(c, proofMasterLink) }

// readHello reads a hello from c and checks its proof for side.
func (l *MasterLink) readHello(c net.Conn, side string) bool {
	_ = c.SetReadDeadline(time.Now().Add(replicaDialTimeout))
	defer func() { _ = c.SetReadDeadline(time.Time{}) }()
	var h masterHello
	if err := readFrame(c, &h); err != nil {
		return false
	}
	b := bindingOf(c)
	return len(b) > 0 && len(h.Proof) > 0 && l.key.Verify(append([]byte(side), b...), h.Proof)
}

// isMaster reports whether id is a live master other than this one.
func (l *MasterLink) isMaster(id string) bool {
	if id == "" || id == l.self {
		return false
	}
	for _, m := range l.members() {
		if m.ID == id && m.Roles.Has(RoleMaster) && (m.State == MemberAlive || m.State == MemberSuspect) {
			return true
		}
	}
	return false
}

// Run serves the calls of other masters until ctx ends.
func (l *MasterLink) Run(ctx context.Context) error {
	srv := &http.Server{
		Handler:           l.handler,
		ReadHeaderTimeout: 10 * time.Second,
		BaseContext:       func(net.Listener) context.Context { return ctx },
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			if pc, ok := c.(peerConn); ok {
				return context.WithValue(ctx, masterPeerKey{}, pc.peer)
			}
			return ctx
		},
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(l.ln) }()
	select {
	case err := <-errc:
		return fmt.Errorf("master link: %w", err)
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)
	_ = srv.Close()
	l.transport.CloseIdleConnections()
	if err := <-errc; err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("master link: %w", err)
	}
	return nil
}

// Client returns an HTTP client whose requests to http://<master id>/...
// go to that master over the link.
func (l *MasterLink) Client() *http.Client { return &http.Client{Transport: l.transport} }

// Transport is the round tripper of Client.
func (l *MasterLink) Transport() http.RoundTripper { return l.transport }

// peerConn is an accepted connection and the master it came from.
type peerConn struct {
	net.Conn
	peer string
}

// connListener is a net.Listener of connections handed to it with put.
type connListener struct {
	ch     chan net.Conn
	once   sync.Once
	closed chan struct{}
}

func newConnListener() *connListener {
	return &connListener{ch: make(chan net.Conn), closed: make(chan struct{})}
}

// put hands c to Accept; false once the listener is closed.
func (l *connListener) put(c net.Conn) bool {
	select {
	case l.ch <- c:
		return true
	case <-l.closed:
		return false
	}
}

func (l *connListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ch:
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *connListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *connListener) Addr() net.Addr { return masterAddr{} }

type masterAddr struct{}

func (masterAddr) Network() string { return "hearth-master" }
func (masterAddr) String() string  { return "hearth-master" }
