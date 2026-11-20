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
// served only when the member that sent it is a live master.

// MasterLink serves and makes the HTTP calls between masters.
type MasterLink struct {
	self    string
	dial    func(ctx context.Context, id string) (net.Conn, error)
	members func() []MemberInfo
	log     *slog.Logger

	ln        *connListener
	handler   http.Handler
	transport *http.Transport
}

// NewMasterLink returns the link of master self: dial opens a gossipMaster
// connection to a member, members lists the members, and h serves what
// other masters ask.
func NewMasterLink(self string, dial func(ctx context.Context, id string) (net.Conn, error),
	members func() []MemberInfo, h http.Handler, log *slog.Logger,
) *MasterLink {
	l := &MasterLink{self: self, dial: dial, members: members, handler: h, log: log, ln: newConnListener()}
	l.transport = &http.Transport{
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			return l.dial(ctx, host)
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
	if !l.ln.put(peerConn{Conn: c, peer: peer}) {
		_ = c.Close()
	}
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
