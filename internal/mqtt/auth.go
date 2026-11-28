// SPDX-License-Identifier: AGPL-3.0-only

package mqtt

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"time"

	mochi "github.com/mochi-mqtt/server/v2"
	"github.com/mochi-mqtt/server/v2/packets"
	"golang.org/x/crypto/bcrypt"

	"github.com/gvart/hearth/internal/pki"
	"github.com/gvart/hearth/internal/store"
)

// devicePrefix marks a device's identity, kept as the client's username once
// it has connected. User names may not contain ':', so none can pass as one.
const devicePrefix = "device:"

// Bounds of the queue for the password check (authHook.gate).
const (
	maxLoginWaiters = 32
	loginWait       = 2 * time.Second
)

// dummyHash is checked against for an unknown user, so a refusal takes as
// long whether or not the user exists. It is made on first use, not when
// the binary starts: agents never need it.
var dummyHash = sync.OnceValue(func() []byte {
	h, _ := bcrypt.GenerateFromPassword([]byte("not a password"), bcrypt.DefaultCost)
	return h
})

// authHook authenticates clients at CONNECT and checks every subscription,
// publish and delivery against their rules.
type authHook struct {
	mochi.HookBase
	srv     *mochi.Server
	ca      *pki.CA
	certs   CertChecker
	users   map[string]*User
	devices map[string]*Device
	log     *slog.Logger
	// protocol receives the Device Protocol's messages; nil drops them
	// after they are checked.
	protocol ProtocolSink
	// ctx is the broker's run context, set before it serves.
	ctx context.Context
	// gate runs one bcrypt comparison at a time, so a flood of logins
	// cannot take every core from the hub. At most cap(waiters) logins wait
	// for it, each for at most gateWait: the rest are refused as busy, so a
	// flood cannot queue up ahead of a legitimate client for ever.
	gate     chan struct{}
	waiters  chan struct{}
	gateWait time.Duration
	// compare is bcrypt.CompareHashAndPassword; tests slow it down.
	compare func(hash, password []byte) error

	// claims maps a client ID to the identity whose connections hold it,
	// so two identities racing for one ID cannot both get it.
	mu     sync.Mutex
	claims map[string]*claim
}

type claim struct {
	identity string
	conns    int
}

func newAuthHook(srv *mochi.Server, cfg Config) *authHook {
	h := &authHook{
		srv: srv, ca: cfg.CA, certs: cfg.Certs, log: cfg.Log, ctx: context.Background(),
		users: map[string]*User{}, devices: map[string]*Device{},
		gate: make(chan struct{}, 1), waiters: make(chan struct{}, maxLoginWaiters), gateWait: loginWait,
		compare: bcrypt.CompareHashAndPassword, claims: map[string]*claim{}, protocol: cfg.Protocol,
	}
	if cfg.Clients != nil {
		for i := range cfg.Clients.Users {
			h.users[cfg.Clients.Users[i].Name] = &cfg.Clients.Users[i]
		}
		for i := range cfg.Clients.Devices {
			h.devices[cfg.Clients.Devices[i].ID] = &cfg.Clients.Devices[i]
		}
	}
	return h
}

func (h *authHook) ID() string { return "hearth-auth" }

func (h *authHook) Provides(b byte) bool {
	return b == mochi.OnConnectAuthenticate || b == mochi.OnACLCheck || b == mochi.OnDisconnect ||
		b == mochi.OnPublish
}

// OnConnectAuthenticate admits a client with a valid device certificate or
// username and password, whose will topic (if any) it may write, and whose
// client ID is not another identity's session.
func (h *authHook) OnConnectAuthenticate(cl *mochi.Client, pk packets.Packet) bool {
	identity, rules, reason := h.authenticate(cl, pk)
	switch {
	case reason != "":
	case pk.Connect.WillFlag && !permits(identity, rules, pk.Connect.WillTopic, true):
		reason = "will topic not allowed"
	case pk.Connect.WillFlag && !protocolWill(pk.Connect.WillTopic, pk.Connect.WillPayload):
		reason = "a Device Protocol will must be an offline availability message"
	case !h.claim(cl.ID, identity):
		reason = "client ID belongs to another client's session"
	}
	if reason != "" {
		// Never the password: only who tried, from where, and why not.
		h.log.Warn("mqtt client refused", "reason", reason, "identity", identity, "client_id", cl.ID, "remote", cl.Net.Remote)
		return false
	}
	cl.Properties.Username = []byte(identity)
	h.log.Debug("mqtt client authenticated", "identity", identity, "client_id", cl.ID, "remote", cl.Net.Remote)
	return true
}

// authenticate returns the client's identity and rules, or why it is
// refused. A client certificate, if presented, decides: a username must then
// be empty or the certificate's device ID, and any password is ignored.
func (h *authHook) authenticate(cl *mochi.Client, pk packets.Packet) (string, []Rule, string) {
	conn, ok := cl.Net.Conn.(*tls.Conn)
	if !ok {
		return "", nil, "not a TLS connection"
	}
	if chains := conn.ConnectionState().VerifiedChains; len(chains) > 0 {
		return h.authenticateDevice(chains[0][0], pk.Connect.Username)
	}
	name := string(pk.Connect.Username)
	if !pk.Connect.UsernameFlag || name == "" || !pk.Connect.PasswordFlag {
		return name, nil, "no client certificate or username and password"
	}
	u := h.users[name]
	var hash []byte
	if u != nil {
		hash = []byte(u.PasswordHash)
	} else {
		hash = dummyHash()
	}
	select {
	case h.waiters <- struct{}{}:
	default:
		return name, nil, "server busy: too many logins waiting"
	}
	wait := time.NewTimer(h.gateWait)
	defer wait.Stop()
	select {
	case h.gate <- struct{}{}:
		<-h.waiters
	case <-wait.C:
		<-h.waiters
		return name, nil, "server busy: login timed out waiting"
	case <-h.ctx.Done():
		<-h.waiters
		return name, nil, "broker stopping"
	}
	err := h.compare(hash, pk.Connect.Password)
	<-h.gate
	if u == nil || err != nil {
		return name, nil, "wrong username or password"
	}
	return name, u.Allow, ""
}

func (h *authHook) authenticateDevice(leaf *x509.Certificate, username []byte) (string, []Rule, string) {
	if h.ca.IssuerOf(leaf) == nil {
		return "", nil, "client certificate of a hub CA no longer trusted"
	}
	id, err := pki.DeviceID(leaf)
	if err != nil {
		return "", nil, "client certificate has no device identity"
	}
	identity := devicePrefix + id
	if len(username) > 0 && !bytes.Equal(username, []byte(id)) {
		return identity, nil, "username does not match the client certificate"
	}
	ctx, cancel := context.WithTimeout(h.ctx, 5*time.Second)
	defer cancel()
	switch err := h.certs.Check(ctx, pki.SerialString(leaf), id); {
	case errors.Is(err, store.ErrCertRevoked):
		return identity, nil, "certificate revoked"
	case errors.Is(err, store.ErrNotFound):
		return identity, nil, "certificate unknown"
	case err != nil:
		h.log.Error("mqtt: check client certificate", "device_id", id, "err", err)
		return identity, nil, "cannot check certificate"
	}
	d := h.devices[id]
	if d == nil {
		return identity, nil, "device not in the MQTT clients file"
	}
	return identity, d.Allow, ""
}

// claim gives clientID to identity, unless another identity holds it: a
// connection that is still connecting, connected, or a stored session.
func (h *authHook) claim(clientID, identity string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if c := h.claims[clientID]; c != nil && c.identity != identity {
		return false
	}
	if prev, ok := h.srv.Clients.Get(clientID); ok && string(prev.Properties.Username) != identity {
		return false
	}
	c := h.claims[clientID]
	if c == nil {
		c = &claim{identity: identity}
		h.claims[clientID] = c
	}
	c.conns++
	return true
}

// OnDisconnect releases the client's claim on its ID. A stored session
// keeps the ID for its identity (see claim). A connection that fails to send
// its CONNACK never gets here and leaves its claim, which only keeps the ID
// for the identity that already proved it holds it.
func (h *authHook) OnDisconnect(cl *mochi.Client, _ error, _ bool) {
	h.deviceGone(cl)
	h.mu.Lock()
	defer h.mu.Unlock()
	if c := h.claims[cl.ID]; c != nil && c.identity == string(cl.Properties.Username) {
		if c.conns--; c.conns <= 0 {
			delete(h.claims, cl.ID)
		}
	}
}

// recheck disconnects every connected device whose certificate is no longer
// good: revoked, or from a hub CA a rotation retired. It runs periodically,
// as revocations are written by another process (`hearth device revoke`).
func (h *authHook) recheck(ctx context.Context) {
	for _, cl := range h.srv.Clients.GetAll() {
		id, ok := strings.CutPrefix(string(cl.Properties.Username), devicePrefix)
		if !ok || cl.Closed() {
			continue
		}
		conn, ok := cl.Net.Conn.(*tls.Conn)
		if !ok {
			continue
		}
		chains := conn.ConnectionState().VerifiedChains
		reason := ""
		switch {
		case len(chains) == 0:
			reason = "no client certificate"
		case h.ca.IssuerOf(chains[0][0]) == nil:
			reason = "client certificate of a hub CA no longer trusted"
		default:
			cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			err := h.certs.Check(cctx, pki.SerialString(chains[0][0]), id)
			cancel()
			switch {
			case errors.Is(err, store.ErrCertRevoked):
				reason = "certificate revoked"
			case errors.Is(err, store.ErrNotFound):
				reason = "certificate unknown"
			case err != nil:
				// Keep the client: the store may be briefly unavailable.
				h.log.Error("mqtt: recheck client certificate", "device_id", id, "err", err)
			}
		}
		if reason != "" {
			h.log.Warn("mqtt client disconnected", "reason", reason, "identity", devicePrefix+id,
				"client_id", cl.ID, "remote", cl.Net.Remote)
			_ = h.srv.DisconnectClient(cl, packets.ErrNotAuthorized)
		}
	}
}

// OnACLCheck allows a read (a subscription filter, or a message delivered to
// the client) or a write (a publish) only if the client's rules grant it.
func (h *authHook) OnACLCheck(cl *mochi.Client, topic string, write bool) bool {
	identity := string(cl.Properties.Username)
	ok := permits(identity, h.rulesOf(identity), topic, write)
	if !ok {
		h.log.Debug("mqtt topic denied", "identity", string(cl.Properties.Username), "topic", topic, "write", write)
	}
	return ok
}

// rulesOf returns the rules of an authenticated identity.
func (h *authHook) rulesOf(identity string) []Rule {
	if id, ok := strings.CutPrefix(identity, devicePrefix); ok {
		if d := h.devices[id]; d != nil {
			return d.Allow
		}
		return nil
	}
	if u := h.users[identity]; u != nil {
		return u.Allow
	}
	return nil
}
