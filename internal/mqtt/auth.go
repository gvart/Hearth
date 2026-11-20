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
	// ctx is the broker's run context, set before it serves.
	ctx context.Context
	// gate runs one bcrypt comparison at a time, so a flood of logins
	// cannot take every core from the hub.
	gate chan struct{}
}

func newAuthHook(srv *mochi.Server, cfg Config) *authHook {
	h := &authHook{
		srv: srv, ca: cfg.CA, certs: cfg.Certs, log: cfg.Log, ctx: context.Background(),
		users: map[string]*User{}, devices: map[string]*Device{}, gate: make(chan struct{}, 1),
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
	return b == mochi.OnConnectAuthenticate || b == mochi.OnACLCheck
}

// OnConnectAuthenticate admits a client with a valid device certificate or
// username and password, whose will topic (if any) it may write, and whose
// client ID is not another identity's session.
func (h *authHook) OnConnectAuthenticate(cl *mochi.Client, pk packets.Packet) bool {
	identity, rules, reason := h.authenticate(cl, pk)
	switch {
	case reason != "":
	case pk.Connect.WillFlag && !allowed(rules, pk.Connect.WillTopic, true):
		reason = "will topic not allowed"
	default:
		if prev, ok := h.srv.Clients.Get(cl.ID); ok && string(prev.Properties.Username) != identity {
			reason = "client ID belongs to another client's session"
		}
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
	case h.gate <- struct{}{}:
	case <-h.ctx.Done():
		return name, nil, "broker stopping"
	}
	err := bcrypt.CompareHashAndPassword(hash, pk.Connect.Password)
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

// OnACLCheck allows a read (a subscription filter, or a message delivered to
// the client) or a write (a publish) only if the client's rules grant it.
func (h *authHook) OnACLCheck(cl *mochi.Client, topic string, write bool) bool {
	ok := allowed(h.rulesOf(string(cl.Properties.Username)), topic, write)
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
