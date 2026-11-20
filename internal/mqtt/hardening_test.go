// SPDX-License-Identifier: AGPL-3.0-only

package mqtt

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	mochi "github.com/mochi-mqtt/server/v2"
	"golang.org/x/crypto/bcrypt"

	"github.com/gvart/hearth/internal/pki"
	"github.com/gvart/hearth/internal/store"
)

// rawTLS opens a TLS connection to the broker without sending CONNECT.
func (tb *testBroker) rawTLS(t *testing.T) *client {
	t.Helper()
	conn, err := tls.Dial("tcp", tb.addr, &tls.Config{RootCAs: tb.pool, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	return &client{t: t, conn: conn, r: bufio.NewReader(conn)}
}

// closedSoon reports whether the broker ends c's connection, possibly after
// a DISCONNECT, without sending it anything else.
func (c *client) closedSoon() (bool, []byte) {
	var got []byte
	for range 3 {
		typ, _, err := c.read()
		if err != nil {
			return true, got
		}
		got = append(got, typ)
		if typ != 0xe0 {
			return false, got
		}
	}
	return false, got
}

func TestOversizedPacketRefused(t *testing.T) {
	tb := startBroker(t, clientsYAML)
	// An unauthenticated CONNECT declaring 192 MiB: refused before any read.
	raw := tb.rawTLS(t)
	if _, err := raw.conn.Write([]byte{0x10, 0x80, 0x80, 0x80, 0x60}); err != nil {
		t.Fatal(err)
	}
	if closed, got := raw.closedSoon(); !closed {
		t.Fatalf("oversized CONNECT answered with %#x", got)
	}
	// After login too: a PUBLISH one byte over the limit ends the client.
	c, rc, err := tb.dial(t, connectOpts{user: "sensors", pass: testPassword})
	if err != nil || rc != accepted {
		t.Fatalf("connect: rc %d, %v", rc, err)
	}
	if _, err := c.conn.Write(packet(0x30, make([]byte, MaxPacketSize))); err != nil {
		t.Fatal(err)
	}
	if closed, got := c.closedSoon(); !closed {
		t.Fatalf("oversized PUBLISH answered with %#x", got)
	}
}

func TestLoginFloodIsBounded(t *testing.T) {
	release, entered := make(chan struct{}), make(chan struct{}, 1)
	tb := startBroker(t, clientsYAML, func(b *Broker) {
		b.auth.gateWait = 300 * time.Millisecond
		b.auth.compare = func(hash, pw []byte) error {
			if string(pw) == "flood" {
				select {
				case entered <- struct{}{}:
				default:
				}
				<-release
				return bcrypt.ErrMismatchedHashAndPassword
			}
			return bcrypt.CompareHashAndPassword(hash, pw)
		}
	})
	var wg sync.WaitGroup
	for i := range maxLoginWaiters + 8 {
		wg.Go(func() {
			_, _, _ = tb.dial(t, connectOpts{id: fmt.Sprintf("flood-%d", i), user: "sensors", pass: "flood"})
		})
	}
	<-entered // one flood login holds the check, the rest queue or are refused
	start := time.Now()
	_, rc, err := tb.dial(t, connectOpts{id: "legit", user: "sensors", pass: testPassword})
	if err != nil {
		t.Fatalf("legit client during the flood: %v", err)
	}
	if took := time.Since(start); took > 3*time.Second || rc == accepted {
		t.Fatalf("during the flood: rc %d after %v; want refused as busy within the login wait", rc, took)
	}
	if !strings.Contains(tb.logs.String(), "server busy") {
		t.Error("busy refusals are not logged")
	}
	close(release)
	wg.Wait()
	if _, rc, err := tb.dial(t, connectOpts{id: "legit", user: "sensors", pass: testPassword}); err != nil || rc != accepted {
		t.Fatalf("after the flood: rc %d, %v", rc, err)
	}
}

func TestPacketsNotLogged(t *testing.T) {
	tb := startBroker(t, clientsYAML)
	c, rc, err := tb.dial(t, connectOpts{user: "sensors", pass: testPassword})
	if err != nil || rc != accepted {
		t.Fatalf("connect: rc %d, %v", rc, err)
	}
	// A second CONNECT is a protocol error, which mochi logs with the packet.
	const secret = "second-connect-secret"
	body := append(mqttString("MQTT"), 4, 0xc2, 0, 60)
	body = append(body, mqttString("again")...)
	body = append(body, mqttString("sensors")...)
	body = append(body, mqttString(secret)...)
	if _, err := c.conn.Write(packet(0x10, body)); err != nil {
		t.Fatal(err)
	}
	_, _ = c.closedSoon()
	deadline := time.Now().Add(3 * time.Second)
	for !strings.Contains(tb.logs.String(), "error processing packet") {
		if time.Now().After(deadline) {
			t.Fatal("the second CONNECT was not logged at all")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if strings.Contains(tb.logs.String(), secret) {
		t.Fatalf("the password reached the log:\n%s", tb.logs.String())
	}
}

func TestTopicAliasRefused(t *testing.T) {
	tb := startBroker(t, clientsYAML)
	c := tb.rawTLS(t)
	// MQTT 5 CONNECT: protocol level 5, no properties.
	body := append(mqttString("MQTT"), 5, 0xc2, 0, 60, 0)
	body = append(body, mqttString("alias")...)
	body = append(body, mqttString("sensors")...)
	body = append(body, mqttString(testPassword)...)
	if _, err := c.conn.Write(packet(0x10, body)); err != nil {
		t.Fatal(err)
	}
	typ, resp, err := c.read()
	if err != nil || typ != 0x20 || len(resp) < 2 || resp[1] != 0 {
		t.Fatalf("CONNACK: %#x %v %v", typ, resp, err)
	}
	// PUBLISH QoS 0 with topic alias 1 (property 0x23).
	pub := append(mqttString("sensors/a"), 3, 0x23, 0, 1)
	if _, err := c.conn.Write(packet(0x30, append(pub, "x"...))); err != nil {
		t.Fatal(err)
	}
	typ, resp, err = c.read()
	if err != nil || typ != 0xe0 || len(resp) < 1 || resp[0] != 0x94 {
		t.Fatalf("want DISCONNECT 0x94 (topic alias invalid), got %#x %v %v", typ, resp, err)
	}
}

func TestRevokedDeviceIsDisconnected(t *testing.T) {
	tb := startBroker(t, clientsYAML)
	cert := deviceCert(t, tb.ca, "dev1", time.Now())
	serial := pki.SerialString(cert.Leaf)
	tb.certs.set(serial, nil)
	c, rc, err := tb.dial(t, connectOpts{cert: &cert})
	if err != nil || rc != accepted {
		t.Fatalf("connect: rc %d, %v", rc, err)
	}
	// A store error keeps the client: the store may be briefly unavailable.
	tb.certs.set(serial, fmt.Errorf("database is locked"))
	time.Sleep(200 * time.Millisecond)
	if rc := c.subscribe("hearth/dev1/#"); rc != 0 {
		t.Fatalf("dropped on a store error: %#x", rc)
	}
	tb.certs.set(serial, fmt.Errorf("check: %w", store.ErrCertRevoked))
	if closed, got := c.closedSoon(); !closed {
		t.Fatalf("revoked device still connected, got %#x", got)
	}
	if !strings.Contains(tb.logs.String(), `msg="mqtt client disconnected" reason="certificate revoked"`) {
		t.Errorf("revocation not logged:\n%s", tb.logs.String())
	}
}

func TestRetiredCADeviceIsDisconnected(t *testing.T) {
	tb := startBroker(t, clientsYAML)
	cert := deviceCert(t, tb.ca, "dev1", time.Now())
	tb.certs.set(pki.SerialString(cert.Leaf), nil)
	c, rc, err := tb.dial(t, connectOpts{cert: &cert})
	if err != nil || rc != accepted {
		t.Fatalf("connect: rc %d, %v", rc, err)
	}
	next, err := tb.ca.GenerateNext(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range []func() error{func() error { return tb.ca.TrustNext(next) }, tb.ca.Cutover, tb.ca.Finish} {
		if err := step(); err != nil {
			t.Fatal(err)
		}
	}
	if closed, got := c.closedSoon(); !closed {
		t.Fatalf("device of a retired CA still connected, got %#x", got)
	}
}

func TestClientIDClaim(t *testing.T) {
	h := newAuthHook(mochi.New(&mochi.Options{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}),
		Config{Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if !h.claim("id", "alice") || !h.claim("id", "alice") {
		t.Fatal("an identity could not claim its own ID twice")
	}
	if h.claim("id", "bob") {
		t.Fatal("another identity claimed a held ID")
	}
	cl := &mochi.Client{ID: "id"}
	cl.Properties.Username = []byte("alice")
	h.OnDisconnect(cl, nil, true)
	if h.claim("id", "bob") {
		t.Fatal("claimed while alice still has a connection")
	}
	h.OnDisconnect(cl, nil, true)
	if !h.claim("id", "bob") {
		t.Fatal("ID not released after alice's connections ended")
	}

	// Racing identities: only one ever wins a fresh ID.
	var wins [2]atomic.Int32
	var wg sync.WaitGroup
	for i := range 64 {
		wg.Go(func() {
			if h.claim("race", []string{"alice", "bob"}[i%2]) {
				wins[i%2].Add(1)
			}
		})
	}
	wg.Wait()
	if wins[0].Load() > 0 && wins[1].Load() > 0 {
		t.Fatalf("both identities claimed the ID: %d, %d", wins[0].Load(), wins[1].Load())
	}
}

func TestLoadClientsRefusesWritableFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mqtt.yaml")
	if err := os.WriteFile(path, []byte("users: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadClients(path); err != nil {
		t.Fatalf("0600: %v", err)
	}
	for _, mode := range []os.FileMode{0o620, 0o602, 0o640} {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		_, err := LoadClients(path)
		if writable := mode&0o022 != 0; writable != (err != nil) {
			t.Errorf("mode %o: err %v", mode, err)
		}
	}
}
