// SPDX-License-Identifier: AGPL-3.0-only

package mqtt

import (
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"strconv"
	"time"

	"github.com/mochi-mqtt/server/v2/packets"

	"github.com/gvart/hearth/internal/pki"
)

// remoteYAML is the remote broker's clients file: the hub's bridge logs in
// as "bridge", and "watcher" reads and writes everything.
const remoteYAML = `
users:
  - name: bridge
    password_hash: HASH
    allow:
      - topic: home/#
        access: readwrite
  - name: watcher
    password_hash: HASH
    allow:
      - topic: "#"
        access: readwrite
`

// localYAML is the hub's clients file; its bridge may only use sensors/ok/#.
const localYAML = `
users:
  - name: local
    password_hash: HASH
    allow:
      - topic: "#"
        access: readwrite
bridge:
  allow:
    - topic: sensors/ok/#
      access: readwrite
`

// bridgeTo returns a bridge config for the remote broker rb.
func bridgeTo(t *testing.T, rb *testBroker, addr string, protocol byte, password string) *BridgeConfig {
	t.Helper()
	cfg, err := ParseBridge([]byte("address: " + addr + "\nclient_id: hearth-test\nusername: bridge\n" +
		"topics:\n  - prefix: sensors/\n    remote_prefix: home/sensors/\n    direction: both\n"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Protocol = protocol
	cfg.Password = password
	cfg.TLS = &tls.Config{RootCAs: rb.pool, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12}
	return cfg
}

// fastRetry makes the bridge reconnect within milliseconds.
func fastRetry(b *Broker) {
	b.bridge.minBackoff, b.bridge.maxBackoff = 20*time.Millisecond, 100*time.Millisecond
}

// waitLog waits until the broker's logs contain s n times.
func waitLog(t *testing.T, tb *testBroker, s string, n int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for strings.Count(tb.logs.String(), s) < n {
		if time.Now().After(deadline) {
			t.Fatalf("logs do not contain %q %d times:\n%s", s, n, tb.logs.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// none checks no PUBLISH arrives within a short while.
func (c *client) none() {
	c.t.Helper()
	_ = c.conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	typ, body, err := c.read()
	var ne net.Error
	if !errors.As(err, &ne) || !ne.Timeout() {
		c.t.Fatalf("want nothing, got %#x %q %v", typ, body, err)
	}
	_ = c.conn.SetReadDeadline(time.Now().Add(10 * time.Second))
}

func connected(t *testing.T, tb *testBroker, user, id string) *client {
	t.Helper()
	c, rc, err := tb.dial(t, connectOpts{id: id, user: user, pass: testPassword})
	if err != nil || rc != accepted {
		t.Fatalf("connect %s: rc %d, %v", user, rc, err)
	}
	return c
}

// TestBridgeBothWays forwards both ways and checks the loop guard: each
// message reaches each side once, with MQTT 5 No Local and with 3.1.1 echo
// suppression.
func TestBridgeBothWays(t *testing.T) {
	for _, v := range []byte{5, 4} {
		t.Run(map[byte]string{5: "mqtt5", 4: "mqtt311"}[v], func(t *testing.T) {
			rb := startBroker(t, remoteYAML)
			lb := startBrokerWith(t, localYAML, bridgeTo(t, rb, rb.addr, v, testPassword), fastRetry)
			waitLog(t, lb, "mqtt bridge connected", 1)

			rsub := connected(t, rb, "watcher", "rsub")
			if rc := rsub.subscribe("home/#"); rc != 0 {
				t.Fatalf("remote subscribe: %#x", rc)
			}
			lsub := connected(t, lb, "local", "lsub")
			if rc := lsub.subscribe("sensors/#"); rc != 0 {
				t.Fatalf("local subscribe: %#x", rc)
			}

			// Out: hub -> remote.
			connected(t, lb, "local", "lpub").publish("sensors/ok/kitchen", "21.5")
			if topic, payload := rsub.next(); topic != "home/sensors/ok/kitchen" || payload != "21.5" {
				t.Fatalf("remote got %s %s", topic, payload)
			}
			if topic, payload := lsub.next(); topic != "sensors/ok/kitchen" || payload != "21.5" {
				t.Fatalf("local got %s %s", topic, payload)
			}

			// In: remote -> hub.
			connected(t, rb, "watcher", "rpub").publish("home/sensors/ok/garage", "7")
			if topic, payload := lsub.next(); topic != "sensors/ok/garage" || payload != "7" {
				t.Fatalf("local got %s %s", topic, payload)
			}
			if topic, payload := rsub.next(); topic != "home/sensors/ok/garage" || payload != "7" {
				t.Fatalf("remote got %s %s", topic, payload)
			}

			// No echo either way.
			lsub.none()
			rsub.none()
		})
	}
}

// TestBridgeClientCertificate logs in to the remote with a client
// certificate instead of a password.
func TestBridgeClientCertificate(t *testing.T) {
	rb := startBroker(t, remoteYAML+`devices:
  - id: hub1
    allow:
      - topic: home/#
        access: readwrite
`)
	cert := deviceCert(t, rb.ca, "hub1", time.Now())
	rb.certs.set(pki.SerialString(cert.Leaf), nil)
	cfg := bridgeTo(t, rb, rb.addr, 5, "")
	cfg.Username = ""
	cfg.TLS.Certificates = []tls.Certificate{cert}
	lb := startBrokerWith(t, localYAML, cfg, fastRetry)
	waitLog(t, lb, "mqtt bridge connected", 1)
	waitLog(t, rb, "identity=device:hub1", 1)

	rsub := connected(t, rb, "watcher", "rsub")
	rsub.subscribe("home/#")
	connected(t, lb, "local", "lpub").publish("sensors/ok/cert", "1")
	if topic, _ := rsub.next(); topic != "home/sensors/ok/cert" {
		t.Fatalf("remote got %s", topic)
	}
}

// TestBridgeLocalACL checks bridged messages are bound by the bridge rules
// of the hub's clients file, in both directions.
func TestBridgeLocalACL(t *testing.T) {
	rb := startBroker(t, remoteYAML)
	lb := startBrokerWith(t, localYAML, bridgeTo(t, rb, rb.addr, 5, testPassword), fastRetry)
	waitLog(t, lb, "mqtt bridge connected", 1)
	rsub := connected(t, rb, "watcher", "rsub")
	rsub.subscribe("home/#")
	lsub := connected(t, lb, "local", "lsub")
	lsub.subscribe("sensors/#")

	lpub := connected(t, lb, "local", "lpub")
	lpub.publish("sensors/secret/door", "open")
	lpub.publish("sensors/ok/door", "shut")
	for _, want := range []string{"sensors/secret/door", "sensors/ok/door"} {
		if topic, _ := lsub.next(); topic != want {
			t.Fatalf("local got %s, want %s", topic, want)
		}
	}
	// The denied topic is not sent out: the first thing out is the allowed one.
	if topic, _ := rsub.next(); topic != "home/sensors/ok/door" {
		t.Fatalf("remote got %s", topic)
	}

	rpub := connected(t, rb, "watcher", "rpub")
	rpub.publish("home/sensors/secret/window", "open")
	rpub.publish("home/sensors/ok/window", "shut")
	for _, want := range []string{"home/sensors/secret/window", "home/sensors/ok/window"} {
		if topic, _ := rsub.next(); topic != want {
			t.Fatalf("remote got %s, want %s", topic, want)
		}
	}
	// The denied topic is not brought in.
	if topic, _ := lsub.next(); topic != "sensors/ok/window" {
		t.Fatalf("local got %s", topic)
	}
	waitLog(t, lb, "mqtt bridge topic denied", 2)
}

// TestBridgeNoRules refuses a bridge the clients file grants nothing.
func TestBridgeNoRules(t *testing.T) {
	rb := startBroker(t, remoteYAML)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	c, err := ParseClients([]byte("users: []\n"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = New(Config{Listener: ln, CA: rb.ca, Clients: c, Bridge: bridgeTo(t, rb, rb.addr, 5, ""), Log: slog.New(slog.DiscardHandler)})
	if err == nil || !strings.Contains(err.Error(), "no bridge rules") {
		t.Fatalf("New: %v", err)
	}
}

// TestBridgeBadCredentials keeps retrying a remote that refuses the
// password, and never logs it.
func TestBridgeBadCredentials(t *testing.T) {
	for _, v := range []byte{5, 4} {
		rb := startBroker(t, remoteYAML)
		lb := startBrokerWith(t, localYAML, bridgeTo(t, rb, rb.addr, v, "wrong-password"), fastRetry)
		waitLog(t, lb, "remote refused the connection", 3)
		if strings.Contains(lb.logs.String(), "mqtt bridge connected") {
			t.Fatal("bridge connected with a wrong password")
		}
	}
}

// TestBridgeUntrustedRemote refuses a remote whose certificate is not from
// the configured CA.
func TestBridgeUntrustedRemote(t *testing.T) {
	rb := startBroker(t, remoteYAML)
	other := startBroker(t, remoteYAML)
	cfg := bridgeTo(t, rb, rb.addr, 5, testPassword)
	cfg.TLS.RootCAs = other.pool
	lb := startBrokerWith(t, localYAML, cfg, fastRetry)
	waitLog(t, lb, "certificate signed by unknown authority", 2)
}

// TestBridgeReconnect cuts the bridge's connection from the remote's side
// and checks it reconnects and forwards again.
func TestBridgeReconnect(t *testing.T) {
	rb := startBroker(t, remoteYAML)
	p := startProxy(t, rb.addr)
	lb := startBrokerWith(t, localYAML, bridgeTo(t, rb, p.addr(), 5, testPassword), fastRetry)
	waitLog(t, lb, "mqtt bridge connected", 1)
	rsub := connected(t, rb, "watcher", "rsub")
	rsub.subscribe("home/#")
	lpub := connected(t, lb, "local", "lpub")

	p.cut()
	waitLog(t, lb, "mqtt bridge disconnected", 1)
	waitLog(t, lb, "mqtt bridge connected", 2)
	lpub.publish("sensors/ok/after", "1")
	if topic, _ := rsub.next(); topic != "home/sensors/ok/after" {
		t.Fatalf("remote got %s", topic)
	}
	lsub := connected(t, lb, "local", "lsub")
	lsub.subscribe("sensors/#")
	connected(t, rb, "watcher", "rpub").publish("home/sensors/ok/back", "3")
	if topic, payload := lsub.next(); topic != "sensors/ok/back" || payload != "3" {
		t.Fatalf("local got %s %s", topic, payload)
	}
}

// proxy forwards TCP connections to a broker and can cut them all.
type proxy struct {
	ln    net.Listener
	mu    sync.Mutex
	conns []net.Conn
}

func startProxy(t *testing.T, target string) *proxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &proxy{ln: ln}
	t.Cleanup(func() { _ = ln.Close(); p.cut() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			u, err := net.Dial("tcp", target)
			if err != nil {
				_ = c.Close()
				continue
			}
			p.mu.Lock()
			p.conns = append(p.conns, c, u)
			p.mu.Unlock()
			go func() { _, _ = io.Copy(u, c); _ = u.Close() }()
			go func() { _, _ = io.Copy(c, u); _ = c.Close() }()
		}
	}()
	return p
}

func (p *proxy) addr() string { return p.ln.Addr().String() }

func (p *proxy) cut() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, c := range p.conns {
		_ = c.Close()
	}
	p.conns = nil
}

// TestBridgeDropsWildcardTopics drops a remote PUBLISH whose topic is a
// filter: mochi does not check an inline client's topic, and a retained
// message on sensors/# could never be cleared.
func TestBridgeDropsWildcardTopics(t *testing.T) {
	rb := startBroker(t, remoteYAML)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := ln.Addr().String()
	_ = ln.Close() // the bridge keeps retrying; receive is called directly
	var b *Broker
	lb := startBrokerWith(t, localYAML, bridgeTo(t, rb, dead, 5, testPassword), fastRetry, func(x *Broker) { b = x })
	lsub := connected(t, lb, "local", "lsub")
	lsub.subscribe("sensors/#")

	for _, topic := range []string{"home/sensors/ok/a/#", "home/sensors/ok/+/x"} {
		for _, retain := range []bool{false, true} {
			b.bridge.receive(packets.Packet{
				FixedHeader: packets.FixedHeader{Type: packets.Publish, Retain: retain},
				TopicName:   topic, Payload: []byte("bad"),
			})
		}
	}
	for topic := range b.srv.Topics.Retained.GetAll() {
		if !strings.HasPrefix(topic, "$SYS/") {
			t.Fatalf("retained message on %s", topic)
		}
	}
	b.bridge.receive(packets.Packet{FixedHeader: packets.FixedHeader{Type: packets.Publish}, TopicName: "home/sensors/ok/a", Payload: []byte("good")})
	if topic, payload := lsub.next(); topic != "sensors/ok/a" || payload != "good" {
		t.Fatalf("local got %s %s, want only the valid topic", topic, payload)
	}
	waitLog(t, lb, "invalid topic from the remote dropped", 4)
}

func TestEchoesSweepAtMostOnceASecond(t *testing.T) {
	e := newEchoes()
	t0 := time.Now()
	for i := range maxEchoes {
		e.sent("t", []byte(strconv.Itoa(i)), t0)
	}
	if len(e.m) != maxEchoes {
		t.Fatalf("%d entries, want a full table", len(e.m))
	}
	// Every entry has expired, but the table was swept half a second ago:
	// no scan, and the new message is not remembered.
	t1 := t0.Add(echoTTL + time.Second)
	e.swept = t1.Add(-500 * time.Millisecond)
	e.sent("x", nil, t1)
	if len(e.m) != maxEchoes || e.back("x", nil, t1) {
		t.Fatal("a full table was swept twice within a second")
	}
	// A second after the last sweep, it is swept.
	t2 := t1.Add(600 * time.Millisecond)
	e.sent("y", nil, t2)
	if len(e.m) != 1 || !e.back("y", nil, t2) {
		t.Fatalf("after a sweep: %d entries, want only the new one", len(e.m))
	}
}

func TestEchoes(t *testing.T) {
	e := newEchoes()
	now := time.Now()
	e.sent("a", []byte("1"), now)
	e.sent("a", []byte("1"), now)
	for i := range 2 {
		if !e.back("a", []byte("1"), now) {
			t.Fatalf("echo %d of a sent message not recognised", i)
		}
	}
	if e.back("a", []byte("1"), now) {
		t.Fatal("a third copy was taken for an echo")
	}
	if e.back("a", []byte("2"), now) || e.back("b", []byte("1"), now) {
		t.Fatal("another message taken for an echo")
	}
	e.sent("a", []byte("1"), now)
	if e.back("a", []byte("1"), now.Add(echoTTL+time.Second)) {
		t.Fatal("an expired echo was recognised")
	}
	if len(e.m) != 0 {
		t.Fatalf("table not emptied: %v", e.m)
	}
}

func TestParseBridge(t *testing.T) {
	const topics = "topics:\n  - prefix: sensors/\n    direction: both\n"
	for name, tc := range map[string]struct {
		yaml, err string
	}{
		"ok":             {yaml: "address: b:8883\n" + topics},
		"no address":     {yaml: topics, err: "host:port"},
		"no port":        {yaml: "address: b\n" + topics, err: "host:port"},
		"protocol":       {yaml: "address: b:1\nprotocol: 3\n" + topics, err: "protocol"},
		"no topics":      {yaml: "address: b:1\n", err: "at least one"},
		"no slash":       {yaml: "address: b:1\ntopics:\n  - prefix: sensors\n    direction: in\n", err: "prefix"},
		"wildcard":       {yaml: "address: b:1\ntopics:\n  - prefix: a/+/\n    direction: in\n", err: "prefix"},
		"remote prefix":  {yaml: "address: b:1\ntopics:\n  - prefix: a/\n    remote_prefix: '#/'\n    direction: in\n", err: "prefix"},
		"direction":      {yaml: "address: b:1\ntopics:\n  - prefix: a/\n    direction: sideways\n", err: "direction"},
		"cert, no key":   {yaml: "address: b:1\ncert_file: c\n" + topics, err: "together"},
		"inline secret":  {yaml: "address: b:1\npassword: hunter2\n" + topics, err: "password"},
		"unknown fields": {yaml: "address: b:1\nbogus: 1\n" + topics, err: "bogus"},
	} {
		t.Run(name, func(t *testing.T) {
			c, err := ParseBridge([]byte(tc.yaml))
			if tc.err == "" {
				if err != nil {
					t.Fatal(err)
				}
				if c.Protocol != 5 || c.Topics[0].RemotePrefix != "sensors/" || !strings.HasPrefix(c.ClientID, "hearth-") {
					t.Fatalf("defaults: %+v", c)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.err) {
				t.Fatalf("err %v, want %q", err, tc.err)
			}
		})
	}
}

func TestLoadBridgePassword(t *testing.T) {
	dir := t.TempDir()
	pass := filepath.Join(dir, "pass")
	path := filepath.Join(dir, "bridge.yaml")
	write := func(p, s string, mode os.FileMode) {
		if err := os.WriteFile(p, []byte(s), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
	}
	write(path, "address: b:8883\nusername: u\npassword_file: "+pass+"\ntopics:\n  - prefix: a/\n    direction: out\n", 0o644)

	write(pass, "s3cret\nignored\n", 0o644)
	if _, err := LoadBridge(path, ""); err == nil || !strings.Contains(err.Error(), "chmod 600") {
		t.Fatalf("readable password file: %v", err)
	}
	write(pass, "s3cret\nignored\n", 0o600)
	c, err := LoadBridge(path, "")
	if err != nil || c.Password != "s3cret" {
		t.Fatalf("password file: %v", err)
	}
	if c.TLS.ServerName != "b" || c.TLS.MinVersion != tls.VersionTLS12 {
		t.Fatalf("TLS: %+v", c.TLS)
	}
	// The environment wins over the file.
	if c, err := LoadBridge(path, "from-env"); err != nil || c.Password != "from-env" {
		t.Fatalf("env password: %v", err)
	}

	crt := filepath.Join(dir, "c.crt")
	write(crt, "cert", 0o644)
	write(path, "address: b:8883\ncert_file: "+crt+"\nkey_file: "+pass+"\ntopics:\n  - prefix: a/\n    direction: out\n", 0o644)
	write(pass, "key", 0o640)
	if _, err := LoadBridge(path, ""); err == nil || !strings.Contains(err.Error(), "chmod 600") {
		t.Fatalf("group-readable key file: %v", err)
	}
	write(path, "address: b:8883\npassword_file: "+pass+"\ntopics:\n  - prefix: a/\n    direction: out\n", 0o644)
	write(pass, "p", 0o600)
	if _, err := LoadBridge(path, ""); err == nil || !strings.Contains(err.Error(), "needs a username") {
		t.Fatalf("password without username: %v", err)
	}
	write(pass, "\nsecond line\n", 0o600)
	if _, err := LoadBridge(path, ""); err == nil || !strings.Contains(err.Error(), "first line is empty") {
		t.Fatalf("empty password file: %v", err)
	}
}
