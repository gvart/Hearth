// SPDX-License-Identifier: AGPL-3.0-only

package mqtt

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/gvart/hearth/internal/pki"
	"github.com/gvart/hearth/internal/store"
)

// fakeCerts answers Check from a map of serial to result.
type fakeCerts struct {
	mu sync.Mutex
	m  map[string]error
}

func (f *fakeCerts) set(serial string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.m[serial] = err
}

func (f *fakeCerts) Check(_ context.Context, serial, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err, ok := f.m[serial]; ok {
		return err
	}
	return fmt.Errorf("check cert %s: %w", serial, store.ErrNotFound)
}

// syncBuffer is a log sink tests can read while the broker writes.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

type testBroker struct {
	addr   string
	ca     *pki.CA
	pool   *x509.CertPool
	certs  *fakeCerts
	logs   *syncBuffer
	cancel context.CancelFunc
	done   chan error
}

const testPassword = "correct horse battery staple"

// startBroker starts a broker; each of tweak runs on it before it serves.
func startBroker(t *testing.T, clients string, tweak ...func(*Broker)) *testBroker {
	t.Helper()
	now := time.Now()
	ca, err := pki.LoadOrCreateCA(t.TempDir(), now)
	if err != nil {
		t.Fatal(err)
	}
	serverCert, err := ca.IssueServerCert([]string{"127.0.0.1"}, now)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(testPassword), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	c, err := ParseClients([]byte(strings.ReplaceAll(clients, "HASH", string(hash))))
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	logs := &syncBuffer{}
	certs := &fakeCerts{m: map[string]error{}}
	b, err := New(Config{
		Listener: ln, CA: ca, ServerCert: func() *tls.Certificate { return &serverCert },
		Clients: c, Certs: certs, Recheck: 50 * time.Millisecond, Log: slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	tb := &testBroker{addr: b.Addr().String(), ca: ca, pool: ca.Pool(), certs: certs, logs: logs, cancel: cancel, done: make(chan error, 1)}
	for _, f := range tweak {
		f(b)
	}
	go func() { tb.done <- b.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-tb.done:
			if err != nil {
				t.Errorf("Run: %v", err)
			}
		case <-time.After(15 * time.Second):
			t.Error("broker did not stop")
		}
		if strings.Contains(logs.String(), testPassword) || strings.Contains(logs.String(), "wrong-password") {
			t.Error("a password was logged")
		}
	})
	return tb
}

// deviceCert issues a hub client certificate for deviceID, valid at now.
func deviceCert(t *testing.T, ca *pki.CA, deviceID string, now time.Time) tls.Certificate {
	t.Helper()
	key, err := pki.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	cert, err := ca.SignClientKey(key.Public(), deviceID, now)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{cert.Raw}, PrivateKey: key, Leaf: cert}
}

// client is a minimal MQTT 3.1.1 client.
type client struct {
	t    *testing.T
	conn net.Conn
	r    *bufio.Reader
}

type connectOpts struct {
	id, user, pass       string
	willTopic            string
	cert                 *tls.Certificate
	noUsername, noPasswd bool
}

func mqttString(s string) []byte {
	return append(binary.BigEndian.AppendUint16(nil, uint16(len(s))), s...) //nolint:gosec // test strings are short
}

func packet(typ byte, body []byte) []byte {
	out := []byte{typ}
	n := len(body)
	for {
		b := byte(n % 128)
		n /= 128
		if n > 0 {
			b |= 0x80
		}
		out = append(out, b)
		if n == 0 {
			break
		}
	}
	return append(out, body...)
}

// dial connects and returns the client and the CONNACK return code, or an
// error if the TLS handshake or CONNACK fails.
func (tb *testBroker) dial(t *testing.T, o connectOpts) (*client, byte, error) {
	t.Helper()
	cfg := &tls.Config{RootCAs: tb.pool, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12}
	if o.cert != nil {
		cfg.Certificates = []tls.Certificate{*o.cert}
	}
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", tb.addr, cfg)
	if err != nil {
		return nil, 0, err
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	c := &client{t: t, conn: conn, r: bufio.NewReader(conn)}
	if o.id == "" {
		o.id = "c-" + t.Name()
	}
	flags := byte(0x02) // clean session
	payload := mqttString(o.id)
	if o.willTopic != "" {
		flags |= 0x04
		payload = append(payload, mqttString(o.willTopic)...)
		payload = append(payload, mqttString("gone")...)
	}
	if o.user != "" && !o.noUsername {
		flags |= 0x80
		payload = append(payload, mqttString(o.user)...)
		if !o.noPasswd {
			flags |= 0x40
			payload = append(payload, mqttString(o.pass)...)
		}
	}
	body := append(mqttString("MQTT"), 4, flags, 0, 60)
	if _, err := conn.Write(packet(0x10, append(body, payload...))); err != nil {
		return nil, 0, err
	}
	typ, resp, err := c.read()
	if err != nil {
		return nil, 0, err
	}
	if typ != 0x20 || len(resp) != 2 {
		return nil, 0, fmt.Errorf("want CONNACK, got type %#x %v", typ, resp)
	}
	return c, resp[1], nil
}

func (c *client) read() (byte, []byte, error) {
	typ, err := c.r.ReadByte()
	if err != nil {
		return 0, nil, err
	}
	n, mul := 0, 1
	for {
		b, err := c.r.ReadByte()
		if err != nil {
			return 0, nil, err
		}
		n += int(b&0x7f) * mul
		mul *= 128
		if b&0x80 == 0 {
			break
		}
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(c.r, body); err != nil {
		return 0, nil, err
	}
	return typ, body, nil
}

// subscribe subscribes at QoS 0 and returns the SUBACK return code.
func (c *client) subscribe(filter string) byte {
	c.t.Helper()
	body := append([]byte{0, 1}, mqttString(filter)...)
	if _, err := c.conn.Write(packet(0x82, append(body, 0))); err != nil {
		c.t.Fatal(err)
	}
	typ, resp, err := c.read()
	if err != nil || typ != 0x90 || len(resp) != 3 {
		c.t.Fatalf("SUBACK: %#x %v %v", typ, resp, err)
	}
	return resp[2]
}

func (c *client) publish(topic, payload string) {
	c.t.Helper()
	if _, err := c.conn.Write(packet(0x30, append(mqttString(topic), payload...))); err != nil {
		c.t.Fatal(err)
	}
}

// next returns the topic and payload of the next PUBLISH.
func (c *client) next() (string, string) {
	c.t.Helper()
	typ, body, err := c.read()
	if err != nil {
		c.t.Fatalf("read PUBLISH: %v", err)
	}
	if typ&0xf0 != 0x30 || len(body) < 2 {
		c.t.Fatalf("want PUBLISH, got %#x", typ)
	}
	n := int(body[0])<<8 | int(body[1])
	return string(body[2 : 2+n]), string(body[2+n:])
}

const (
	accepted      = 0x00
	notAuthorized = 0x05
	subFailure    = 0x80
)

const clientsYAML = `
users:
  - name: sensors
    password_hash: HASH
    allow:
      - topic: sensors/#
        access: readwrite
  - name: watcher
    password_hash: HASH
    allow:
      - topic: "#"
        access: read
devices:
  - id: dev1
    allow:
      - topic: hearth/dev1/#
        access: readwrite
`

func TestPasswordClientPublishesAndSubscribes(t *testing.T) {
	tb := startBroker(t, clientsYAML)
	sub, rc, err := tb.dial(t, connectOpts{id: "sub", user: "sensors", pass: testPassword})
	if err != nil || rc != accepted {
		t.Fatalf("connect: rc %d, %v", rc, err)
	}
	if rc := sub.subscribe("sensors/#"); rc != 0 {
		t.Fatalf("subscribe sensors/#: %#x", rc)
	}
	pub, rc, err := tb.dial(t, connectOpts{id: "pub", user: "sensors", pass: testPassword})
	if err != nil || rc != accepted {
		t.Fatalf("connect: rc %d, %v", rc, err)
	}
	pub.publish("sensors/kitchen/temp", "21.5")
	if topic, payload := sub.next(); topic != "sensors/kitchen/temp" || payload != "21.5" {
		t.Fatalf("got %s %s", topic, payload)
	}
}

func TestRefusedConnections(t *testing.T) {
	tb := startBroker(t, clientsYAML)
	tests := map[string]connectOpts{
		"wrong password":       {user: "sensors", pass: "wrong-password"},
		"unknown user":         {user: "nobody", pass: testPassword},
		"anonymous":            {},
		"username, no passwd":  {user: "sensors", noPasswd: true},
		"empty password":       {user: "sensors", pass: ""},
		"device name as user":  {user: "device:dev1", pass: testPassword},
		"will outside its ACL": {user: "sensors", pass: testPassword, willTopic: "other/lwt"},
	}
	for name, o := range tests {
		t.Run(name, func(t *testing.T) {
			_, rc, err := tb.dial(t, o)
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			// mochi answers an empty password with a protocol error;
			// every other refusal is "not authorized".
			if want := byte(notAuthorized); rc != want && (name != "empty password" || rc == accepted) {
				t.Fatalf("CONNACK %#x, want %#x", rc, want)
			}
		})
	}
	if !strings.Contains(tb.logs.String(), "mqtt client refused") {
		t.Error("refusals are not logged")
	}
}

func TestWillInsideACL(t *testing.T) {
	tb := startBroker(t, clientsYAML)
	if _, rc, err := tb.dial(t, connectOpts{user: "sensors", pass: testPassword, willTopic: "sensors/lwt"}); err != nil || rc != accepted {
		t.Fatalf("rc %d, %v", rc, err)
	}
}

func TestTopicACL(t *testing.T) {
	tb := startBroker(t, clientsYAML)
	sensors, _, err := tb.dial(t, connectOpts{id: "sensors", user: "sensors", pass: testPassword})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"#", "other/#", "+/temp", "$SYS/#", "sensorsX/a", "$share/g/other/#"} {
		if rc := sensors.subscribe(f); rc != subFailure {
			t.Errorf("subscribe %q: %#x, want refused", f, rc)
		}
	}
	watcher, _, err := tb.dial(t, connectOpts{id: "watcher", user: "watcher", pass: testPassword})
	if err != nil {
		t.Fatal(err)
	}
	if rc := watcher.subscribe("#"); rc != 0 {
		t.Fatalf("watcher subscribe #: %#x", rc)
	}
	// A publish outside the ACL is dropped: the watcher sees only the
	// allowed one that follows it.
	sensors.publish("other/x", "forbidden")
	sensors.publish("sensors/x", "fine")
	if topic, payload := watcher.next(); topic != "sensors/x" || payload != "fine" {
		t.Fatalf("watcher got %s %s", topic, payload)
	}
	// The watcher may only read.
	watcher.publish("sensors/y", "from-watcher")
	sensors.publish("sensors/z", "after")
	if topic, _ := watcher.next(); topic != "sensors/z" {
		t.Fatalf("a read-only client's publish went through: %s", topic)
	}
}

func TestDeviceCertificate(t *testing.T) {
	tb := startBroker(t, clientsYAML)
	now := time.Now()
	good := deviceCert(t, tb.ca, "dev1", now)
	tb.certs.set(pki.SerialString(good.Leaf), nil)
	c, rc, err := tb.dial(t, connectOpts{cert: &good})
	if err != nil || rc != accepted {
		t.Fatalf("device connect: rc %d, %v", rc, err)
	}
	if rc := c.subscribe("hearth/dev1/#"); rc != 0 {
		t.Fatalf("subscribe own topic: %#x", rc)
	}
	if rc := c.subscribe("hearth/dev2/#"); rc != subFailure {
		t.Fatalf("subscribe another device's topic: %#x", rc)
	}
	c.publish("hearth/dev1/state", "on")
	if topic, payload := c.next(); topic != "hearth/dev1/state" || payload != "on" {
		t.Fatalf("got %s %s", topic, payload)
	}
	// The certificate decides; a matching username is fine, a password ignored.
	if _, rc, err := tb.dial(t, connectOpts{id: "d2", cert: &good, user: "dev1", pass: "anything"}); err != nil || rc != accepted {
		t.Fatalf("cert with matching username: rc %d, %v", rc, err)
	}

	revoked := deviceCert(t, tb.ca, "dev1", now)
	tb.certs.set(pki.SerialString(revoked.Leaf), fmt.Errorf("check: %w", store.ErrCertRevoked))
	unlisted := deviceCert(t, tb.ca, "dev9", now)
	tb.certs.set(pki.SerialString(unlisted.Leaf), nil)
	broken := deviceCert(t, tb.ca, "dev1", now)
	tb.certs.set(pki.SerialString(broken.Leaf), errors.New("database is locked"))
	unknown := deviceCert(t, tb.ca, "dev1", now)
	refused := map[string]connectOpts{
		"revoked":              {cert: &revoked},
		"unknown to the store": {cert: &unknown},
		"store error":          {cert: &broken},
		"not in clients file":  {cert: &unlisted},
		"other username":       {cert: &good, user: "sensors", pass: testPassword},
	}
	for name, o := range refused {
		t.Run(name, func(t *testing.T) {
			if _, rc, err := tb.dial(t, o); err != nil || rc != notAuthorized {
				t.Fatalf("rc %d, %v; want refused", rc, err)
			}
		})
	}

	// Certificates the TLS handshake itself refuses.
	foreignCA, err := pki.LoadOrCreateCA(t.TempDir(), now)
	if err != nil {
		t.Fatal(err)
	}
	foreign := deviceCert(t, foreignCA, "dev1", now)
	expired := deviceCert(t, tb.ca, "dev1", now.Add(-pki.ClientCertValidity-time.Hour))
	tb.certs.set(pki.SerialString(expired.Leaf), nil)
	for name, cert := range map[string]*tls.Certificate{"foreign CA": &foreign, "expired": &expired} {
		t.Run(name, func(t *testing.T) {
			if _, rc, err := tb.dial(t, connectOpts{cert: cert}); err == nil {
				t.Fatalf("connected with rc %d; want a TLS failure", rc)
			}
		})
	}
}

func TestClientIDOfAnotherIdentity(t *testing.T) {
	tb := startBroker(t, clientsYAML)
	if _, rc, err := tb.dial(t, connectOpts{id: "shared", user: "sensors", pass: testPassword}); err != nil || rc != accepted {
		t.Fatalf("rc %d, %v", rc, err)
	}
	if _, rc, err := tb.dial(t, connectOpts{id: "shared", user: "watcher", pass: testPassword}); err != nil || rc != notAuthorized {
		t.Fatalf("takeover by another identity: rc %d, %v; want refused", rc, err)
	}
	// The same identity may take its own session over, as MQTT allows.
	if _, rc, err := tb.dial(t, connectOpts{id: "shared", user: "sensors", pass: testPassword}); err != nil || rc != accepted {
		t.Fatalf("own takeover: rc %d, %v", rc, err)
	}
}

func TestPlainTCPRefused(t *testing.T) {
	tb := startBroker(t, clientsYAML)
	conn, err := net.DialTimeout("tcp", tb.addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	connect := packet(0x10, append(append(mqttString("MQTT"), 4, 0x02, 0, 60), mqttString("plain")...))
	_, _ = conn.Write(connect)
	if b, err := io.ReadAll(conn); err == nil && bytes.HasPrefix(b, []byte{0x20}) {
		t.Fatalf("plain TCP got a CONNACK: %v", b)
	}
}

func TestRunStopsWithConnectedClients(t *testing.T) {
	tb := startBroker(t, clientsYAML)
	c, _, err := tb.dial(t, connectOpts{user: "sensors", pass: testPassword})
	if err != nil {
		t.Fatal(err)
	}
	// A connection that never finishes its handshake must not hold up the stop.
	raw, err := net.Dial("tcp", tb.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = raw.Close() }()
	tb.cancel()
	select {
	case err := <-tb.done:
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		tb.done <- nil // for the cleanup
	case <-time.After(connectTimeout / 2):
		t.Fatal("Run did not return before the connect timeout")
	}
	// The broker may send DISCONNECT first; then the connection ends.
	for range 3 {
		if _, _, err := c.read(); err != nil {
			return
		}
	}
	t.Fatal("client still connected after stop")
}
