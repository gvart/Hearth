// SPDX-License-Identifier: AGPL-3.0-only

package mqtt

import (
	"crypto/tls"
	"net"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mochi-mqtt/server/v2/packets"

	"github.com/gvart/hearth/internal/deviceproto"
	"github.com/gvart/hearth/internal/pki"
)

// fakeSink records what the broker hands the Device Protocol.
type fakeSink struct {
	mu   sync.Mutex
	msgs []deviceproto.Message
	gone []string
}

func (f *fakeSink) DeviceMessage(m deviceproto.Message) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.msgs = append(f.msgs, m)
}

func (f *fakeSink) DeviceGone(id string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.gone = append(f.gone, id)
}

func (f *fakeSink) messages() []deviceproto.Message {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.msgs)
}

func (f *fakeSink) departed() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.gone)
}

// protocolYAML: kitchen is a protocol device; garage is one too, granted all
// of hearth/; watcher reads everything; dev1 is an enrolled device granted
// all of hearth/ as well.
const protocolYAML = `
users:
  - name: kitchen
    password_hash: HASH
    allow:
      - topic: hearth/v1/kitchen/#
        access: readwrite
  - name: garage
    password_hash: HASH
    allow:
      - topic: hearth/#
        access: readwrite
  - name: watcher
    password_hash: HASH
    allow:
      - topic: "#"
        access: read
devices:
  - id: dev1
    allow:
      - topic: hearth/#
        access: readwrite
`

const announceJSON = `{"v":1,"name":"Kitchen","entities":[{"id":"relay","kind":"switch"}],"commands":[{"name":"relay.set"}]}`

func startProtocolBroker(t *testing.T) (*testBroker, *fakeSink) {
	t.Helper()
	sink := &fakeSink{}
	return startBrokerConfig(t, protocolYAML, func(c *Config) { c.Protocol = sink }), sink
}

func TestPermits(t *testing.T) {
	all := []Rule{{Topic: "#", Access: ReadWrite}}
	tests := []struct {
		name, identity, topic string
		write, want           bool
	}{
		{"own announce", "kitchen", "hearth/v1/kitchen/announce", true, true},
		{"own state", "kitchen", "hearth/v1/kitchen/state", true, true},
		{"own result", "kitchen", "hearth/v1/kitchen/result", true, true},
		{"own command", "kitchen", "hearth/v1/kitchen/command", true, false},
		{"another device's announce", "garage", "hearth/v1/kitchen/announce", true, false},
		{"unknown kind", "kitchen", "hearth/v1/kitchen/foo", true, false},
		{"deeper topic", "kitchen", "hearth/v1/kitchen/state/x", true, false},
		{"the namespace root", "kitchen", "hearth/v1", true, false},
		{"an enrolled device", devicePrefix + "kitchen", "hearth/v1/kitchen/state", true, false},
		{"reading another device's state", "garage", "hearth/v1/kitchen/state", false, true},
		{"outside the namespace", "garage", "hearth/dev1/x", true, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := permits(tt.identity, all, tt.topic, tt.write); got != tt.want {
				t.Fatalf("permits = %v, want %v", got, tt.want)
			}
		})
	}
	// The clients file must still grant the topic.
	if permits("kitchen", nil, "hearth/v1/kitchen/state", true) {
		t.Fatal("a topic no rule grants is permitted")
	}
}

func TestProtocolAnnounceReachesSink(t *testing.T) {
	tb, sink := startProtocolBroker(t)
	watcher := connected(t, tb, "watcher", "watcher")
	watcher.subscribe("hearth/#")
	connected(t, tb, "kitchen", "kitchen").publish("hearth/v1/kitchen/announce", announceJSON)
	if topic, payload := watcher.next(); topic != "hearth/v1/kitchen/announce" || payload != announceJSON {
		t.Fatalf("watcher got %s %s", topic, payload)
	}
	msgs := sink.messages()
	if len(msgs) != 1 || msgs[0].Device != "kitchen" || msgs[0].Kind != deviceproto.KindAnnounce || msgs[0].Announce.Name != "Kitchen" {
		t.Fatalf("sink got %+v", msgs)
	}
}

// TestProtocolOnlyOwnTopics: whatever the clients file grants, a client
// publishes only on its own device topics, and none on a command topic.
func TestProtocolOnlyOwnTopics(t *testing.T) {
	tb, sink := startProtocolBroker(t)
	watcher := connected(t, tb, "watcher", "watcher")
	watcher.subscribe("hearth/#")
	kitchen := connected(t, tb, "kitchen", "kitchen")
	garage := connected(t, tb, "garage", "garage")
	good := deviceCert(t, tb.ca, "dev1", time.Now())
	tb.certs.set(pki.SerialString(good.Leaf), nil)
	dev1, rc, err := tb.dial(t, connectOpts{id: "dev1", cert: &good})
	if err != nil || rc != accepted {
		t.Fatalf("device connect: rc %d, %v", rc, err)
	}

	garage.publish("hearth/v1/kitchen/announce", announceJSON)        // another device's topic
	garage.publish("hearth/v1/kitchen/command", `{"v":1}`)            // a command
	garage.publish("hearth/v1/garage/command", `{"v":1}`)             // even its own
	kitchen.publish("hearth/v1/kitchen/command", `{"v":1}`)           // even the device's own
	dev1.publish("hearth/v1/dev1/announce", announceJSON)             // an enrolled device: no protocol id
	garage.publish("hearth/v1", announceJSON)                         // the root
	garage.publish("hearth/v1/kitchen/state/x", `{"v":1,"state":{}}`) // below a device topic
	kitchen.publish("hearth/v1/kitchen/state", `{"v":1,"state":{"relay":true}}`)
	if topic, _ := watcher.next(); topic != "hearth/v1/kitchen/state" {
		t.Fatalf("a refused publish went through: %s", topic)
	}
	if msgs := sink.messages(); len(msgs) != 1 || msgs[0].Device != "kitchen" || msgs[0].Kind != deviceproto.KindState {
		t.Fatalf("sink got %+v", msgs)
	}
	// Outside the namespace the clients file decides alone.
	garage.publish("hearth/garage/x", "fine")
	if topic, _ := watcher.next(); topic != "hearth/garage/x" {
		t.Fatalf("watcher got %s", topic)
	}
}

func TestProtocolWill(t *testing.T) {
	tb, _ := startProtocolBroker(t)
	const offline = `{"v":1,"status":"offline"}`
	if _, rc, err := tb.dial(t, connectOpts{
		user: "kitchen", pass: testPassword,
		willTopic: "hearth/v1/kitchen/availability", willPayload: offline,
	}); err != nil || rc != accepted {
		t.Fatalf("own availability will: rc %d, %v", rc, err)
	}
	// The broker sends a will without checking it as a publish: it is
	// checked at CONNECT.
	for _, will := range []struct{ topic, payload string }{
		{"hearth/v1/kitchen/availability", "gone"},
		{"hearth/v1/kitchen/availability", `{"v":1,"status":"online"}`},
		{"hearth/v1/kitchen/state", `{"v":1,"state":{"relay":true}}`},
	} {
		if _, rc, err := tb.dial(t, connectOpts{
			user: "kitchen", pass: testPassword,
			willTopic: will.topic, willPayload: will.payload,
		}); err != nil || rc != notAuthorized {
			t.Fatalf("will %s %s: rc %d, %v, want refused", will.topic, will.payload, rc, err)
		}
	}
	for _, will := range []string{"hearth/v1/kitchen/availability", "hearth/v1/garage/command"} {
		if _, rc, err := tb.dial(t, connectOpts{user: "garage", pass: testPassword, willTopic: will}); err != nil || rc != notAuthorized {
			t.Fatalf("will on %s: rc %d, %v, want refused", will, rc, err)
		}
	}
}

func TestProtocolMalformedAndOversize(t *testing.T) {
	tb, sink := startProtocolBroker(t)
	watcher := connected(t, tb, "watcher", "watcher")
	watcher.subscribe("hearth/#")
	kitchen := connected(t, tb, "kitchen", "kitchen")
	const marker = "do-not-log-this-payload"
	for _, payload := range []string{
		`{"v":1,"name":"` + marker,        // malformed JSON
		`{"v":2,"name":"` + marker + `"}`, // another version
		`{"v":1,"name":"` + marker + strings.Repeat("x", deviceproto.MaxPayload) + `"}`, // over 16 KiB
		`{"v":1,"entities":[{"id":"` + marker + `/x","kind":"sensor"}]}`,                // a bad entity id
	} {
		kitchen.publish("hearth/v1/kitchen/announce", payload)
	}
	kitchen.publish("hearth/v1/kitchen/announce", announceJSON)
	if topic, payload := watcher.next(); topic != "hearth/v1/kitchen/announce" || payload != announceJSON {
		t.Fatalf("a refused message was delivered: %s %.40s", topic, payload)
	}
	if msgs := sink.messages(); len(msgs) != 1 || msgs[0].Announce.Name != "Kitchen" {
		t.Fatalf("sink got %d messages, want only the valid one", len(msgs))
	}
	waitLog(t, tb, "mqtt device message refused", 4)
	if strings.Contains(tb.logs.String(), marker) {
		t.Fatal("a payload was logged")
	}
	// A refused message is not retained either.
	for topic := range tb.b.srv.Topics.Retained.GetAll() {
		if deviceproto.InNamespace(topic) {
			t.Fatalf("retained message on %s", topic)
		}
	}
}

func TestProtocolUnauthenticated(t *testing.T) {
	tb, sink := startProtocolBroker(t)
	for _, o := range []connectOpts{
		{user: "kitchen", pass: "wrong-password"},
		{user: "kitchen", noPasswd: true},
		{},
	} {
		c, rc, err := tb.dial(t, o)
		if err != nil {
			t.Fatal(err)
		}
		if rc == accepted {
			t.Fatalf("%+v: accepted", o)
		}
		// Whatever it sends after a refused CONNECT goes nowhere.
		if _, err := c.conn.Write(packet(0x30, append(mqttString("hearth/v1/kitchen/announce"), announceJSON...))); err == nil {
			_, _, _ = c.read()
		}
	}
	if msgs := sink.messages(); len(msgs) != 0 {
		t.Fatalf("sink got %+v", msgs)
	}
	if tb.b.Connected("kitchen") {
		t.Fatal("a refused client counts as connected")
	}
}

func TestProtocolCommandAndGone(t *testing.T) {
	tb, sink := startProtocolBroker(t)
	kitchen := connected(t, tb, "kitchen", "kitchen")
	if rc := kitchen.subscribe("hearth/v1/kitchen/command"); rc != 0 {
		t.Fatalf("subscribe own command topic: %#x", rc)
	}
	if !tb.b.Connected("kitchen") || tb.b.Connected("garage") {
		t.Fatal("Connected is wrong")
	}
	if err := tb.b.PublishCommand("kitchen", []byte(`{"v":1}`)); err != nil {
		t.Fatal(err)
	}
	if topic, payload := kitchen.next(); topic != "hearth/v1/kitchen/command" || payload != `{"v":1}` {
		t.Fatalf("kitchen got %s %s", topic, payload)
	}
	if err := tb.b.PublishCommand("bad/id", nil); err == nil {
		t.Fatal("PublishCommand took an invalid id")
	}
	_ = kitchen.conn.Close()
	deadline := time.Now().Add(5 * time.Second)
	for !slices.Equal(sink.departed(), []string{"kitchen"}) {
		if time.Now().After(deadline) {
			t.Fatalf("DeviceGone = %v, want [kitchen]", sink.departed())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestPublishCommandWithoutProtocol(t *testing.T) {
	tb := startBroker(t, protocolYAML)
	if err := tb.b.PublishCommand("kitchen", nil); err == nil {
		t.Fatal("PublishCommand worked without the device protocol")
	}
}

// TestBridgeRefusesProtocolTopics: a remote broker cannot bring in a message
// on a Device Protocol topic, a command least of all.
func TestBridgeRefusesProtocolTopics(t *testing.T) {
	rb := startBroker(t, remoteYAML)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := ln.Addr().String()
	_ = ln.Close() // receive is called directly
	cfg, err := ParseBridge([]byte("address: " + dead + "\nclient_id: hearth-test\nusername: bridge\n" +
		"topics:\n  - prefix: hearth/\n    remote_prefix: home/hearth/\n    direction: in\n"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Protocol, cfg.Password = 5, testPassword
	cfg.TLS = &tls.Config{RootCAs: rb.pool, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12}
	clients := protocolYAML + "bridge:\n  allow:\n    - topic: hearth/#\n      access: readwrite\n"
	sink := &fakeSink{}
	lb := startBrokerConfig(t, clients, func(c *Config) { c.Bridge, c.Protocol = cfg, sink }, fastRetry)
	kitchen := connected(t, lb, "kitchen", "kitchen")
	kitchen.subscribe("hearth/v1/kitchen/command")
	watcher := connected(t, lb, "watcher", "watcher")
	watcher.subscribe("hearth/#")
	for _, topic := range []string{"home/hearth/v1/kitchen/command", "home/hearth/v1/kitchen/announce"} {
		lb.b.bridge.receive(packets.Packet{FixedHeader: packets.FixedHeader{Type: packets.Publish}, TopicName: topic, Payload: []byte(announceJSON)})
	}
	lb.b.bridge.receive(packets.Packet{FixedHeader: packets.FixedHeader{Type: packets.Publish}, TopicName: "home/hearth/other", Payload: []byte("ok")})
	if topic, _ := watcher.next(); topic != "hearth/other" {
		t.Fatalf("a bridged protocol message went through: %s", topic)
	}
	kitchen.none()
	if msgs := sink.messages(); len(msgs) != 0 {
		t.Fatalf("sink got %+v", msgs)
	}
}
