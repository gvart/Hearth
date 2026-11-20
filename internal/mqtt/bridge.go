// SPDX-License-Identifier: AGPL-3.0-only

package mqtt

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"hash/maphash"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"strings"
	"sync"
	"time"

	mochi "github.com/mochi-mqtt/server/v2"
	"github.com/mochi-mqtt/server/v2/packets"
)

// The bridge is a small MQTT client written on mochi's packets package, so
// the binary carries one MQTT stack. It forwards at QoS 0: it subscribes to
// the remote broker at QoS 0 and publishes at QoS 0, so it never holds a
// message waiting for an acknowledgement.
const (
	bridgeKeepalive  = 30 * time.Second
	bridgeQueue      = 256
	bridgeMinBackoff = time.Second
	bridgeMaxBackoff = 2 * time.Minute
	// echoTTL is how long a message sent to an MQTT 3.1.1 remote is
	// remembered, to recognise it if the remote sends it back.
	echoTTL   = 10 * time.Second
	maxEchoes = 4096
)

// bridge connects the hub's broker to a remote broker as a client.
type bridge struct {
	srv   *mochi.Server
	cfg   *BridgeConfig
	rules []Rule
	log   *slog.Logger
	// out queues messages from the hub's broker for the remote. The
	// broker's publish path fills it and must never wait on the network.
	out chan message
	// echoes is set for an MQTT 3.1.1 remote, which has no No Local.
	echoes *echoes

	minBackoff, maxBackoff, keepalive time.Duration
}

type message struct {
	topic   string
	payload []byte
	retain  bool
}

func newBridge(srv *mochi.Server, cfg *BridgeConfig, clients *Clients, log *slog.Logger) (*bridge, error) {
	if clients == nil || clients.Bridge == nil || len(clients.Bridge.Allow) == 0 {
		return nil, errors.New("mqtt: the clients file has no bridge rules, so the bridge could forward nothing (see docs/mqtt.md)")
	}
	br := &bridge{
		srv: srv, cfg: cfg, rules: clients.Bridge.Allow, log: log, out: make(chan message, bridgeQueue),
		minBackoff: bridgeMinBackoff, maxBackoff: bridgeMaxBackoff, keepalive: bridgeKeepalive,
	}
	if cfg.Protocol == 4 {
		br.echoes = newEchoes()
	}
	for _, t := range cfg.Topics {
		if t.Direction != Out && !allowed(br.rules, t.Prefix+"#", true) {
			log.Warn("mqtt bridge: the bridge rules do not let it write every topic it brings in; the rest are dropped", "prefix", t.Prefix)
		}
		if t.Direction != In && !allowed(br.rules, t.Prefix+"#", false) {
			log.Warn("mqtt bridge: the bridge rules do not let it read every topic it sends out; the rest are dropped", "prefix", t.Prefix)
		}
	}
	return br, nil
}

// run keeps the bridge connected until ctx is done, reconnecting with a
// jittered, capped exponential backoff. A remote failure never ends it.
func (br *bridge) run(ctx context.Context) {
	backoff := br.minBackoff
	for {
		start := time.Now()
		connected, err := br.session(ctx)
		if ctx.Err() != nil {
			return
		}
		// A remote that drops the bridge as soon as it subscribes (another
		// hub with the same client ID, say) still backs off.
		if connected && time.Since(start) > backoff {
			backoff = br.minBackoff
		}
		wait := backoff/2 + rand.N(backoff/2+1) //nolint:gosec // jitter, not a secret
		br.log.Warn("mqtt bridge disconnected", "remote", br.cfg.Address, "err", err, "retry_in", wait)
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
		backoff = min(backoff*2, br.maxBackoff)
	}
}

// session connects once and forwards until the connection or ctx ends. It
// reports whether it got as far as subscribing.
func (br *bridge) session(ctx context.Context) (bool, error) {
	d := tls.Dialer{NetDialer: &net.Dialer{Timeout: connectTimeout}, Config: br.cfg.TLS.Clone()}
	conn, err := d.DialContext(ctx, "tcp", br.cfg.Address)
	if err != nil {
		return false, fmt.Errorf("dial: %w", err)
	}
	defer func() { _ = conn.Close() }()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	_ = conn.SetReadDeadline(time.Now().Add(connectTimeout))
	r := bufio.NewReader(conn)
	v := br.cfg.Protocol

	if err := writePacket(conn, br.connect()); err != nil {
		return false, fmt.Errorf("connect: %w", err)
	}
	pk, err := readPacket(r, v)
	switch {
	case err != nil:
		return false, fmt.Errorf("connect: %w", err)
	case pk.FixedHeader.Type != packets.Connack:
		return false, fmt.Errorf("connect: remote sent packet type %d, not CONNACK", pk.FixedHeader.Type)
	case pk.ReasonCode != 0:
		return false, fmt.Errorf("remote refused the connection: %s", connackReason(v, pk.ReasonCode))
	}

	if sub := br.subscribe(); len(sub.Filters) > 0 {
		if err := writePacket(conn, sub); err != nil {
			return false, fmt.Errorf("subscribe: %w", err)
		}
		for {
			pk, err := readPacket(r, v)
			if err != nil {
				return false, fmt.Errorf("subscribe: %w", err)
			}
			if pk.FixedHeader.Type == packets.Suback {
				br.checkSuback(sub.Filters, pk.ReasonCodes)
				break
			}
			if err := br.handle(pk); err != nil {
				return false, err
			}
		}
	}
	for i, t := range br.cfg.Topics {
		if t.Direction == In {
			continue
		}
		if err := br.srv.Subscribe(t.Prefix+"#", i+1, br.forward(t)); err != nil {
			return true, fmt.Errorf("subscribe locally to %s#: %w", t.Prefix, err)
		}
		defer func() { _ = br.srv.Unsubscribe(t.Prefix+"#", i+1) }()
	}
	br.log.Info("mqtt bridge connected", "remote", br.cfg.Address, "client_id", br.cfg.ClientID, "protocol", v)

	errc := make(chan error, 1)
	go func() { errc <- br.read(conn, r) }()
	ping := time.NewTicker(br.keepalive / 2)
	defer ping.Stop()
	for {
		var err error
		select {
		case err = <-errc:
			return true, err
		case m := <-br.out:
			err = br.publish(conn, m)
		case <-ping.C:
			err = writePacket(conn, packets.Packet{FixedHeader: packets.FixedHeader{Type: packets.Pingreq}})
		}
		if err != nil {
			_ = conn.Close()
			<-errc //nolint:errcheck // the reader fails because of the close
			return true, err
		}
	}
}

func (br *bridge) connect() packets.Packet {
	pk := packets.Packet{
		FixedHeader:     packets.FixedHeader{Type: packets.Connect},
		ProtocolVersion: br.cfg.Protocol,
		Connect: packets.ConnectParams{
			ProtocolName:     []byte("MQTT"),
			Clean:            true,
			Keepalive:        uint16(br.keepalive / time.Second), //nolint:gosec // seconds, set by the bridge
			ClientIdentifier: br.cfg.ClientID,
		},
	}
	if br.cfg.Username != "" {
		pk.Connect.UsernameFlag, pk.Connect.Username = true, []byte(br.cfg.Username)
	}
	if br.cfg.Password != "" {
		pk.Connect.PasswordFlag, pk.Connect.Password = true, []byte(br.cfg.Password)
	}
	if br.cfg.Protocol == 5 {
		pk.Properties.MaximumPacketSize = MaxPacketSize
	}
	return pk
}

// subscribe is the SUBSCRIBE for the topics brought in. With MQTT 5, No
// Local stops the remote from sending back what the bridge publishes.
func (br *bridge) subscribe() packets.Packet {
	pk := packets.Packet{
		FixedHeader:     packets.FixedHeader{Type: packets.Subscribe, Qos: 1},
		ProtocolVersion: br.cfg.Protocol,
		PacketID:        1,
	}
	for _, t := range br.cfg.Topics {
		if t.Direction != Out {
			pk.Filters = append(pk.Filters, packets.Subscription{
				Filter: t.RemotePrefix + "#", NoLocal: true, RetainAsPublished: true,
			})
		}
	}
	return pk
}

func (br *bridge) checkSuback(filters packets.Subscriptions, codes []byte) {
	for i, c := range codes {
		if c >= 0x80 && i < len(filters) {
			br.log.Error("mqtt bridge: the remote refused a subscription", "filter", filters[i].Filter, "code", c)
		}
	}
}

// read handles the remote's packets until the connection fails. The remote
// answers a ping every keepalive/2, so a silent link is a dead one.
func (br *bridge) read(conn net.Conn, r *bufio.Reader) error {
	for {
		_ = conn.SetReadDeadline(time.Now().Add(br.keepalive * 3 / 2))
		pk, err := readPacket(r, br.cfg.Protocol)
		if err != nil {
			return err
		}
		if err := br.handle(pk); err != nil {
			return err
		}
	}
}

func (br *bridge) handle(pk packets.Packet) error {
	switch pk.FixedHeader.Type {
	case packets.Publish:
		br.receive(pk)
	case packets.Disconnect:
		return fmt.Errorf("remote disconnected the bridge: reason code %#x", pk.ReasonCode)
	}
	return nil
}

// receive brings a message from the remote into the hub's broker, if the
// bridge rules let it write the topic.
func (br *bridge) receive(pk packets.Packet) {
	if br.echoes != nil && br.echoes.back(pk.TopicName, pk.Payload, time.Now()) {
		return
	}
	topic, ok := br.toLocal(pk.TopicName)
	if !ok {
		return
	}
	if !allowed(br.rules, topic, true) {
		br.log.Debug("mqtt bridge topic denied", "topic", topic, "direction", In)
		return
	}
	// Published by the broker's inline client, whose ID marks it as the
	// bridge's: forward does not send it back out.
	if err := br.srv.Publish(topic, pk.Payload, pk.FixedHeader.Retain, 0); err != nil {
		br.log.Debug("mqtt bridge: publish locally", "topic", topic, "err", err)
	}
}

func (br *bridge) toLocal(remote string) (string, bool) {
	for _, t := range br.cfg.Topics {
		if t.Direction == Out {
			continue
		}
		if rest, ok := strings.CutPrefix(remote, t.RemotePrefix); ok && rest != "" {
			return t.Prefix + rest, true
		}
	}
	return "", false
}

// forward returns the inline subscription handler that queues the hub
// broker's messages under t.Prefix for the remote. It runs in the broker's
// publish path, so it never blocks: a full queue drops the message.
func (br *bridge) forward(t BridgeTopic) mochi.InlineSubFn {
	return func(_ *mochi.Client, _ packets.Subscription, pk packets.Packet) {
		if pk.Origin == mochi.InlineClientId {
			return // the bridge brought it in
		}
		rest, ok := strings.CutPrefix(pk.TopicName, t.Prefix)
		if !ok || rest == "" {
			return
		}
		if !allowed(br.rules, pk.TopicName, false) {
			br.log.Debug("mqtt bridge topic denied", "topic", pk.TopicName, "direction", Out)
			return
		}
		m := message{topic: t.RemotePrefix + rest, payload: bytes.Clone(pk.Payload), retain: pk.FixedHeader.Retain}
		select {
		case br.out <- m:
		default:
			br.log.Debug("mqtt bridge queue full, message dropped", "topic", pk.TopicName)
		}
	}
}

func (br *bridge) publish(conn net.Conn, m message) error {
	if br.echoes != nil {
		if _, back := br.toLocal(m.topic); back {
			br.echoes.sent(m.topic, m.payload, time.Now())
		}
	}
	return writePacket(conn, packets.Packet{
		FixedHeader:     packets.FixedHeader{Type: packets.Publish, Retain: m.retain},
		ProtocolVersion: br.cfg.Protocol,
		TopicName:       m.topic,
		Payload:         m.payload,
	})
}

// echoes remembers, for a short while, the messages sent to an MQTT 3.1.1
// remote on topics the bridge also brings in. Such a remote has no No Local
// and sends them back; back recognises them. Were it to miss one (the table
// is full), the message would reach local subscribers twice but go no
// further: forward never sends out what the bridge brought in.
type echoes struct {
	mu   sync.Mutex
	seed maphash.Seed
	m    map[uint64]echo
}

func newEchoes() *echoes { return &echoes{seed: maphash.MakeSeed(), m: map[uint64]echo{}} }

type echo struct {
	n     int
	until time.Time
}

func (e *echoes) key(topic string, payload []byte) uint64 {
	var h maphash.Hash
	h.SetSeed(e.seed)
	_, _ = h.WriteString(topic)
	_ = h.WriteByte(0)
	_, _ = h.Write(payload)
	return h.Sum64()
}

func (e *echoes) sent(topic string, payload []byte, now time.Time) {
	k := e.key(topic, payload)
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.m) >= maxEchoes {
		for k, x := range e.m {
			if now.After(x.until) {
				delete(e.m, k)
			}
		}
		if len(e.m) >= maxEchoes {
			return
		}
	}
	x := e.m[k]
	x.n++
	x.until = now.Add(echoTTL)
	e.m[k] = x
}

func (e *echoes) back(topic string, payload []byte, now time.Time) bool {
	k := e.key(topic, payload)
	e.mu.Lock()
	defer e.mu.Unlock()
	x, ok := e.m[k]
	if !ok {
		return false
	}
	if x.n--; x.n <= 0 || now.After(x.until) {
		delete(e.m, k)
	} else {
		e.m[k] = x
	}
	return !now.After(x.until)
}

// writePacket encodes pk and writes it. Errors never carry the packet: a
// CONNECT holds the password.
func writePacket(conn net.Conn, pk packets.Packet) error {
	var buf bytes.Buffer
	var err error
	switch pk.FixedHeader.Type {
	case packets.Connect:
		err = pk.ConnectEncode(&buf)
	case packets.Subscribe:
		err = pk.SubscribeEncode(&buf)
	case packets.Publish:
		err = pk.PublishEncode(&buf)
	case packets.Pingreq:
		err = pk.PingreqEncode(&buf)
	default:
		err = fmt.Errorf("cannot send packet type %d", pk.FixedHeader.Type)
	}
	if err != nil {
		return fmt.Errorf("encode: %w", err)
	}
	_ = conn.SetWriteDeadline(time.Now().Add(connectTimeout))
	if _, err := conn.Write(buf.Bytes()); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	return nil
}

// readPacket reads one packet of at most MaxPacketSize bytes.
func readPacket(r *bufio.Reader, version byte) (packets.Packet, error) {
	pk := packets.Packet{ProtocolVersion: version}
	hb, err := r.ReadByte()
	if err != nil {
		return pk, fmt.Errorf("read: %w", err)
	}
	if err := pk.FixedHeader.Decode(hb); err != nil {
		return pk, fmt.Errorf("read: %w", err)
	}
	n, _, err := packets.DecodeLength(r)
	if err != nil {
		return pk, fmt.Errorf("read: %w", err)
	}
	if n > MaxPacketSize {
		return pk, fmt.Errorf("read: the remote sent a packet of %d bytes, over the %d byte limit", n, MaxPacketSize)
	}
	pk.FixedHeader.Remaining = n
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return pk, fmt.Errorf("read: %w", err)
	}
	switch pk.FixedHeader.Type {
	case packets.Connack:
		err = pk.ConnackDecode(buf)
		// An MQTT 3.1.1 broker refuses an MQTT 5 CONNECT with a 3.1.1
		// CONNACK, which has no properties.
		if err != nil && len(buf) == 2 && buf[1] != 0 {
			pk.ReasonCode, err = buf[1], nil
		}
	case packets.Publish:
		err = pk.PublishDecode(buf)
	case packets.Suback:
		err = pk.SubackDecode(buf)
	case packets.Disconnect:
		err = pk.DisconnectDecode(buf)
	}
	if err != nil {
		return pk, fmt.Errorf("decode packet type %d: %w", pk.FixedHeader.Type, err)
	}
	return pk, nil
}

func connackReason(version, code byte) string {
	reasons := map[byte]string{
		0x84: "unsupported protocol version (try protocol: 4)", 0x85: "client ID not valid",
		0x86: "bad username or password", 0x87: "not authorized", 0x88: "server unavailable",
		0x8a: "banned",
	}
	if version == 4 {
		reasons = map[byte]string{
			1: "unsupported protocol version", 2: "client ID not valid", 3: "server unavailable",
			4: "bad username or password", 5: "not authorized",
		}
	}
	if r, ok := reasons[code]; ok {
		return fmt.Sprintf("%s (code %#x)", r, code)
	}
	return fmt.Sprintf("code %#x", code)
}
