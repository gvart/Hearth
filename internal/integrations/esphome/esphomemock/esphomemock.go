// SPDX-License-Identifier: AGPL-3.0-only

// Package esphomemock is a fake ESPHome device for tests: it serves the
// native API on a loopback port, in plaintext or with Noise encryption, as
// the device side does (esphome/components/api/api_frame_helper_*.cpp). It
// lists entities, streams their states, answers and sends pings, and
// records the commands it receives.
package esphomemock

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/flynn/noise"
	"google.golang.org/protobuf/proto"

	esphomev1 "github.com/gvart/hearth/internal/proto/hearth/esphome/v1"
)

// Entity kinds.
const (
	Sensor       = "sensor"
	BinarySensor = "binary_sensor"
	Switch       = "switch"
	Button       = "button"
	TextSensor   = "text_sensor"
)

// Entity is one entity of the fake device.
type Entity struct {
	Key      uint32
	ObjectID string
	Name     string
	Kind     string
	Unit     string
	// State is float32 for a sensor, bool for a binary sensor or a switch,
	// string for a text sensor; nil for none yet.
	State any
}

// Config describes the fake device.
type Config struct {
	Name string
	MAC  string
	// Key is the API encryption key, base64 of 32 bytes; empty serves
	// plaintext.
	Key string
	// Password, for plaintext, is the legacy API password the device wants.
	Password string
	Entities []Entity
	// PingEvery makes the device ping each client this often, and drop one
	// that does not answer before the next ping. Zero sends no pings.
	PingEvery time.Duration
}

// Command is a command the device received.
type Command struct {
	Key  uint32
	Kind string
	// On is the state a switch command asks for.
	On bool
}

// Device is a running fake device.
type Device struct {
	cfg Config
	psk []byte
	ln  net.Listener
	wg  sync.WaitGroup

	mu       sync.Mutex
	states   map[uint32]any
	commands []Command
	pongs    int
	conns    map[*conn]bool
	closed   bool
}

// Start serves cfg on 127.0.0.1 until Close.
func Start(cfg Config) (*Device, error) {
	d := &Device{cfg: cfg, states: map[uint32]any{}, conns: map[*conn]bool{}}
	if cfg.Key != "" {
		psk, err := base64.StdEncoding.DecodeString(cfg.Key)
		if err != nil || len(psk) != 32 {
			return nil, errors.New("esphomemock: key must be base64 of 32 bytes")
		}
		d.psk = psk
	}
	for _, e := range cfg.Entities {
		d.states[e.Key] = e.State
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	d.ln = ln
	d.wg.Go(d.accept)
	return d, nil
}

// Addr is the address the device serves on.
func (d *Device) Addr() string { return d.ln.Addr().String() }

// Close stops the device and drops every client.
func (d *Device) Close() {
	d.mu.Lock()
	d.closed = true
	for c := range d.conns {
		_ = c.nc.Close()
	}
	d.mu.Unlock()
	_ = d.ln.Close()
	d.wg.Wait()
}

// DropClients closes every client's connection, as a reboot would.
func (d *Device) DropClients() {
	d.mu.Lock()
	defer d.mu.Unlock()
	for c := range d.conns {
		_ = c.nc.Close()
	}
}

// Clients is how many clients are subscribed to states.
func (d *Device) Clients() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	n := 0
	for c := range d.conns {
		if c.subscribed {
			n++
		}
	}
	return n
}

// Commands returns the commands received so far.
func (d *Device) Commands() []Command {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]Command(nil), d.commands...)
}

// Pongs is how many of the device's pings were answered.
func (d *Device) Pongs() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.pongs
}

// SetState changes an entity's state and sends it to every subscribed
// client.
func (d *Device) SetState(key uint32, state any) {
	d.mu.Lock()
	d.states[key] = state
	var subs []*conn
	for c := range d.conns {
		if c.subscribed {
			subs = append(subs, c)
		}
	}
	d.mu.Unlock()
	for _, c := range subs {
		if p, ok := d.statePacket(key); ok {
			_ = c.send(p)
		}
	}
}

func (d *Device) accept() {
	for {
		nc, err := d.ln.Accept()
		if err != nil {
			return
		}
		c := &conn{d: d, nc: nc, r: bufio.NewReader(nc)}
		d.mu.Lock()
		if d.closed {
			d.mu.Unlock()
			_ = nc.Close()
			return
		}
		d.conns[c] = true
		d.mu.Unlock()
		d.wg.Go(func() {
			defer func() {
				d.mu.Lock()
				delete(d.conns, c)
				d.mu.Unlock()
				_ = nc.Close()
			}()
			_ = c.serve()
		})
	}
}

// packet is one message.
type packet struct {
	typ  uint16
	data []byte
}

func msg(typ uint16, m proto.Message) packet {
	data, _ := proto.Marshal(m)
	return packet{typ: typ, data: data}
}

// conn is one client.
type conn struct {
	d  *Device
	nc net.Conn
	r  *bufio.Reader

	wmu     sync.Mutex
	encrypt *noise.CipherState
	decrypt *noise.CipherState

	// subscribed and authed are guarded by d.mu.
	subscribed bool
	pinged     bool
}

func (c *conn) serve() error {
	if c.d.psk != nil {
		if err := c.handshake(); err != nil {
			return err
		}
	}
	stop := make(chan struct{})
	defer close(stop)
	if every := c.d.cfg.PingEvery; every > 0 {
		c.d.wg.Go(func() { c.pingLoop(every, stop) })
	}
	authed := c.d.cfg.Password == ""
	for {
		p, err := c.read()
		if err != nil {
			return err
		}
		switch p.typ {
		case 1: // HelloRequest
			if err := c.send(msg(2, &esphomev1.HelloResponse{
				ApiVersionMajor: 1, ApiVersionMinor: 10, ServerInfo: "esphomemock", Name: c.d.cfg.Name,
			})); err != nil {
				return err
			}
		case 3: // AuthenticationRequest
			var m esphomev1.AuthenticationRequest
			_ = proto.Unmarshal(p.data, &m)
			if m.GetPassword() != c.d.cfg.Password {
				_ = c.send(msg(4, &esphomev1.AuthenticationResponse{InvalidPassword: true}))
				return errors.New("invalid password")
			}
			authed = true
		case 5: // DisconnectRequest
			_ = c.send(msg(6, &esphomev1.DisconnectResponse{}))
			return nil
		case 7: // PingRequest
			if err := c.send(msg(8, &esphomev1.PingResponse{})); err != nil {
				return err
			}
		case 8: // PingResponse
			c.d.mu.Lock()
			c.d.pongs++
			c.pinged = false
			c.d.mu.Unlock()
		case 9: // DeviceInfoRequest
			if err := c.send(msg(10, &esphomev1.DeviceInfoResponse{
				Name: c.d.cfg.Name, MacAddress: c.d.cfg.MAC, EsphomeVersion: "2026.11.0", Model: "esp32dev",
				Manufacturer: "Espressif", FriendlyName: c.d.cfg.Name,
			})); err != nil {
				return err
			}
		case 11, 20, 33, 62:
			if !authed {
				// A device drops a client that skips the login.
				return errors.New("unauthenticated")
			}
			if err := c.handle(p); err != nil {
				return err
			}
		}
	}
}

// handle serves the messages that need a login.
func (c *conn) handle(p packet) error {
	switch p.typ {
	case 11: // ListEntitiesRequest
		var pkts []packet
		for _, e := range c.d.cfg.Entities {
			pkts = append(pkts, listPacket(e))
		}
		pkts = append(pkts, msg(19, &esphomev1.ListEntitiesDoneResponse{}))
		return c.send(pkts...)
	case 20: // SubscribeStatesRequest
		c.d.mu.Lock()
		c.subscribed = true
		c.d.mu.Unlock()
		var pkts []packet
		for _, e := range c.d.cfg.Entities {
			if sp, ok := c.d.statePacket(e.Key); ok {
				pkts = append(pkts, sp)
			}
		}
		return c.send(pkts...)
	case 33: // SwitchCommandRequest
		var m esphomev1.SwitchCommandRequest
		if err := proto.Unmarshal(p.data, &m); err != nil {
			return err
		}
		c.d.mu.Lock()
		c.d.commands = append(c.d.commands, Command{Key: m.GetKey(), Kind: Switch, On: m.GetState()})
		c.d.mu.Unlock()
		// A switch reports its new state, as a real one does.
		c.d.SetState(m.GetKey(), m.GetState())
	case 62: // ButtonCommandRequest
		var m esphomev1.ButtonCommandRequest
		if err := proto.Unmarshal(p.data, &m); err != nil {
			return err
		}
		c.d.mu.Lock()
		c.d.commands = append(c.d.commands, Command{Key: m.GetKey(), Kind: Button})
		c.d.mu.Unlock()
	}
	return nil
}

func (c *conn) pingLoop(every time.Duration, stop <-chan struct{}) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
		}
		c.d.mu.Lock()
		missed := c.pinged
		c.pinged = true
		c.d.mu.Unlock()
		if missed {
			// No answer to the last ping: drop the client, as a device does.
			_ = c.nc.Close()
			return
		}
		if c.send(msg(7, &esphomev1.PingRequest{})) != nil {
			return
		}
	}
}

func listPacket(e Entity) packet {
	switch e.Kind {
	case Sensor:
		return msg(16, &esphomev1.ListEntitiesSensorResponse{
			ObjectId: e.ObjectID, Key: e.Key, Name: e.Name, UnitOfMeasurement: e.Unit, AccuracyDecimals: 1,
		})
	case BinarySensor:
		return msg(12, &esphomev1.ListEntitiesBinarySensorResponse{ObjectId: e.ObjectID, Key: e.Key, Name: e.Name})
	case Switch:
		return msg(17, &esphomev1.ListEntitiesSwitchResponse{ObjectId: e.ObjectID, Key: e.Key, Name: e.Name})
	case Button:
		return msg(61, &esphomev1.ListEntitiesButtonResponse{ObjectId: e.ObjectID, Key: e.Key, Name: e.Name})
	case TextSensor:
		return msg(18, &esphomev1.ListEntitiesTextSensorResponse{ObjectId: e.ObjectID, Key: e.Key, Name: e.Name})
	}
	panic(fmt.Sprintf("esphomemock: unknown kind %q", e.Kind))
}

// statePacket is entity key's current state message; ok is false for a
// button, which has none.
func (d *Device) statePacket(key uint32) (packet, bool) {
	d.mu.Lock()
	state := d.states[key]
	d.mu.Unlock()
	for _, e := range d.cfg.Entities {
		if e.Key != key {
			continue
		}
		switch e.Kind {
		case Sensor:
			v, ok := state.(float32)
			return msg(25, &esphomev1.SensorStateResponse{Key: key, State: v, MissingState: !ok}), true
		case BinarySensor:
			v, ok := state.(bool)
			return msg(21, &esphomev1.BinarySensorStateResponse{Key: key, State: v, MissingState: !ok}), true
		case Switch:
			v, ok := state.(bool)
			return msg(26, &esphomev1.SwitchStateResponse{Key: key, State: v, MissingState: !ok}), true
		case TextSensor:
			v, ok := state.(string)
			return msg(27, &esphomev1.TextSensorStateResponse{Key: key, State: v, MissingState: !ok}), true
		}
	}
	return packet{}, false
}

// The framing, the device's side of it.

func (c *conn) read() (packet, error) {
	if c.decrypt == nil {
		return c.readPlain()
	}
	frame, err := c.readNoiseFrame()
	if err != nil {
		return packet{}, err
	}
	m, err := c.decrypt.Decrypt(nil, nil, frame)
	if err != nil || len(m) < 4 {
		return packet{}, errors.New("bad encrypted frame")
	}
	n := int(binary.BigEndian.Uint16(m[2:4]))
	if n > len(m)-4 {
		return packet{}, errors.New("bad encrypted frame length")
	}
	return packet{typ: binary.BigEndian.Uint16(m[:2]), data: m[4 : 4+n]}, nil
}

func (c *conn) readPlain() (packet, error) {
	b, err := c.r.ReadByte()
	if err != nil {
		return packet{}, err
	}
	if b != 0x00 {
		// A Noise client on a plaintext device: answer as the device does,
		// in plaintext, and close.
		_ = c.send(msg(5, &esphomev1.DisconnectRequest{}))
		return packet{}, errors.New("not plaintext")
	}
	size, err := binary.ReadUvarint(c.r)
	if err != nil {
		return packet{}, err
	}
	typ, err := binary.ReadUvarint(c.r)
	if err != nil {
		return packet{}, err
	}
	data := make([]byte, size)
	if _, err := io.ReadFull(c.r, data); err != nil {
		return packet{}, err
	}
	return packet{typ: uint16(typ), data: data}, nil //nolint:gosec // a test fake
}

func (c *conn) readNoiseFrame() ([]byte, error) {
	var hdr [3]byte
	if _, err := io.ReadFull(c.r, hdr[:]); err != nil {
		return nil, err
	}
	if hdr[0] != 0x01 {
		return nil, fmt.Errorf("bad indicator byte %d", hdr[0])
	}
	frame := make([]byte, binary.BigEndian.Uint16(hdr[1:]))
	if _, err := io.ReadFull(c.r, frame); err != nil {
		return nil, err
	}
	return frame, nil
}

func (c *conn) writeNoiseFrame(frame []byte) error {
	out := binary.BigEndian.AppendUint16([]byte{0x01}, uint16(len(frame))) //nolint:gosec // a test fake
	_, err := c.nc.Write(append(out, frame...))
	return err
}

// handshake is the responder's side of the Noise handshake.
func (c *conn) handshake() error {
	hello, err := c.readNoiseFrame()
	if err != nil {
		// A plaintext client: the device rejects it in a Noise frame.
		_ = c.writeNoiseFrame(append([]byte{0x01}, "Bad indicator byte"...))
		return err
	}
	prologue := binary.BigEndian.AppendUint16([]byte("NoiseAPIInit"), uint16(len(hello))) //nolint:gosec // a test fake
	prologue = append(prologue, hello...)
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite: noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256),
		Pattern:     noise.HandshakeNN, Initiator: false, Prologue: prologue,
		PresharedKey: c.d.psk, PresharedKeyPlacement: 0,
	})
	if err != nil {
		return err
	}
	var sh bytes.Buffer
	sh.WriteByte(0x01)
	sh.WriteString(c.d.cfg.Name)
	sh.WriteByte(0)
	sh.WriteString(c.d.cfg.MAC)
	sh.WriteByte(0)
	if err := c.writeNoiseFrame(sh.Bytes()); err != nil {
		return err
	}
	frame, err := c.readNoiseFrame()
	if err != nil {
		return err
	}
	if len(frame) == 0 || frame[0] != 0x00 {
		_ = c.writeNoiseFrame(append([]byte{0x01}, "Bad handshake error byte"...))
		return errors.New("bad handshake error byte")
	}
	if _, _, _, err := hs.ReadMessage(nil, frame[1:]); err != nil {
		_ = c.writeNoiseFrame(append([]byte{0x01}, "Handshake MAC failure"...))
		return errors.New("handshake MAC failure")
	}
	out, recv, send, err := hs.WriteMessage(nil, nil)
	if err != nil {
		return err
	}
	if err := c.writeNoiseFrame(append([]byte{0x00}, out...)); err != nil {
		return err
	}
	c.encrypt, c.decrypt = send, recv
	return nil
}

func (c *conn) send(pkts ...packet) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.encrypt == nil {
		var buf bytes.Buffer
		for _, p := range pkts {
			buf.WriteByte(0x00)
			buf.Write(binary.AppendUvarint(nil, uint64(len(p.data))))
			buf.Write(binary.AppendUvarint(nil, uint64(p.typ)))
			buf.Write(p.data)
		}
		_, err := c.nc.Write(buf.Bytes())
		return err
	}
	var out []byte
	for _, p := range pkts {
		m := binary.BigEndian.AppendUint16(nil, p.typ)
		m = binary.BigEndian.AppendUint16(m, uint16(len(p.data))) //nolint:gosec // a test fake
		frame, err := c.encrypt.Encrypt(nil, nil, append(m, p.data...))
		if err != nil {
			return err
		}
		out = binary.BigEndian.AppendUint16(append(out, 0x01), uint16(len(frame))) //nolint:gosec // a test fake
		out = append(out, frame...)
	}
	_, err := c.nc.Write(out)
	return err
}
