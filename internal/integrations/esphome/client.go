// SPDX-License-Identifier: AGPL-3.0-only

package esphome

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	esphomev1 "github.com/gvart/hearth/internal/proto/hearth/esphome/v1"
)

// Message type IDs, the "(id)" options of ESPHome's api.proto.
const (
	msgHelloRequest              = 1
	msgHelloResponse             = 2
	msgAuthenticationRequest     = 3
	msgAuthenticationResponse    = 4
	msgDisconnectRequest         = 5
	msgDisconnectResponse        = 6
	msgPingRequest               = 7
	msgPingResponse              = 8
	msgDeviceInfoRequest         = 9
	msgDeviceInfoResponse        = 10
	msgListEntitiesRequest       = 11
	msgListBinarySensor          = 12
	msgListSensor                = 16
	msgListSwitch                = 17
	msgListTextSensor            = 18
	msgListEntitiesDone          = 19
	msgSubscribeStatesRequest    = 20
	msgBinarySensorState         = 21
	msgSensorState               = 25
	msgSwitchState               = 26
	msgTextSensorState           = 27
	msgSwitchCommandRequest      = 33
	msgListButton                = 61
	msgButtonCommandRequest      = 62
	apiVersionMajor              = 1
	apiVersionMinor              = 10
	clientInfo                   = "Hearth"
	defaultHandshakeTimeout      = 10 * time.Second
	defaultKeepalive             = 20 * time.Second
	keepaliveMisses              = 3
	maxEntities                  = 256
	maxText                      = 255
	clientInfoAPIVersionMismatch = "incompatible API version"
)

// Entity kinds.
const (
	KindSensor       = "sensor"
	KindBinarySensor = "binary_sensor"
	KindSwitch       = "switch"
	KindButton       = "button"
	KindTextSensor   = "text_sensor"
)

// Errors of a session.
var (
	// ErrInvalidPassword is returned when firmware older than ESPHome 2026.1
	// rejects the API password.
	ErrInvalidPassword = errors.New("the device rejected the API password")
	// ErrClosed is returned when the device closes the session.
	ErrClosed = errors.New("the device closed the connection")
)

// Entity is one thing of an ESPHome device: a sensor, a binary sensor, a
// switch, a button or a text sensor.
type Entity struct {
	// Key is the device's ID of the entity, a hash of its object ID.
	Key      uint32 `json:"key"`
	ObjectID string `json:"object_id"`
	Name     string `json:"name"`
	// Kind is sensor, binary_sensor, switch, button or text_sensor.
	Kind        string `json:"kind"`
	Unit        string `json:"unit,omitempty"`
	DeviceClass string `json:"device_class,omitempty"`
	// Decimals is how many decimals the device shows of a sensor's value.
	Decimals int `json:"accuracy_decimals,omitempty"`
	// State is a number for a sensor, a boolean for a binary sensor or a
	// switch, text for a text sensor; null while the device has none, and
	// always for a button.
	State any `json:"state"`
}

// deviceInfo is what a device says of itself.
type deviceInfo struct {
	Name, FriendlyName, MAC, Version, Model, Manufacturer string
}

// session is one connection to a device, once it is set up.
type session struct {
	conn net.Conn
	f    framer
	info deviceInfo
	// entities are those the device listed, in its order.
	entities  []Entity
	keepalive time.Duration

	wmu sync.Mutex
}

// dialOptions tunes a session; tests shorten them.
type dialOptions struct {
	handshakeTimeout time.Duration
	keepalive        time.Duration
}

// dial connects to the device of c, runs the handshake, says hello, logs in
// on firmware that takes a password, and reads the device's info and
// entities. It then subscribes to their states: call run to receive them.
func dial(ctx context.Context, c Connection, opts dialOptions) (*session, error) {
	if opts.handshakeTimeout <= 0 {
		opts.handshakeTimeout = defaultHandshakeTimeout
	}
	if opts.keepalive <= 0 {
		opts.keepalive = defaultKeepalive
	}
	d := net.Dialer{Timeout: opts.handshakeTimeout}
	conn, err := d.DialContext(ctx, "tcp", c.Address)
	if err != nil {
		return nil, err
	}
	s, err := setUp(ctx, conn, c, opts)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return s, nil
}

func setUp(ctx context.Context, conn net.Conn, c Connection, opts dialOptions) (*session, error) {
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer stop()
	_ = conn.SetDeadline(time.Now().Add(opts.handshakeTimeout))
	s := &session{conn: conn, keepalive: opts.keepalive}
	if c.Key == "" {
		s.f = newPlainFramer(conn)
	} else {
		psk, err := decodeKey(c.Key)
		if err != nil {
			return nil, err
		}
		nf, _, err := noiseHandshake(conn, psk)
		if err != nil {
			return nil, err
		}
		s.f = nf
	}
	// As aioesphomeapi does, the login goes with the hello: firmware older
	// than ESPHome 2026.1 needs it, even without a password, and answers
	// only a wrong password; newer firmware ignores it.
	if err := s.send(
		msg(msgHelloRequest, &esphomev1.HelloRequest{
			ClientInfo: clientInfo, ApiVersionMajor: apiVersionMajor, ApiVersionMinor: apiVersionMinor,
		}),
		msg(msgAuthenticationRequest, &esphomev1.AuthenticationRequest{Password: c.Password}),
		msg(msgDeviceInfoRequest, &esphomev1.DeviceInfoRequest{}),
		msg(msgListEntitiesRequest, &esphomev1.ListEntitiesRequest{}),
	); err != nil {
		return nil, err
	}
	hello := false
	for {
		p, err := s.f.read()
		if err != nil {
			return nil, setUpError(ctx, err)
		}
		done, err := s.setUpPacket(p, &hello)
		if err != nil {
			return nil, err
		}
		if done {
			break
		}
	}
	if !hello {
		return nil, fmt.Errorf("%w: entities listed before the hello", ErrProtocol)
	}
	if err := s.send(msg(msgSubscribeStatesRequest, &esphomev1.SubscribeStatesRequest{})); err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	return s, nil
}

// setUpError says what a read that failed during set-up means: a device that
// closes the connection on a wrong password, before it answers, is told
// apart by the caller.
func setUpError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return ErrClosed
	}
	return err
}

// setUpPacket handles one packet before the entity list is done, and reports
// whether it was its end.
func (s *session) setUpPacket(p packet, hello *bool) (bool, error) {
	switch p.typ {
	case msgHelloResponse:
		var m esphomev1.HelloResponse
		if err := proto.Unmarshal(p.data, &m); err != nil {
			return false, fmt.Errorf("%w: hello: %w", ErrProtocol, err)
		}
		if m.GetApiVersionMajor() != apiVersionMajor {
			return false, fmt.Errorf("%w: %s %d.%d", ErrProtocol, clientInfoAPIVersionMismatch,
				m.GetApiVersionMajor(), m.GetApiVersionMinor())
		}
		*hello = true
	case msgAuthenticationResponse:
		var m esphomev1.AuthenticationResponse
		if err := proto.Unmarshal(p.data, &m); err != nil {
			return false, fmt.Errorf("%w: login: %w", ErrProtocol, err)
		}
		if m.GetInvalidPassword() {
			return false, ErrInvalidPassword
		}
	case msgDeviceInfoResponse:
		var m esphomev1.DeviceInfoResponse
		if err := proto.Unmarshal(p.data, &m); err != nil {
			return false, fmt.Errorf("%w: device info: %w", ErrProtocol, err)
		}
		s.info = deviceInfo{
			Name: clip(m.GetName()), FriendlyName: clip(m.GetFriendlyName()), MAC: clip(m.GetMacAddress()),
			Version: clip(m.GetEsphomeVersion()), Model: clip(m.GetModel()), Manufacturer: clip(m.GetManufacturer()),
		}
	case msgListEntitiesDone:
		return true, nil
	case msgPingRequest, msgDisconnectRequest:
		return false, s.answer(p)
	default:
		e, ok, err := listedEntity(p)
		if err != nil {
			return false, err
		}
		if ok {
			if len(s.entities) >= maxEntities {
				return false, fmt.Errorf("%w: more than %d entities", ErrProtocol, maxEntities)
			}
			s.entities = append(s.entities, e)
		}
	}
	return false, nil
}

// answer answers the device's ping or disconnect request.
func (s *session) answer(p packet) error {
	switch p.typ {
	case msgPingRequest:
		return s.send(msg(msgPingResponse, &esphomev1.PingResponse{}))
	case msgDisconnectRequest:
		_ = s.send(msg(msgDisconnectResponse, &esphomev1.DisconnectResponse{}))
		return ErrClosed
	}
	return nil
}

// run reads the session until ctx is done or the connection fails, handing
// each state to onState and answering the device's pings. It pings the device
// itself every keepalive, and gives up when nothing arrives for
// keepaliveMisses of them: a device that lost power never closes the
// connection.
func (s *session) run(ctx context.Context, onState func(stateUpdate)) error {
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(ctx, func() { _ = s.conn.SetDeadline(time.Now()) })
	var wg sync.WaitGroup
	defer func() {
		cancel()
		wg.Wait()
		stop()
	}()
	wg.Go(func() {
		t := time.NewTicker(s.keepalive)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if s.send(msg(msgPingRequest, &esphomev1.PingRequest{})) != nil {
					cancel()
					return
				}
			}
		}
	})
	for {
		_ = s.conn.SetReadDeadline(time.Now().Add(keepaliveMisses * s.keepalive))
		p, err := s.f.read()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return ErrClosed
			}
			return err
		}
		switch p.typ {
		case msgPingRequest, msgDisconnectRequest:
			if err := s.answer(p); err != nil {
				return err
			}
			continue
		}
		u, ok, err := decodeState(p)
		if err != nil {
			return err
		}
		if ok {
			onState(u)
		}
	}
}

// switchCommand turns switch key on or off.
func (s *session) switchCommand(key uint32, on bool) error {
	return s.send(msg(msgSwitchCommandRequest, &esphomev1.SwitchCommandRequest{Key: key, State: on}))
}

// pressButton presses button key.
func (s *session) pressButton(key uint32) error {
	return s.send(msg(msgButtonCommandRequest, &esphomev1.ButtonCommandRequest{Key: key}))
}

// close says goodbye and closes the connection.
func (s *session) close() {
	_ = s.conn.SetWriteDeadline(time.Now().Add(time.Second))
	_ = s.send(msg(msgDisconnectRequest, &esphomev1.DisconnectRequest{}))
	_ = s.conn.Close()
}

// send writes pkts in one go; it is safe for concurrent use.
func (s *session) send(pkts ...packet) error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	return s.f.write(pkts...)
}

// msg encodes m as a packet of type typ. The hub's own messages always
// encode.
func msg(typ uint16, m proto.Message) packet {
	data, _ := proto.Marshal(m)
	return packet{typ: typ, data: data}
}
