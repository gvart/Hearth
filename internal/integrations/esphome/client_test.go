// SPDX-License-Identifier: AGPL-3.0-only

package esphome

import (
	"bufio"
	"bytes"
	"errors"
	"math"
	"sync"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/integrations/esphome/esphomemock"
)

// testKey is a key as ESPHome's YAML has it: base64 of 32 bytes.
const (
	testKey  = "px7tsbK3C7bpXHr2OevEV2ZMg/FrNBw2+O2pNPbedtA="
	otherKey = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
)

func testEntities() []esphomemock.Entity {
	return []esphomemock.Entity{
		{Key: 1, ObjectID: "temperature", Name: "Temperature", Kind: esphomemock.Sensor, Unit: "°C", State: float32(21.3)},
		{Key: 2, ObjectID: "motion", Name: "Motion", Kind: esphomemock.BinarySensor, State: true},
		{Key: 3, ObjectID: "relay", Name: "Relay", Kind: esphomemock.Switch, State: false},
		{Key: 4, ObjectID: "restart", Name: "Restart", Kind: esphomemock.Button},
		{Key: 5, ObjectID: "humidity", Name: "Humidity", Kind: esphomemock.Sensor, Unit: "%"},
	}
}

func startFake(t *testing.T, cfg esphomemock.Config) *esphomemock.Device {
	t.Helper()
	if cfg.Name == "" {
		cfg.Name = "kitchen"
	}
	if cfg.MAC == "" {
		cfg.MAC = "AC:BC:32:89:0E:A9"
	}
	if cfg.Entities == nil {
		cfg.Entities = testEntities()
	}
	d, err := esphomemock.Start(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Close)
	return d
}

// states collects what a session hands run.
type states struct {
	mu sync.Mutex
	m  map[uint32]any
}

func (s *states) put(u stateUpdate) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.m == nil {
		s.m = map[uint32]any{}
	}
	s.m[u.key] = u.state
}

func (s *states) get(key uint32) (any, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.m[key]
	return v, ok
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestSession(t *testing.T) {
	for _, tc := range []struct {
		name string
		key  string
	}{
		{"noise", testKey},
		{"plaintext", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dev := startFake(t, esphomemock.Config{Key: tc.key, PingEvery: 50 * time.Millisecond})
			s, err := dial(t.Context(), Connection{Address: dev.Addr(), Key: tc.key}, dialOptions{})
			if err != nil {
				t.Fatal(err)
			}
			defer s.close()
			if s.info.Name != "kitchen" || s.info.MAC != "AC:BC:32:89:0E:A9" || s.info.Version != "2026.11.0" {
				t.Errorf("info = %+v", s.info)
			}
			if len(s.entities) != 5 || s.entities[0].Kind != KindSensor || s.entities[0].Unit != "°C" ||
				s.entities[3].Kind != KindButton {
				t.Fatalf("entities = %+v", s.entities)
			}
			var got states
			done := make(chan error, 1)
			go func() { done <- s.run(t.Context(), got.put) }()
			waitFor(t, "the first states", func() bool { _, ok := got.get(3); return ok })
			if v, _ := got.get(1); v != 21.3 {
				t.Errorf("temperature = %v, want 21.3", v)
			}
			if v, ok := got.get(5); !ok || v != nil {
				t.Errorf("humidity = %v, %v; want a null state", v, ok)
			}
			dev.SetState(1, float32(22.5))
			waitFor(t, "the new temperature", func() bool { v, _ := got.get(1); return v == 22.5 })
			// The device drops a client that leaves its pings unanswered.
			waitFor(t, "pings answered", func() bool { return dev.Pongs() >= 3 })

			if err := s.switchCommand(3, true); err != nil {
				t.Fatal(err)
			}
			if err := s.pressButton(4); err != nil {
				t.Fatal(err)
			}
			waitFor(t, "the switch's new state", func() bool { v, _ := got.get(3); return v == true })
			cmds := dev.Commands()
			want := []esphomemock.Command{{Key: 3, Kind: esphomemock.Switch, On: true}, {Key: 4, Kind: esphomemock.Button}}
			if len(cmds) != 2 || cmds[0] != want[0] || cmds[1] != want[1] {
				t.Errorf("commands = %+v, want %+v", cmds, want)
			}
			dev.DropClients()
			select {
			case err := <-done:
				if !errors.Is(err, ErrClosed) {
					t.Errorf("run after the device dropped it = %v, want ErrClosed", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("run did not end when the device dropped it")
			}
		})
	}
}

func TestSessionRefused(t *testing.T) {
	for _, tc := range []struct {
		name   string
		device esphomemock.Config
		conn   Connection
		want   error
	}{
		{"wrong key", esphomemock.Config{Key: testKey}, Connection{Key: otherKey}, ErrInvalidKey},
		{"no key for a noise device", esphomemock.Config{Key: testKey}, Connection{}, ErrNeedsKey},
		{"a key for a plaintext device", esphomemock.Config{}, Connection{Key: testKey}, ErrNotEncrypted},
		{"wrong password", esphomemock.Config{Password: "hunter2"}, Connection{Password: "nope"}, ErrInvalidPassword},
		{"no password", esphomemock.Config{Password: "hunter2"}, Connection{}, ErrInvalidPassword},
		{"malformed key", esphomemock.Config{Key: testKey}, Connection{Key: "c2hvcnQ="}, ErrBadConnection},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dev := startFake(t, tc.device)
			tc.conn.Address = dev.Addr()
			s, err := dial(t.Context(), tc.conn, dialOptions{handshakeTimeout: 2 * time.Second})
			if err == nil {
				s.close()
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("dial = %v, want %v", err, tc.want)
			}
		})
	}
	t.Run("right password", func(t *testing.T) {
		dev := startFake(t, esphomemock.Config{Password: "hunter2"})
		s, err := dial(t.Context(), Connection{Address: dev.Addr(), Password: "hunter2"}, dialOptions{})
		if err != nil {
			t.Fatal(err)
		}
		s.close()
	})
}

func TestPlainFrameLimits(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   []byte
	}{
		{"oversized", append([]byte{0x00}, 0xff, 0xff, 0xff, 0x7f, 0x01)},
		{"bad preamble", []byte{0x07, 0x00, 0x01}},
		{"type beyond 16 bits", []byte{0x00, 0x00, 0xff, 0xff, 0x7f}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := readPlain(bufio.NewReader(bytes.NewReader(tc.in))); !errors.Is(err, ErrProtocol) {
				t.Fatalf("readPlain = %v, want ErrProtocol", err)
			}
		})
	}
	p, err := readPlain(bufio.NewReader(bytes.NewReader(encodePlain(packet{typ: 300, data: []byte("hi")}))))
	if err != nil || p.typ != 300 || string(p.data) != "hi" {
		t.Fatalf("round trip = %+v, %v", p, err)
	}
}

func TestSensorValue(t *testing.T) {
	for _, tc := range []struct {
		in      float32
		missing bool
		want    any
	}{
		{21.3, false, 21.3},
		{float32(math.NaN()), false, nil},
		{float32(math.Inf(1)), false, nil},
		{1, true, nil},
	} {
		if got := sensorValue(tc.in, tc.missing); got != tc.want {
			t.Errorf("sensorValue(%v, %v) = %v, want %v", tc.in, tc.missing, got, tc.want)
		}
	}
}

func TestConnectionNormalize(t *testing.T) {
	for _, tc := range []struct {
		in      Connection
		want    string
		wantErr bool
	}{
		{Connection{Address: "192.168.1.40"}, "192.168.1.40:6053", false},
		{Connection{Address: " 192.168.1.40:7000 "}, "192.168.1.40:7000", false},
		{Connection{Address: "fe80::1"}, "[fe80::1]:6053", false},
		{Connection{Address: "kitchen.local"}, "", true},
		{Connection{Address: "kitchen.local:6053"}, "", true},
		{Connection{Address: "192.168.1.40:0"}, "", true},
		{Connection{Address: ""}, "", true},
		{Connection{Address: "192.168.1.40", Key: "nope"}, "", true},
		{Connection{Address: "192.168.1.40", Key: testKey, Password: "x"}, "", true},
	} {
		got, err := tc.in.normalize()
		if (err != nil) != tc.wantErr || (err == nil && got.Address != tc.want) {
			t.Errorf("normalize(%+v) = %+v, %v; want %q (error %v)", tc.in, got, err, tc.want, tc.wantErr)
		}
		if err != nil && !errors.Is(err, ErrBadConnection) {
			t.Errorf("normalize(%+v) = %v, want ErrBadConnection", tc.in, err)
		}
		if err != nil && tc.in.Key != "" && bytes.Contains([]byte(err.Error()), []byte(tc.in.Key)) {
			t.Errorf("the error quotes the key: %v", err)
		}
	}
}
