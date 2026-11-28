// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/deviceproto"
	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

// fakeBus answers every command at once, with ok, unless the device is not
// connected.
type fakeBus struct {
	p    *DeviceProtocol
	mu   sync.Mutex
	up   bool
	ok   bool
	sent int
}

func (b *fakeBus) Connected(string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.up
}

func (b *fakeBus) PublishCommand(id string, payload []byte) error {
	var cmd deviceproto.Command
	if err := json.Unmarshal(payload, &cmd); err != nil {
		return err
	}
	b.mu.Lock()
	b.sent++
	ok := b.ok
	b.mu.Unlock()
	go b.p.DeviceMessage(deviceproto.Message{Device: id, Kind: deviceproto.KindResult, Result: &deviceproto.Result{V: 1, ID: cmd.ID, OK: ok, Message: "done"}})
	return nil
}

func TestDeviceProtocolCommandAPI(t *testing.T) {
	st := newTestStore(t)
	log := slog.New(slog.DiscardHandler)
	reg := NewRegistry(RegistryConfig{Store: st, Log: log})
	pol := policy.NewWithConfig(st.Audit(), st.Approvals(), policy.Config{})
	p := NewDeviceProtocol(DeviceProtocolConfig{Store: st, Registry: reg, Policy: pol, Log: log, CommandTimeout: time.Second})
	bus := &fakeBus{p: p, up: true, ok: true}
	p.SetBus(bus)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = p.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-done })

	m, err := deviceproto.Parse("kitchen", deviceproto.KindAnnounce, []byte(`{"v":1,"commands":[{"name":"restart"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	p.DeviceMessage(m)
	id := store.ProtocolDeviceID("kitchen")
	deadline := time.Now().Add(5 * time.Second)
	for {
		if d, err := st.Devices().Get(t.Context(), id); err == nil && d.Name == "kitchen" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the announce did not register the device")
		}
		time.Sleep(10 * time.Millisecond)
	}

	a := newAPI(Config{Store: st, Policy: pol, Log: log, Registry: reg, DeviceProtocol: p})
	srv := httptest.NewServer(a.routes())
	t.Cleanup(srv.Close)
	if err := st.Admin().CreateSession(t.Context(), "proto-session", time.Now(), time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	f := &apiFixture{srv: srv, st: st}
	cookie := testCookie("proto-session")
	path := "/api/v1/devices/" + id + "/commands"

	if r := f.do(t, http.MethodPost, path, `{"command":"restart"}`, nil); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("without a session: %d", r.StatusCode)
	}
	if r := f.send(t, http.MethodPost, path, "text/plain", `{"command":"restart"}`, cookie); r.StatusCode != http.StatusUnsupportedMediaType {
		t.Fatalf("text body: %d", r.StatusCode)
	}
	// A dangerous action: the password again first.
	if r := f.do(t, http.MethodPost, path, `{"command":"restart"}`, cookie); r.StatusCode != http.StatusForbidden ||
		!strings.Contains(string(r.body), "reauth_required") {
		t.Fatalf("without re-authentication: %d %s", r.StatusCode, r.body)
	}
	a.reauths.mark("proto-session", a.now())
	r := f.do(t, http.MethodPost, path, `{"command":"restart"}`, cookie)
	var res CommandResult
	if err := json.Unmarshal(r.body, &res); err != nil || r.StatusCode != http.StatusOK || !res.OK || res.Class != "dangerous" {
		t.Fatalf("command: %d %s", r.StatusCode, r.body)
	}
	for _, tt := range []struct {
		name, path, body string
		want             int
	}{
		{"unknown device", "/api/v1/devices/0000000000000000/commands", `{"command":"restart"}`, http.StatusNotFound},
		{"undeclared command", path, `{"command":"reboot"}`, http.StatusBadRequest},
		{"bad params", path, `{"command":"restart","params":"x"}`, http.StatusBadRequest},
		{"not JSON", path, `{`, http.StatusBadRequest},
	} {
		if r := f.do(t, http.MethodPost, tt.path, tt.body, cookie); r.StatusCode != tt.want {
			t.Errorf("%s: %d %s, want %d", tt.name, r.StatusCode, r.body, tt.want)
		}
	}

	bus.mu.Lock()
	bus.ok = false
	bus.mu.Unlock()
	if r := f.do(t, http.MethodPost, path, `{"command":"restart"}`, cookie); r.StatusCode != http.StatusBadGateway {
		t.Fatalf("failed command: %d %s", r.StatusCode, r.body)
	}
	bus.mu.Lock()
	bus.up = false
	bus.mu.Unlock()
	if r := f.do(t, http.MethodPost, path, `{"command":"restart"}`, cookie); r.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("not connected: %d %s", r.StatusCode, r.body)
	}
	bus.mu.Lock()
	bus.up = true
	bus.mu.Unlock()
	pol.SetConfig(policy.Config{Classes: map[policy.Class]policy.Mode{policy.Dangerous: policy.ModeDeny}})
	if r := f.do(t, http.MethodPost, path, `{"command":"restart"}`, cookie); r.StatusCode != http.StatusForbidden {
		t.Fatalf("denied: %d %s", r.StatusCode, r.body)
	}
	// A hub without the device protocol has no such endpoint.
	off := httptest.NewServer(newAPI(Config{Store: st, Policy: pol, Log: log, Registry: reg}).routes())
	t.Cleanup(off.Close)
	if r := (&apiFixture{srv: off, st: st}).do(t, http.MethodPost, path, `{"command":"restart"}`, cookie); r.StatusCode != http.StatusNotFound {
		t.Fatalf("without the device protocol: %d", r.StatusCode)
	}
	bus.mu.Lock()
	defer bus.mu.Unlock()
	if bus.sent != 2 {
		t.Fatalf("%d commands published, want 2: the refused ones must publish nothing", bus.sent)
	}
}

// TestDeviceProtocolMissedDeparture: a device that leaves before its announce
// is written, or whose departure is lost, ends offline and stays so.
func TestDeviceProtocolMissedDeparture(t *testing.T) {
	st := newTestStore(t)
	reg := NewRegistry(RegistryConfig{Store: st})
	p := NewDeviceProtocol(DeviceProtocolConfig{Store: st, Registry: reg, Policy: policy.New(st.Audit()), Seen: 10 * time.Millisecond})
	bus := &fakeBus{p: p, up: false}
	p.SetBus(bus)
	m, err := deviceproto.Parse("kitchen", deviceproto.KindAnnounce, []byte(`{"v":1}`))
	if err != nil {
		t.Fatal(err)
	}
	// The announce is queued, and the device gone, before Run writes it.
	p.DeviceMessage(m)
	p.DeviceGone("kitchen")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = p.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-done })
	id := store.ProtocolDeviceID("kitchen")
	deadline := time.Now().Add(5 * time.Second)
	for {
		d, err := st.Devices().Get(t.Context(), id)
		if err == nil && d.Status == store.StatusOffline {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("device = %+v, %v, want offline", d, err)
		}
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond) // a few Seen ticks
	if d, err := st.Devices().Get(t.Context(), id); err != nil || d.Status != store.StatusOffline {
		t.Fatalf("device = %+v, %v, want still offline", d, err)
	}

	// Online, then its connection ends with no departure seen: the next
	// Seen tick marks it offline.
	bus.mu.Lock()
	bus.up = true
	bus.mu.Unlock()
	p.DeviceMessage(m)
	for {
		d, err := st.Devices().Get(t.Context(), id)
		if err == nil && d.Status == store.StatusOnline {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("device = %+v, %v, want online", d, err)
		}
		time.Sleep(5 * time.Millisecond)
	}
	bus.mu.Lock()
	bus.up = false
	bus.mu.Unlock()
	for {
		d, err := st.Devices().Get(t.Context(), id)
		if err == nil && d.Status == store.StatusOffline {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("device = %+v, %v, want offline again", d, err)
		}
		time.Sleep(5 * time.Millisecond)
	}
}
