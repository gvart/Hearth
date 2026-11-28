// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"context"
	"encoding/json"
	"errors"
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
	// users are the MQTT users RemoveUser finds; removed, those it took
	// out; removeErr, its error.
	users     map[string]bool
	removed   []string
	removeErr error
}

func (b *fakeBus) RemoveUser(id string) (bool, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.removeErr != nil {
		return false, b.removeErr
	}
	had := b.users[id]
	delete(b.users, id)
	b.removed = append(b.removed, id)
	b.up = false
	return had, nil
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
	// The result, and an error naming the device's message.
	if r := f.do(t, http.MethodPost, path, `{"command":"restart"}`, cookie); r.StatusCode != http.StatusBadGateway ||
		!strings.Contains(string(r.body), `"error":"the device answered that the command failed: done"`) ||
		!strings.Contains(string(r.body), `"ok":false`) {
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

// TestDeviceProtocolRemoveAPI: removing a Device Protocol device takes the
// password again, policy and its audit; it removes the MQTT user first, then
// the device, and what the hub queued of it, so a pending announce does not
// bring it back. An enrolled device is not removed.
func TestDeviceProtocolRemoveAPI(t *testing.T) {
	ctx := t.Context()
	st := newTestStore(t)
	log := slog.New(slog.DiscardHandler)
	reg := NewRegistry(RegistryConfig{Store: st, Log: log})
	pol := policy.NewWithConfig(st.Audit(), st.Approvals(), policy.Config{})
	// No Run: the test writes what p queued, with applyOps and flushValues.
	p := NewDeviceProtocol(DeviceProtocolConfig{Store: st, Registry: reg, Policy: pol, Log: log})
	bus := &fakeBus{p: p, up: true, ok: true, users: map[string]bool{"kitchen": true}}
	p.SetBus(bus)
	announce := func() {
		m, err := deviceproto.Parse("kitchen", deviceproto.KindAnnounce,
			[]byte(`{"v":1,"name":"Kitchen","entities":[{"id":"t","kind":"sensor"}]}`))
		if err != nil {
			t.Fatal(err)
		}
		p.DeviceMessage(m)
	}
	announce()
	p.applyOps(ctx)
	id := store.ProtocolDeviceID("kitchen")
	if _, err := st.Devices().Get(ctx, id); err != nil {
		t.Fatalf("the announce did not register the device: %v", err)
	}
	now := time.Now()
	if err := st.Devices().Upsert(ctx, store.Device{ID: "agentdevice0000000000", Name: "pi", FirstSeen: now, LastSeen: now, Status: store.StatusOnline}); err != nil {
		t.Fatal(err)
	}

	a := newAPI(Config{Store: st, Policy: pol, Log: log, Registry: reg, DeviceProtocol: p})
	srv := httptest.NewServer(a.routes())
	t.Cleanup(srv.Close)
	if err := st.Admin().CreateSession(ctx, "rm-session", time.Now(), time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	f := &apiFixture{srv: srv, st: st}
	cookie := testCookie("rm-session")
	path := "/api/v1/devices/" + id
	audits := func() []string {
		t.Helper()
		entries, err := st.Audit().List(ctx, 50)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, e := range entries {
			if e.Action == string(policy.DeviceRemove) {
				out = append(out, e.Decision+":"+e.Result)
			}
		}
		return out
	}
	stillThere := func(what string) {
		t.Helper()
		if _, err := st.Devices().Get(ctx, id); err != nil {
			t.Fatalf("%s: the device is gone: %v", what, err)
		}
		bus.mu.Lock()
		defer bus.mu.Unlock()
		if len(bus.removed) != 0 {
			t.Fatalf("%s: MQTT users removed: %v", what, bus.removed)
		}
	}

	if r := f.do(t, http.MethodDelete, path, "", nil); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("without a session: %d", r.StatusCode)
	}
	if r := f.do(t, http.MethodDelete, path, "", cookie); r.StatusCode != http.StatusForbidden ||
		!strings.Contains(string(r.body), "reauth_required") {
		t.Fatalf("without re-authentication: %d %s", r.StatusCode, r.body)
	}
	stillThere("without re-authentication")
	a.reauths.mark("rm-session", a.now())
	for _, tt := range []struct{ name, path string }{
		{"unknown device", "/api/v1/devices/0000000000000000"},
		{"enrolled device", "/api/v1/devices/agentdevice0000000000"},
	} {
		if r := f.do(t, http.MethodDelete, tt.path, "", cookie); r.StatusCode != http.StatusNotFound {
			t.Fatalf("%s: %d %s", tt.name, r.StatusCode, r.body)
		}
	}
	if _, err := st.Devices().Get(ctx, "agentdevice0000000000"); err != nil {
		t.Fatalf("the enrolled device is gone: %v", err)
	}

	pol.SetConfig(policy.Config{Classes: map[policy.Class]policy.Mode{policy.Dangerous: policy.ModeDeny}})
	if r := f.do(t, http.MethodDelete, path, "", cookie); r.StatusCode != http.StatusForbidden ||
		!strings.Contains(string(r.body), `"forbidden"`) {
		t.Fatalf("denied: %d %s", r.StatusCode, r.body)
	}
	stillThere("denied")
	pol.SetConfig(policy.Config{})

	bus.mu.Lock()
	bus.removeErr = errors.New("clients file read-only")
	bus.mu.Unlock()
	if r := f.do(t, http.MethodDelete, path, "", cookie); r.StatusCode != http.StatusInternalServerError {
		t.Fatalf("clients file not written: %d %s", r.StatusCode, r.body)
	}
	stillThere("clients file not written")
	bus.mu.Lock()
	bus.removeErr = nil
	bus.mu.Unlock()

	// An announce and readings wait to be written when it is removed.
	announce()
	p.DeviceMessage(deviceproto.Message{Device: "kitchen", Kind: deviceproto.KindState, Values: map[string]any{"t": 21.5}})
	r := f.do(t, http.MethodDelete, path, "", cookie)
	var res RemoveResult
	if err := json.Unmarshal(r.body, &res); err != nil || r.StatusCode != http.StatusOK || !res.MQTTUserRemoved ||
		res.ID != id || res.Class != "dangerous" {
		t.Fatalf("remove: %d %s", r.StatusCode, r.body)
	}
	p.applyOps(ctx)
	p.flushValues(ctx)
	if _, err := st.Devices().Get(ctx, id); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("removed device: %v, want not found", err)
	}
	bus.mu.Lock()
	if strings.Join(bus.removed, ",") != "kitchen" {
		t.Errorf("MQTT users removed: %v, want kitchen", bus.removed)
	}
	bus.mu.Unlock()
	if r := f.do(t, http.MethodDelete, path, "", cookie); r.StatusCode != http.StatusNotFound {
		t.Fatalf("removed again: %d %s", r.StatusCode, r.body)
	}
	// Newest first: the removal, the failed write, the policy's denial, the
	// one for want of the password.
	got := audits()
	want := []string{"allow:ok", "allow:error: remove its MQTT user", "deny:dangerous actions", "deny:the admin password"}
	if len(got) != len(want) {
		t.Fatalf("audit of device.remove = %v", got)
	}
	for i := range want {
		if !strings.HasPrefix(got[i], want[i]) {
			t.Fatalf("audit of device.remove = %v, want %v", got, want)
		}
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
