// SPDX-License-Identifier: AGPL-3.0-only

package esphome

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/integrations/esphome/esphomemock"
	"github.com/gvart/hearth/internal/integrations/kubernetes"
	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

const webActor = "192.0.2.1"

type fixture struct {
	m      *Manager
	st     *store.Store
	sealer *kubernetes.Sealer
	logs   *syncBuffer
}

// syncBuffer is a log sink safe for the manager's goroutines.
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

// newFixture runs a manager with the policy configuration cfg on a fresh
// store.
func newFixture(t *testing.T, cfg policy.Config) *fixture {
	t.Helper()
	st, err := store.Open(t.Context(), filepath.Join(t.TempDir(), "hearth.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	sealer, err := kubernetes.NewPurposeSealer([]byte("test CA key"), SealInfo)
	if err != nil {
		t.Fatal(err)
	}
	logs := &syncBuffer{}
	m := NewManager(Config{
		Store: st, Sealer: sealer, Policy: policy.NewWithConfig(st.Audit(), st.Approvals(), cfg),
		Log:          slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		SyncInterval: 20 * time.Millisecond, retry: 20 * time.Millisecond,
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- m.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Run: %v", err)
		}
	})
	return &fixture{m: m, st: st, sealer: sealer, logs: logs}
}

func (f *fixture) add(t *testing.T, dev *esphomemock.Device, key string, control bool) DeviceInfo {
	t.Helper()
	info, err := f.m.Add(t.Context(), webActor, AddRequest{Name: "kitchen", Address: dev.Addr(), Key: key, Control: control})
	if err != nil {
		t.Fatal(err)
	}
	return info
}

// waitSnapshot waits for device id's snapshot to satisfy ok.
func (f *fixture) waitSnapshot(t *testing.T, id, what string, ok func(Snapshot) bool) Snapshot {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		s, err := f.m.Snapshot(id)
		if err == nil && ok(s) {
			return s
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s: %+v, %v", what, s, err)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func stateOf(s Snapshot, objectID string) any {
	for _, e := range s.Entities {
		if e.ObjectID == objectID {
			return e.State
		}
	}
	return "absent"
}

func (f *fixture) audit(t *testing.T, action policy.Action) []store.AuditEntry {
	t.Helper()
	entries, err := f.st.Audit().Query(t.Context(), store.AuditFilter{Actions: []string{string(action)}}, 50)
	if err != nil {
		t.Fatal(err)
	}
	return entries
}

func TestReadsEntitiesLive(t *testing.T) {
	for _, key := range []string{testKey, ""} {
		t.Run(map[string]string{testKey: "noise", "": "plaintext"}[key], func(t *testing.T) {
			f := newFixture(t, policy.Config{})
			dev := startFake(t, esphomemock.Config{Key: key})
			info := f.add(t, dev, key, false)
			s := f.waitSnapshot(t, info.ID, "the temperature", func(s Snapshot) bool { return stateOf(s, "temperature") == 21.3 })
			if s.Device.State != StateConnected || s.Device.MAC != "AC:BC:32:89:0E:A9" || s.Device.Entities != 5 ||
				s.Device.Encryption != map[string]string{testKey: EncryptionNoise, "": EncryptionPlaintext}[key] {
				t.Errorf("device = %+v", s.Device)
			}
			dev.SetState(1, float32(19.5))
			f.waitSnapshot(t, info.ID, "the new temperature", func(s Snapshot) bool { return stateOf(s, "temperature") == 19.5 })

			// A device that reboots is read again.
			dev.DropClients()
			f.waitSnapshot(t, info.ID, "the device back", func(s Snapshot) bool {
				return s.Device.State == StateConnected && stateOf(s, "temperature") == 19.5
			})
		})
	}
}

func TestWrongKeyIsUnavailable(t *testing.T) {
	f := newFixture(t, policy.Config{})
	dev := startFake(t, esphomemock.Config{Key: testKey})
	info := f.add(t, dev, otherKey, false)
	s := f.waitSnapshot(t, info.ID, "the refusal", func(s Snapshot) bool { return s.Device.State == StateUnavailable })
	if s.Device.Error != ErrInvalidKey.Error() || len(s.Entities) != 0 {
		t.Errorf("device = %+v, entities %v; want the key refused, none shown", s.Device, s.Entities)
	}
}

func TestCalls(t *testing.T) {
	f := newFixture(t, policy.Config{})
	dev := startFake(t, esphomemock.Config{Key: testKey})
	info := f.add(t, dev, testKey, true)
	f.waitSnapshot(t, info.ID, "the relay", func(s Snapshot) bool { return stateOf(s, "relay") == false })

	res, err := f.m.Call(t.Context(), policy.ActorWeb, webActor, info.ID, CallRequest{Key: 3, Action: ActionOn})
	if err != nil {
		t.Fatal(err)
	}
	if res.Class != "safe" || res.Target != "kitchen/relay" {
		t.Errorf("result = %+v", res)
	}
	f.waitSnapshot(t, info.ID, "the relay on", func(s Snapshot) bool { return stateOf(s, "relay") == true })
	if _, err := f.m.Call(t.Context(), policy.ActorWeb, webActor, info.ID, CallRequest{Key: 4, Action: ActionPress}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the button press", func() bool { return len(dev.Commands()) == 2 })
	if got := dev.Commands()[1]; got != (esphomemock.Command{Key: 4, Kind: esphomemock.Button}) {
		t.Errorf("second command = %+v", got)
	}
	audited := f.audit(t, policy.ESPHomeCall)
	if len(audited) != 2 {
		t.Fatalf("audit = %+v, want two calls", audited)
	}
	for _, e := range audited {
		if e.Decision != policy.Allow || !strings.HasPrefix(e.Target, "kitchen/") {
			t.Errorf("audit entry = %+v", e)
		}
	}
}

func TestCallsRefused(t *testing.T) {
	denyAll := policy.Config{Classes: map[policy.Class]policy.Mode{policy.Safe: policy.ModeDeny, policy.Dangerous: policy.ModeDeny}}
	for _, tc := range []struct {
		name    string
		cfg     policy.Config
		control bool
		kind    string
		req     CallRequest
		want    error
		audited bool
	}{
		{"read-only by default", policy.Config{}, false, policy.ActorWeb, CallRequest{Key: 3, Action: ActionOn}, ErrReadOnly, true},
		{"policy denied", denyAll, true, policy.ActorWeb, CallRequest{Key: 3, Action: ActionOn}, policy.ErrDenied, true},
		{"an automation may not", policy.Config{}, true, policy.ActorAutomation, CallRequest{Key: 3, Action: ActionOn}, policy.ErrDenied, true},
		{"an MCP client may not", policy.Config{}, true, policy.ActorMCP, CallRequest{Key: 4, Action: ActionPress}, policy.ErrDenied, true},
		{"unknown entity", policy.Config{}, true, policy.ActorWeb, CallRequest{Key: 99, Action: ActionOn}, ErrEntityNotFound, false},
		{"press a switch", policy.Config{}, true, policy.ActorWeb, CallRequest{Key: 3, Action: ActionPress}, ErrBadAction, false},
		{"switch a sensor", policy.Config{}, true, policy.ActorWeb, CallRequest{Key: 1, Action: ActionOn}, ErrBadAction, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, tc.cfg)
			dev := startFake(t, esphomemock.Config{Key: testKey})
			info := f.seed(t, dev, tc.control)
			f.waitSnapshot(t, info, "connected", func(s Snapshot) bool { return stateOf(s, "relay") == false })
			_, err := f.m.Call(t.Context(), tc.kind, webActor, info, tc.req)
			if !errors.Is(err, tc.want) {
				t.Fatalf("Call = %v, want %v", err, tc.want)
			}
			audited := f.audit(t, policy.ESPHomeCall)
			if tc.audited && (len(audited) != 1 || audited[0].Decision != policy.Deny) {
				t.Errorf("audit = %+v, want one denial", audited)
			}
			if !tc.audited && len(audited) != 0 {
				t.Errorf("audit = %+v, want none", audited)
			}
			time.Sleep(50 * time.Millisecond)
			if got := dev.Commands(); len(got) != 0 {
				t.Errorf("a refused call reached the device: %v", got)
			}
		})
	}
	t.Run("unknown device", func(t *testing.T) {
		f := newFixture(t, policy.Config{})
		if _, err := f.m.Call(t.Context(), policy.ActorWeb, webActor, "nope", CallRequest{Key: 3, Action: ActionOn}); !errors.Is(err, ErrNotFound) {
			t.Fatalf("Call = %v, want ErrNotFound", err)
		}
	})
	t.Run("unavailable device", func(t *testing.T) {
		f := newFixture(t, policy.Config{})
		dev := startFake(t, esphomemock.Config{Key: testKey})
		info := f.add(t, dev, otherKey, true)
		f.waitSnapshot(t, info.ID, "the refusal", func(s Snapshot) bool { return s.Device.State == StateUnavailable })
		if _, err := f.m.Call(t.Context(), policy.ActorWeb, webActor, info.ID, CallRequest{Key: 3, Action: ActionOn}); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("Call = %v, want ErrUnavailable", err)
		}
	})
}

// seed stores a device without going through policy, for configurations that
// deny adding one.
func (f *fixture) seed(t *testing.T, dev *esphomemock.Device, control bool) string {
	t.Helper()
	raw, err := json.Marshal(Connection{Address: dev.Addr(), Key: testKey, Control: control}) //nolint:gosec // a test key
	if err != nil {
		t.Fatal(err)
	}
	id := store.ESPHomeDeviceID("kitchen")
	sealed, err := f.sealer.Seal(id, raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.st.ESPHomeDevices().Add(t.Context(), store.ESPHomeDevice{ID: id, Name: "kitchen", Sealed: sealed, CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	return id
}

func TestKeyIsSealedAndNeverServed(t *testing.T) {
	f := newFixture(t, policy.Config{})
	dev := startFake(t, esphomemock.Config{Key: testKey})
	info := f.add(t, dev, testKey, true)
	f.waitSnapshot(t, info.ID, "connected", func(s Snapshot) bool { return s.Device.State == StateConnected })

	rows, err := f.st.ESPHomeDevices().List(t.Context())
	if err != nil || len(rows) != 1 {
		t.Fatalf("rows = %v, %v", rows, err)
	}
	if bytes.Contains(rows[0].Sealed, []byte(testKey)) {
		t.Error("the stored connection holds the key in the clear")
	}
	if _, err := f.sealer.Open("another-row", rows[0].Sealed); err == nil {
		t.Error("the sealed connection opened for another row")
	}
	snap, err := f.m.Snapshot(info.ID)
	if err != nil {
		t.Fatal(err)
	}
	served, err := json.Marshal([]any{snap, f.m.Devices(), info})
	if err != nil {
		t.Fatal(err)
	}
	entries, err := f.st.Audit().List(t.Context(), 50)
	if err != nil {
		t.Fatal(err)
	}
	audit, err := json.Marshal(entries)
	if err != nil {
		t.Fatal(err)
	}
	for name, b := range map[string][]byte{"API": served, "audit log": audit, "log": []byte(f.logs.String())} {
		if bytes.Contains(b, []byte(testKey)) {
			t.Errorf("the %s holds the key", name)
		}
	}
}

func TestAddAndRemove(t *testing.T) {
	f := newFixture(t, policy.Config{})
	dev := startFake(t, esphomemock.Config{})
	for _, tc := range []struct {
		req  AddRequest
		want error
	}{
		{AddRequest{Name: "", Address: dev.Addr()}, ErrBadName},
		{AddRequest{Name: "a\x00b", Address: dev.Addr()}, ErrBadName},
		{AddRequest{Name: "kitchen", Address: "kitchen.local"}, ErrBadConnection},
		{AddRequest{Name: "kitchen", Address: dev.Addr(), Key: "short"}, ErrBadConnection},
	} {
		if _, err := f.m.Add(t.Context(), webActor, tc.req); !errors.Is(err, tc.want) {
			t.Errorf("Add(%+v) = %v, want %v", tc.req, err, tc.want)
		}
	}
	info := f.add(t, dev, "", false)
	if _, err := f.m.Add(t.Context(), webActor, AddRequest{Name: "kitchen", Address: dev.Addr()}); !errors.Is(err, ErrNameTaken) {
		t.Errorf("second Add = %v, want ErrNameTaken", err)
	}
	f.waitSnapshot(t, info.ID, "connected", func(s Snapshot) bool { return s.Device.State == StateConnected })
	if err := f.m.Remove(t.Context(), webActor, info.ID); err != nil {
		t.Fatal(err)
	}
	if err := f.m.Remove(t.Context(), webActor, info.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("second Remove = %v, want ErrNotFound", err)
	}
	waitFor(t, "the device forgotten", func() bool { _, err := f.m.Snapshot(info.ID); return errors.Is(err, ErrNotFound) })
	waitFor(t, "the connection closed", func() bool { return dev.Clients() == 0 })
	for _, a := range []policy.Action{policy.ESPHomeDeviceAdd, policy.ESPHomeDeviceRemove} {
		if len(f.audit(t, a)) == 0 {
			t.Errorf("%s not audited", a)
		}
	}
}
