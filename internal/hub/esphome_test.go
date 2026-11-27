// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/integrations/esphome"
	"github.com/gvart/hearth/internal/integrations/esphome/esphomemock"
	"github.com/gvart/hearth/internal/integrations/kubernetes"
	"github.com/gvart/hearth/internal/policy"
)

const esphomeTestKey = "px7tsbK3C7bpXHr2OevEV2ZMg/FrNBw2+O2pNPbedtA="

type esphomeAPIFixture struct {
	f      *apiFixture
	cookie *http.Cookie
	dev    *esphomemock.Device
}

func newESPHomeAPIFixture(t *testing.T, cfg policy.Config) *esphomeAPIFixture {
	t.Helper()
	dev, err := esphomemock.Start(esphomemock.Config{
		Name: "kitchen", MAC: "AC:BC:32:89:0E:A9", Key: esphomeTestKey,
		Entities: []esphomemock.Entity{
			{Key: 1, ObjectID: "temperature", Name: "Temperature", Kind: esphomemock.Sensor, Unit: "°C", State: float32(21.3)},
			{Key: 3, ObjectID: "relay", Name: "Relay", Kind: esphomemock.Switch, State: false},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(dev.Close)
	st := newTestStore(t)
	log := slog.New(slog.DiscardHandler)
	sealer, err := kubernetes.NewPurposeSealer([]byte("test CA key"), esphome.SealInfo)
	if err != nil {
		t.Fatal(err)
	}
	pol := policy.NewWithConfig(st.Audit(), st.Approvals(), cfg)
	m := esphome.NewManager(esphome.Config{Store: st, Sealer: sealer, Policy: pol, Log: log, SyncInterval: 20 * time.Millisecond})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = m.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-done })

	a := newAPI(Config{Store: st, Policy: pol, Log: log, Registry: NewRegistry(RegistryConfig{Store: st, Log: log}), ESPHome: m})
	srv := httptest.NewServer(a.routes())
	t.Cleanup(srv.Close)
	if err := st.Admin().CreateSession(t.Context(), "esp-session", time.Now(), time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	return &esphomeAPIFixture{f: &apiFixture{srv: srv, st: st}, cookie: testCookie("esp-session"), dev: dev}
}

func (e *esphomeAPIFixture) post(t *testing.T, path string, body any) (int, string) {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	r := e.f.do(t, http.MethodPost, path, string(b), e.cookie)
	return r.StatusCode, string(r.body)
}

func (e *esphomeAPIFixture) add(t *testing.T, control bool) esphome.DeviceInfo {
	t.Helper()
	code, body := e.post(t, "/api/v1/esphome/devices", esphome.AddRequest{
		Name: "kitchen", Address: e.dev.Addr(), Key: esphomeTestKey, Control: control,
	})
	if code != http.StatusCreated {
		t.Fatalf("add = %d %s", code, body)
	}
	return decodeBody[esphome.DeviceInfo](t, body)
}

func decodeBody[T any](t *testing.T, body string) T {
	t.Helper()
	var v T
	if err := json.Unmarshal([]byte(body), &v); err != nil {
		t.Fatalf("decode %s: %v", body, err)
	}
	return v
}

// waitEntity waits until the hub API shows entity objectID of device id
// with state want, and returns the snapshot.
func (e *esphomeAPIFixture) waitEntity(t *testing.T, id, objectID string, want any) esphome.Snapshot {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		r := e.f.do(t, http.MethodGet, "/api/v1/esphome/devices/"+id, "", e.cookie)
		snap := decodeBody[esphome.Snapshot](t, string(r.body))
		for _, en := range snap.Entities {
			if en.ObjectID == objectID && en.State == want {
				return snap
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s never showed %v: %s", objectID, want, r.body)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// The issue's "done when": an ESPHome sensor appears as an entity, its value
// read from the device and served by the hub API, kept live.
func TestESPHomeSensorAppearsAsAnEntity(t *testing.T) {
	e := newESPHomeAPIFixture(t, policy.Config{})
	for _, path := range []string{"/api/v1/esphome/devices", "/api/v1/esphome/devices/x"} {
		if r := e.f.do(t, http.MethodGet, path, "", nil); r.StatusCode != http.StatusUnauthorized {
			t.Errorf("unauthenticated GET %s = %d", path, r.StatusCode)
		}
	}
	if r := e.f.do(t, http.MethodPost, "/api/v1/esphome/devices/x/call", `{"key":3,"action":"on"}`, nil); r.StatusCode != http.StatusUnauthorized {
		t.Errorf("unauthenticated call = %d", r.StatusCode)
	}

	info := e.add(t, false)
	snap := e.waitEntity(t, info.ID, "temperature", 21.3)
	if snap.Device.State != esphome.StateConnected || snap.Device.Encryption != esphome.EncryptionNoise || snap.CallClass != "safe" {
		t.Errorf("snapshot = %+v", snap)
	}
	var temp esphome.Entity
	for _, en := range snap.Entities {
		if en.ObjectID == "temperature" {
			temp = en
		}
	}
	if temp.Kind != esphome.KindSensor || temp.Unit != "°C" || temp.Name != "Temperature" {
		t.Errorf("temperature = %+v", temp)
	}
	e.dev.SetState(1, float32(23.75))
	e.waitEntity(t, info.ID, "temperature", 23.75)

	for _, path := range []string{"/api/v1/esphome/devices", "/api/v1/esphome/devices/" + info.ID} {
		r := e.f.do(t, http.MethodGet, path, "", e.cookie)
		if r.StatusCode != http.StatusOK || strings.Contains(string(r.body), esphomeTestKey) {
			t.Errorf("GET %s = %d, serving the key: %v", path, r.StatusCode, strings.Contains(string(r.body), esphomeTestKey))
		}
	}

	// Read-only by default: the call is refused, and nothing reaches the device.
	code, body := e.post(t, "/api/v1/esphome/devices/"+info.ID+"/call", esphome.CallRequest{Key: 3, Action: esphome.ActionOn})
	if code != http.StatusForbidden || !strings.Contains(body, "read_only") {
		t.Errorf("call to a read-only device = %d %s", code, body)
	}
	if got := e.dev.Commands(); len(got) != 0 {
		t.Errorf("a refused call reached the device: %v", got)
	}
	if r := e.f.do(t, http.MethodDelete, "/api/v1/esphome/devices/"+info.ID, "", e.cookie); r.StatusCode != http.StatusNoContent {
		t.Errorf("delete = %d %s", r.StatusCode, r.body)
	}
}

func TestESPHomeAPICalls(t *testing.T) {
	e := newESPHomeAPIFixture(t, policy.Config{})
	info := e.add(t, true)
	e.waitEntity(t, info.ID, "relay", false)
	code, body := e.post(t, "/api/v1/esphome/devices/"+info.ID+"/call", esphome.CallRequest{Key: 3, Action: esphome.ActionOn})
	if code != http.StatusOK || !strings.Contains(body, `"class":"safe"`) {
		t.Fatalf("call = %d %s", code, body)
	}
	e.waitEntity(t, info.ID, "relay", true)

	for name, tc := range map[string]struct {
		path string
		body any
		want int
	}{
		"unknown entity":  {"/api/v1/esphome/devices/" + info.ID + "/call", esphome.CallRequest{Key: 99, Action: esphome.ActionOn}, http.StatusNotFound},
		"bad action":      {"/api/v1/esphome/devices/" + info.ID + "/call", esphome.CallRequest{Key: 3, Action: "explode"}, http.StatusBadRequest},
		"unknown device":  {"/api/v1/esphome/devices/nope/call", esphome.CallRequest{Key: 3, Action: esphome.ActionOn}, http.StatusNotFound},
		"taken name":      {"/api/v1/esphome/devices", esphome.AddRequest{Name: "kitchen", Address: "192.168.1.9"}, http.StatusConflict},
		"host name":       {"/api/v1/esphome/devices", esphome.AddRequest{Name: "porch", Address: "porch.local"}, http.StatusBadRequest},
		"malformed key":   {"/api/v1/esphome/devices", esphome.AddRequest{Name: "porch", Address: "192.168.1.9", Key: "pasted-by-mistake"}, http.StatusBadRequest},
		"sensor switched": {"/api/v1/esphome/devices/" + info.ID + "/call", esphome.CallRequest{Key: 1, Action: esphome.ActionOn}, http.StatusBadRequest},
	} {
		code, body := e.post(t, tc.path, tc.body)
		if code != tc.want {
			t.Errorf("%s = %d %s, want %d", name, code, body, tc.want)
		}
		if strings.Contains(body, "pasted-by-mistake") {
			t.Errorf("%s: the answer quotes the key: %s", name, body)
		}
	}
	if got := e.dev.Commands(); len(got) != 1 {
		t.Errorf("commands = %v, want the one allowed call", got)
	}
}
