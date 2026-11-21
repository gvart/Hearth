// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/automation"
	"github.com/gvart/hearth/internal/pki"
	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

// TestMergedDeviceReachesTheUI: a device row merged from another master of
// an AP cluster is a device.updated on this master's UI event stream, and
// only for the devices table's live rows (#266).
func TestMergedDeviceReachesTheUI(t *testing.T) {
	st := newTestStore(t)
	enrollDevice(t, st, "pi")
	ca, err := pki.LoadOrCreateCA(t.TempDir(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.DiscardHandler)
	reg := NewRegistry(RegistryConfig{Store: st, Log: log})
	web := httptest.NewServer(NewHTTPHandler(Config{Store: st, CA: ca, Policy: policy.New(st.Audit()), Log: log, Registry: reg}))
	t.Cleanup(web.Close)
	if err := st.Admin().CreateSession(t.Context(), "s", time.Now(), time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, web.URL+"/api/v1/events", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(testCookie("s"))
	resp, err := web.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	events, subscribed := readSSE(t, resp.Body)
	select {
	case <-subscribed:
	case <-time.After(2 * time.Second):
		t.Fatal("no subscription confirmation")
	}

	// Rows that are no live device tell the UI nothing; the device does.
	reg.Merged([]store.MergedRow{
		{Table: "tokens", Key: []any{"x"}},
		{Table: "devices", Key: []any{"gone"}, Deleted: true},
		{Table: "devices", Key: []any{"missing"}},
		{Table: "devices", Key: []any{"pi"}},
	})
	ev := waitEvent(t, events, EventDeviceUpdated, 2*time.Second)
	if ev.data.Device.ID != "pi" || ev.data.Device.Name != "pi-name" {
		t.Fatalf("merged event device = %+v", ev.data.Device)
	}
	select {
	case e := <-events:
		t.Fatalf("an extra event %s for %s", e.name, e.data.Device.ID)
	case <-time.After(200 * time.Millisecond):
	}
}

// TestMergedDeviceFiresNoTrigger: the automations' device trigger hears this
// master's own presence events, never a merged row, whatever its status: a
// device trigger fires once, on the master the agent streams to (#266).
func TestMergedDeviceFiresNoTrigger(t *testing.T) {
	st := newTestStore(t)
	now := time.Now()
	for _, d := range []store.Device{
		{ID: "on", Name: "on", FirstSeen: now, LastSeen: now, Status: store.StatusOnline},
		{ID: "off", Name: "off", FirstSeen: now, LastSeen: now, Status: store.StatusOffline},
	} {
		if err := st.Devices().Upsert(t.Context(), d); err != nil {
			t.Fatal(err)
		}
	}
	reg := NewRegistry(RegistryConfig{Store: st, Log: slog.New(slog.DiscardHandler)})
	fired := make(chan automation.DeviceEvent, 8)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = AutomationDevices(reg).WatchDevices(ctx, func(e automation.DeviceEvent) { fired <- e })
	}()
	t.Cleanup(func() { cancel(); <-done })
	waitFor(t, "the trigger to subscribe", func() bool { return reg.bus.active() })
	// The bus the automation engine reads carries no merged row of any type.
	bus, unsubscribe := reg.Subscribe()
	defer unsubscribe()

	reg.Merged([]store.MergedRow{{Table: "devices", Key: []any{"on"}}, {Table: "devices", Key: []any{"off"}}})
	// This master's own event, after the merged ones, proves the watcher
	// was live for them.
	reg.publish(t.Context(), Event{Type: EventDeviceOnline, Device: store.Device{ID: "local"}})
	select {
	case e := <-fired:
		if e.ID != "local" {
			t.Fatalf("a merged row fired the device trigger: %+v", e)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the device trigger missed this master's own event")
	}
	select {
	case e := <-fired:
		t.Fatalf("an extra trigger: %+v", e)
	case <-time.After(200 * time.Millisecond):
	}
	if e := <-bus; e.Device.ID != "local" {
		t.Fatalf("the automation bus carried a merged row: %s %s", e.Type, e.Device.ID)
	}
}
