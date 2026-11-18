// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/automation"
	"github.com/gvart/hearth/internal/integrations/prometheus"
	"github.com/gvart/hearth/internal/store"
)

func TestAutomationDevices(t *testing.T) {
	ctx := t.Context()
	st := newTestStore(t)
	enrollDevice(t, st, "pi")
	clk := newFakeClock()
	reg := NewRegistry(RegistryConfig{Store: st, OfflineAfter: 30 * time.Second, Now: clk.Now})

	got := make(chan automation.DeviceEvent, 10)
	done := make(chan error, 1)
	wctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go func() {
		done <- AutomationDevices(reg).WatchDevices(wctx, func(e automation.DeviceEvent) { got <- e })
	}()
	next := func() automation.DeviceEvent {
		t.Helper()
		select {
		case e := <-got:
			return e
		case <-time.After(5 * time.Second):
			t.Fatal("no device event")
			return automation.DeviceEvent{}
		}
	}
	// The watcher subscribes in the background.
	waitSubscribed(t, reg)

	if err := reg.ReportFacts(ctx, "pi", testHello()); err != nil {
		t.Fatal(err)
	}
	if e := next(); e != (automation.DeviceEvent{ID: "pi", Name: "pi-name", Hostname: "pi", Online: true}) {
		t.Errorf("event = %+v, want pi online", e)
	}
	// Updates are not presence changes.
	if err := reg.ReportFacts(ctx, "pi", testHello()); err != nil {
		t.Fatal(err)
	}
	// A restore ends every subscription; the watcher subscribes again.
	reg.Restored()
	waitSubscribed(t, reg)
	clk.Advance(31 * time.Second)
	if err := reg.Sweep(ctx); err != nil {
		t.Fatal(err)
	}
	if e := next(); e.ID != "pi" || e.Online {
		t.Errorf("event = %+v, want pi offline", e)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("WatchDevices = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("WatchDevices did not stop")
	}
}

// waitSubscribed waits until someone subscribes to reg's events.
func waitSubscribed(t *testing.T, reg *Registry) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !reg.bus.active() {
		if time.Now().After(deadline) {
			t.Fatal("nobody subscribed")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestAutomationMetrics(t *testing.T) {
	if m := AutomationMetrics(newTestStore(t), nil); m != nil {
		t.Fatalf("metrics without Prometheus = %v, want nil", m)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		q := r.Form.Get("query")
		w.Header().Set("Content-Type", "application/json")
		var result string
		switch {
		case q == "node_uname_info":
			result = `{"metric":{"instance":"192.168.2.131:9100","nodename":"raspberrypi"},"value":[1700000000,"1"]}`
		case strings.Contains(q, `node_cpu_seconds_total{instance="192.168.2.131:9100"`):
			result = `{"metric":{},"value":[1700000000,"93.5"]}`
		case q == `up{job="pihole"}`:
			result = `{"metric":{"instance":"a"},"value":[1700000000,"1"]},{"metric":{"instance":"b"},"value":[1700000000,"0"]}`
		}
		fmt.Fprintf(w, `{"status":"success","data":{"resultType":"vector","result":[%s]}}`, result)
	}))
	defer srv.Close()
	c, err := prometheus.NewClient(srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	st := newTestStore(t)
	addDevice(t, st, "d1", "raspberrypi", "192.168.2.131/24")
	m := AutomationMetrics(st, prometheus.NewReader(c))

	for _, ref := range []string{"d1", "raspberrypi", "RaspberryPi"} {
		v, err := m.DeviceMetric(t.Context(), ref, "cpu")
		if err != nil || v != 93.5 {
			t.Errorf("DeviceMetric(%s, cpu) = %v, %v; want 93.5", ref, v, err)
		}
	}
	if _, err := m.DeviceMetric(t.Context(), "nas", "cpu"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("unknown device: err = %v, want ErrNotFound", err)
	}
	if _, err := m.DeviceMetric(t.Context(), "d1", "memory"); !errors.Is(err, prometheus.ErrNoData) {
		t.Errorf("no memory series: err = %v, want ErrNoData", err)
	}
	vs, err := m.Query(t.Context(), `up{job="pihole"}`)
	if err != nil || len(vs) != 2 || vs[0] != 1 || vs[1] != 0 {
		t.Errorf("Query = %v, %v; want [1 0]", vs, err)
	}
}
