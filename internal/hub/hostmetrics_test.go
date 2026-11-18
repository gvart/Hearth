// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"errors"
	"log/slog"
	"maps"
	"math"
	"net/http"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/metrics"
	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
	"github.com/gvart/hearth/internal/store"
)

func newMetricsStore(t *testing.T) *metrics.Store {
	t.Helper()
	ms, err := metrics.Open(t.Context(), filepath.Join(t.TempDir(), "metrics.db"), nil, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ms.Close() })
	return ms
}

func TestRecordMetrics(t *testing.T) {
	ms := newMetricsStore(t)
	log := slog.New(slog.DiscardHandler)
	s := NewAgentStream(log, time.Second, NewRegistry(RegistryConfig{Store: newTestStore(t), Log: log}))
	s.metrics = ms
	s.recordMetrics(t.Context(), log, "pi", &agentv1.MetricsBatch{Samples: []*agentv1.MetricSample{
		{Name: "cpu", Value: 12.5},
		{Name: "memory", Value: math.NaN()},
		{Name: "disk", Value: math.Inf(1)},
		{Name: "my_custom_series", Value: 1},
	}})
	if v, err := ms.Latest(t.Context(), "pi", "cpu", time.Minute); err != nil || v != 12.5 {
		t.Errorf("cpu = %v, %v; want 12.5", v, err)
	}
	for _, name := range []string{"memory", "disk", "my_custom_series"} {
		if _, err := ms.Latest(t.Context(), "pi", name, time.Minute); !errors.Is(err, metrics.ErrNoData) {
			t.Errorf("%s: err = %v, want ErrNoData (dropped)", name, err)
		}
	}
}

func TestDeviceMetricsBuiltin(t *testing.T) {
	prom := fakePrometheus(t)
	tests := []struct {
		name       string
		withProm   bool
		path       string
		wantHTTP   int
		wantSource string
		wantStatus string
		wantCharts []string
	}{
		{"default", false, "", http.StatusOK, sourceBuiltin, metricsOK, []string{"cpu", "memory"}},
		{"names", false, "?names=memory", http.StatusOK, sourceBuiltin, metricsOK, []string{"memory"}},
		{"week", false, "?range=168h", http.StatusOK, sourceBuiltin, metricsOK, []string{"cpu", "memory"}},
		{"no data", false, "?names=temperature", http.StatusOK, sourceBuiltin, metricsNoData, nil},
		{"unknown name", false, "?names=cpu,bogus", http.StatusBadRequest, "", "", nil},
		{"bad source", false, "?source=influx", http.StatusBadRequest, "", "", nil},
		{"prometheus by default when configured", true, "", http.StatusOK, sourcePrometheus, metricsOK, []string{"cpu", "memory", "disk"}},
		{"prometheus names", true, "?names=disk", http.StatusOK, sourcePrometheus, metricsOK, []string{"disk"}},
		{"builtin on request", true, "?source=builtin", http.StatusOK, sourceBuiltin, metricsOK, []string{"cpu", "memory"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ms := newMetricsStore(t)
			opts := []func(*Config){func(c *Config) { c.Metrics = ms }}
			if tt.withProm {
				opts = append(opts, withPrometheus(t, prom.URL))
			}
			f := newAPIFixture(t, true, opts...)
			addDevice(t, f.st, "pi", "raspberrypi", "192.168.2.131/24")
			now := time.Now()
			for i := range 3 {
				at := now.Add(-time.Duration(i) * 15 * time.Second)
				if err := ms.Write(t.Context(), "pi", at, []metrics.Sample{{Name: "cpu", Value: 10}, {Name: "memory", Value: 40}}); err != nil {
					t.Fatal(err)
				}
			}
			cookie := sessionCookie(t, f.login(t, testPassword))
			resp := f.do(t, http.MethodGet, "/api/v1/devices/pi/metrics"+tt.path, "", cookie)
			if resp.StatusCode != tt.wantHTTP {
				t.Fatalf("HTTP status = %d, want %d: %s", resp.StatusCode, tt.wantHTTP, resp.body)
			}
			if tt.wantHTTP != http.StatusOK {
				return
			}
			m := decode[MetricsJSON](t, resp)
			var keys []string
			for _, c := range m.Charts {
				keys = append(keys, c.Key)
				if len(c.Points) == 0 {
					t.Errorf("chart %s has no points", c.Key)
				}
			}
			if m.Source != tt.wantSource || m.Status != tt.wantStatus || !slices.Equal(keys, tt.wantCharts) {
				t.Fatalf("metrics = %+v, want source %s status %s charts %v", m, tt.wantSource, tt.wantStatus, tt.wantCharts)
			}
			if m.Source == sourceBuiltin && m.Status == metricsOK {
				for _, c := range m.Charts {
					if v := c.Points[len(c.Points)-1][1]; v != map[string]float64{"cpu": 10, "memory": 40}[c.Key] {
						t.Errorf("chart %s last value = %v", c.Key, v)
					}
				}
			}
		})
	}
}

func TestMetricsSparklines(t *testing.T) {
	tests := []struct {
		name        string
		noStore     bool
		anonymous   bool
		wantHTTP    int
		wantDevices []string
	}{
		{name: "devices with recent metrics", wantHTTP: http.StatusOK, wantDevices: []string{"pi"}},
		{name: "hub keeps no metrics", noStore: true, wantHTTP: http.StatusOK},
		{name: "needs a session", anonymous: true, wantHTTP: http.StatusUnauthorized},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var opts []func(*Config)
			ms := newMetricsStore(t)
			if !tt.noStore {
				opts = append(opts, func(c *Config) { c.Metrics = ms })
			}
			f := newAPIFixture(t, true, opts...)
			addDevice(t, f.st, "pi", "raspberrypi", "192.168.2.131/24")
			addDevice(t, f.st, "stale", "nas", "192.168.2.132/24")
			addDevice(t, f.st, "silent", "router", "192.168.2.1/24")
			now := time.Now()
			if err := ms.Write(t.Context(), "pi", now.Add(-time.Minute), []metrics.Sample{{Name: "cpu", Value: 10}, {Name: "memory", Value: 40}}); err != nil {
				t.Fatal(err)
			}
			if err := ms.Write(t.Context(), "stale", now.Add(-2*sparklineWindow), []metrics.Sample{{Name: "cpu", Value: 99}}); err != nil {
				t.Fatal(err)
			}
			var cookie *http.Cookie
			if !tt.anonymous {
				cookie = sessionCookie(t, f.login(t, testPassword))
			}
			resp := f.do(t, http.MethodGet, "/api/v1/metrics/sparklines", "", cookie)
			if resp.StatusCode != tt.wantHTTP {
				t.Fatalf("HTTP status = %d, want %d: %s", resp.StatusCode, tt.wantHTTP, resp.body)
			}
			if tt.wantHTTP != http.StatusOK {
				return
			}
			got := decode[SparklinesJSON](t, resp)
			ids := slices.Sorted(maps.Keys(got.Devices))
			if !slices.Equal(ids, tt.wantDevices) {
				t.Fatalf("devices = %v, want %v", ids, tt.wantDevices)
			}
			if got.End-got.Start != sparklineWindow.Milliseconds() {
				t.Errorf("window = %d ms, want %d", got.End-got.Start, sparklineWindow.Milliseconds())
			}
			if len(tt.wantDevices) == 0 {
				return
			}
			var keys []string
			for _, c := range got.Devices["pi"] {
				keys = append(keys, c.Key)
			}
			if want := []string{"cpu", "memory"}; !slices.Equal(keys, want) {
				t.Errorf("charts = %v, want %v", keys, want)
			}
		})
	}
}

func TestAutomationMetricsBuiltin(t *testing.T) {
	ms := newMetricsStore(t)
	st := newTestStore(t)
	addDevice(t, st, "d1", "raspberrypi", "192.168.2.131/24")
	if err := ms.Write(t.Context(), "d1", time.Now(), []metrics.Sample{{Name: "cpu", Value: 93.5}}); err != nil {
		t.Fatal(err)
	}
	m := AutomationMetrics(st, nil, ms)
	for _, ref := range []string{"d1", "RaspberryPi"} {
		if v, err := m.DeviceMetric(t.Context(), ref, "cpu"); err != nil || v != 93.5 {
			t.Errorf("DeviceMetric(%s, cpu) = %v, %v; want 93.5", ref, v, err)
		}
	}
	if _, err := m.DeviceMetric(t.Context(), "d1", "memory"); !errors.Is(err, metrics.ErrNoData) {
		t.Errorf("no memory samples: err = %v, want ErrNoData", err)
	}
	if _, err := m.DeviceMetric(t.Context(), "nas", "cpu"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("unknown device: err = %v, want ErrNotFound", err)
	}
	if _, err := m.Query(t.Context(), "up"); !errors.Is(err, errNoPromQL) {
		t.Errorf("Query: err = %v, want errNoPromQL", err)
	}
}
