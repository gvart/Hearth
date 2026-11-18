// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/integrations/prometheus"
	"github.com/gvart/hearth/internal/store"
)

// fakePrometheus answers node_uname_info with one target, 192.168.2.131:9100
// (nodename raspberrypi), and every range query with two samples.
func fakePrometheus(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/query":
			fmt.Fprint(w, `{"status":"success","data":{"resultType":"vector","result":[
				{"metric":{"__name__":"node_uname_info","instance":"192.168.2.131:9100","nodename":"raspberrypi"},"value":[1700000000,"1"]}]}}`)
		case "/api/v1/query_range":
			fmt.Fprint(w, `{"status":"success","data":{"resultType":"matrix","result":[
				{"metric":{"instance":"192.168.2.131:9100"},"values":[[1700000000,"10"],[1700000030,"20.5"]]}]}}`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func withPrometheus(t *testing.T, url string) func(*Config) {
	t.Helper()
	c, err := prometheus.NewClient(url, nil)
	if err != nil {
		t.Fatal(err)
	}
	return func(cfg *Config) { cfg.Prometheus = prometheus.NewReader(c) }
}

func addDevice(t *testing.T, st *store.Store, id, hostname string, ips ...string) {
	t.Helper()
	facts, err := json.Marshal(Facts{Hostname: hostname, Interfaces: []Interface{{Name: "eth0", IPs: ips}}})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if err := st.Devices().Upsert(t.Context(), store.Device{
		ID: id, Hostname: hostname, Facts: facts, FirstSeen: now, LastSeen: now, Status: store.StatusOnline,
	}); err != nil {
		t.Fatal(err)
	}
}

func TestDeviceMetrics(t *testing.T) {
	prom := fakePrometheus(t)
	down := httptest.NewServer(http.NotFoundHandler())
	downURL := down.URL
	down.Close()

	tests := []struct {
		name       string
		opts       []func(*Config)
		device     string
		path       string
		wantHTTP   int
		wantStatus string
		wantInst   string
		wantCharts int
	}{
		{"not configured", nil, "pi", "", http.StatusOK, metricsNotConfigured, "", 0},
		{"unreachable", []func(*Config){withPrometheus(t, downURL)}, "pi", "", http.StatusOK, metricsUnreachable, "", 0},
		{"by nodename", []func(*Config){withPrometheus(t, prom.URL)}, "pi", "", http.StatusOK, metricsOK, "192.168.2.131:9100", 3},
		{"by address", []func(*Config){withPrometheus(t, prom.URL)}, "byip", "?range=6h", http.StatusOK, metricsOK, "192.168.2.131:9100", 3},
		{"no target", []func(*Config){withPrometheus(t, prom.URL)}, "nas", "", http.StatusOK, metricsNoTarget, "", 0},
		{"unknown device", []func(*Config){withPrometheus(t, prom.URL)}, "ghost", "", http.StatusNotFound, "", "", 0},
		{"bad range", []func(*Config){withPrometheus(t, prom.URL)}, "pi", "?range=1y", http.StatusBadRequest, "", "", 0},
		{"range too long", []func(*Config){withPrometheus(t, prom.URL)}, "pi", "?range=1000h", http.StatusBadRequest, "", "", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newAPIFixture(t, true, tt.opts...)
			addDevice(t, f.st, "pi", "raspberrypi", "127.0.0.1/8", "192.168.2.131/24")
			addDevice(t, f.st, "byip", "pi-renamed", "192.168.2.131/24")
			addDevice(t, f.st, "nas", "nas", "192.168.2.50/24")
			cookie := sessionCookie(t, f.login(t, testPassword))

			resp := f.do(t, http.MethodGet, "/api/v1/devices/"+tt.device+"/metrics"+tt.path, "", cookie)
			if resp.StatusCode != tt.wantHTTP {
				t.Fatalf("HTTP status = %d, want %d: %s", resp.StatusCode, tt.wantHTTP, resp.body)
			}
			if tt.wantHTTP != http.StatusOK {
				return
			}
			m := decode[MetricsJSON](t, resp)
			if m.Status != tt.wantStatus || m.Instance != tt.wantInst || len(m.Charts) != tt.wantCharts || m.Source != "prometheus" {
				t.Fatalf("metrics = %+v", m)
			}
			if m.Status == metricsOK && m.End-m.Start != map[string]int64{"": time.Hour.Milliseconds(), "?range=6h": 6 * time.Hour.Milliseconds()}[tt.path] {
				t.Errorf("start, end = %d, %d; want the requested range", m.Start, m.End)
			}
			if m.Status != metricsOK && m.Message == "" {
				t.Errorf("status %s has no message", m.Status)
			}
			if m.Charts == nil || !strings.Contains(string(resp.body), `"charts":[`) {
				t.Errorf("charts must be a JSON array: %s", resp.body)
			}
			for _, c := range m.Charts {
				if len(c.Points) != 2 || c.Points[0] != [2]float64{1_700_000_000_000, 10} || c.Points[1][1] != 20.5 {
					t.Errorf("chart %s points = %v", c.Key, c.Points)
				}
			}
		})
	}
}

func TestMetricsStep(t *testing.T) {
	for window, want := range map[time.Duration]time.Duration{
		5 * time.Minute:     15 * time.Second,
		time.Hour:           30 * time.Second,
		24 * time.Hour:      12 * time.Minute,
		7 * 24 * time.Hour:  84 * time.Minute,
		100 * time.Minute:   50 * time.Second,
		61 * time.Minute:    30 * time.Second,
		2*time.Hour + 1e9:   time.Minute,
		15*time.Minute + 15: 15 * time.Second,
	} {
		if got := metricsStep(window); got != want {
			t.Errorf("metricsStep(%v) = %v, want %v", window, got, want)
		}
	}
}
