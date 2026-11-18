// SPDX-License-Identifier: AGPL-3.0-only

package prometheus

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeProm is a Prometheus API stand-in: it answers node_uname_info with
// targets and every range query with matrix, recording the queries it got.
type fakeProm struct {
	mu      sync.Mutex
	targets []map[string]string
	matrix  string // JSON of data.result for query_range
	queries []string
}

func (f *fakeProm) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	q := r.Form.Get("query")
	f.mu.Lock()
	f.queries = append(f.queries, r.URL.Path+" "+q)
	f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	switch r.URL.Path {
	case "/prom/api/v1/query":
		var parts []string
		for _, t := range f.targets {
			var lbl []string
			for k, v := range t {
				lbl = append(lbl, fmt.Sprintf("%q:%q", k, v))
			}
			parts = append(parts, `{"metric":{`+strings.Join(lbl, ",")+`},"value":[1700000000.5,"1"]}`)
		}
		fmt.Fprintf(w, `{"status":"success","data":{"resultType":"vector","result":[%s]}}`, strings.Join(parts, ","))
	case "/prom/api/v1/query_range":
		if strings.Contains(q, "bad(") {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"status":"error","errorType":"bad_data","error":"parse error"}`)
			return
		}
		fmt.Fprintf(w, `{"status":"success","data":{"resultType":"matrix","result":%s}}`, f.matrix)
	default:
		http.NotFound(w, r)
	}
}

func newFake(t *testing.T, f *fakeProm) *Reader {
	t.Helper()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	c, err := NewClient(srv.URL+"/prom/", nil)
	if err != nil {
		t.Fatal(err)
	}
	r := NewReader(c)
	r.now = func() time.Time { return time.Unix(1_700_000_000, 0) }
	return r
}

func TestNewClientRejectsBadURL(t *testing.T) {
	for _, u := range []string{"", "prometheus:9090", "ftp://x", "http://", "://x"} {
		if _, err := NewClient(u, nil); err == nil {
			t.Errorf("NewClient(%q) = nil error", u)
		}
	}
}

func TestInstance(t *testing.T) {
	targets := []map[string]string{
		{"instance": "nas.lan:9100", "nodename": "nas", "job": "node"},
		{"instance": "192.168.2.131:9100", "nodename": "raspberrypi", "job": "node"},
		{"instance": "10.0.0.7:9100", "nodename": "k8s-worker-1.cluster.local", "job": "node"},
		{"instance": "[fd00::5]:9100", "nodename": "other", "job": "node"},
	}
	tests := []struct {
		name string
		dev  Device
		want string
		err  error
	}{
		{"nodename", Device{Hostname: "nas"}, "nas.lan:9100", nil},
		{"nodename case and fqdn", Device{Hostname: "K8S-Worker-1"}, "10.0.0.7:9100", nil},
		{"device fqdn", Device{Hostname: "nas.home.arpa"}, "nas.lan:9100", nil},
		{"instance ip", Device{Hostname: "pi", Addrs: []string{"127.0.0.1/8", "192.168.2.131/24"}}, "192.168.2.131:9100", nil},
		{"instance ipv6", Device{Hostname: "x", Addrs: []string{"fd00:0:0::5/64"}}, "[fd00::5]:9100", nil},
		{"nodename beats address", Device{Hostname: "nas", Addrs: []string{"192.168.2.131"}}, "nas.lan:9100", nil},
		{"loopback never matches", Device{Hostname: "laptop", Addrs: []string{"127.0.0.1"}}, "", ErrNoTarget},
		{"no match", Device{Hostname: "toaster", Addrs: []string{"192.168.2.200"}}, "", ErrNoTarget},
		{"empty device", Device{}, "", ErrNoTarget},
	}
	r := newFake(t, &fakeProm{targets: targets})
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := r.Instance(t.Context(), tt.dev)
			if !errors.Is(err, tt.err) || got != tt.want {
				t.Fatalf("Instance = %q, %v; want %q, %v", got, err, tt.want, tt.err)
			}
		})
	}
}

func TestCharts(t *testing.T) {
	f := &fakeProm{matrix: `[{"metric":{"instance":"pi:9100"},"values":[[1699999940,"12.5"],[1699999970,"NaN"],[1700000000,"25"]]}]`}
	r := newFake(t, f)
	charts, err := r.Charts(t.Context(), `pi:9100`, r.now().Add(-time.Hour), r.now(), 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if len(charts) != 3 {
		t.Fatalf("got %d charts, want 3", len(charts))
	}
	for _, c := range charts {
		if len(c.Samples) != 2 || c.Samples[0].V != 12.5 || c.Samples[1].V != 25 ||
			!c.Samples[1].T.Equal(time.Unix(1_700_000_000, 0)) {
			t.Errorf("chart %s samples = %+v, want 12.5 and 25 with NaN dropped", c.Key, c.Samples)
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.queries) != 3 || !strings.Contains(f.queries[0], `instance="pi:9100"`) || !strings.Contains(f.queries[0], `[120s]`) {
		t.Errorf("queries = %q", f.queries)
	}
}

func TestChartsEmptySeries(t *testing.T) {
	r := newFake(t, &fakeProm{matrix: `[]`})
	charts, err := r.Charts(t.Context(), "x:9100", r.now().Add(-time.Hour), r.now(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range charts {
		if c.Samples == nil || len(c.Samples) != 0 {
			t.Errorf("chart %s samples = %#v, want empty non-nil", c.Key, c.Samples)
		}
	}
}

func TestQueryErrors(t *testing.T) {
	down := httptest.NewServer(http.NotFoundHandler())
	downURL := down.URL
	down.Close()

	notProm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "<html>login</html>")
	}))
	t.Cleanup(notProm.Close)

	tests := []struct {
		name, url, query, want string
	}{
		{"unreachable", downURL, "up", "connection refused"},
		{"not prometheus", notProm.URL, "up", "not a Prometheus API response"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := NewClient(tt.url, nil)
			if err != nil {
				t.Fatal(err)
			}
			_, err = c.Query(t.Context(), tt.query, time.Now())
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want it to mention %q", err, tt.want)
			}
		})
	}

	t.Run("api error", func(t *testing.T) {
		r := newFake(t, &fakeProm{})
		_, err := r.q.QueryRange(t.Context(), "bad(", time.Now(), time.Now(), time.Second)
		if err == nil || !strings.Contains(err.Error(), "bad_data: parse error") {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestClientSendsBasicAuth(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u, p, ok := r.BasicAuth(); !ok || u != "hearth" || p != "s3cret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		fmt.Fprint(w, `{"status":"success","data":{"resultType":"vector","result":[]}}`)
	}))
	t.Cleanup(srv.Close)
	c, err := NewClient(strings.Replace(srv.URL, "http://", "http://hearth:s3cret@", 1), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Query(t.Context(), "up", time.Now()); err != nil {
		t.Fatal(err)
	}
}
