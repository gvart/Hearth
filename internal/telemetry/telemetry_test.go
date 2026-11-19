// SPDX-License-Identifier: AGPL-3.0-only

package telemetry

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/store"
)

func openStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(t.Context(), filepath.Join(t.TempDir(), "hearth.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

// collector records what it is sent. With fail set, any request fails the test.
type collector struct {
	srv    *httptest.Server
	mu     sync.Mutex
	bodies [][]byte
	status int
}

func newCollector(t *testing.T, fail bool) *collector {
	t.Helper()
	c := &collector{status: http.StatusNoContent}
	c.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fail {
			t.Errorf("collector hit: %s %s", r.Method, r.URL)
		}
		var buf bytes.Buffer
		_, _ = buf.ReadFrom(r.Body)
		c.mu.Lock()
		c.bodies = append(c.bodies, buf.Bytes())
		status := c.status
		c.mu.Unlock()
		w.WriteHeader(status)
	}))
	t.Cleanup(c.srv.Close)
	return c
}

func (c *collector) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.bodies)
}

type leader bool

func (l leader) IsLeader() bool { return bool(l) }

type fixture struct {
	st   *store.Store
	logs *bytes.Buffer
	now  time.Time
}

func (f *fixture) sender(cfg Config) *Sender {
	cfg.Store = f.st
	cfg.Log = slog.New(slog.NewTextHandler(f.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	cfg.Now = func() time.Time { return f.now }
	if cfg.Version == "" {
		cfg.Version = "v0.1.0"
	}
	return New(cfg)
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	return &fixture{st: openStore(t), logs: &bytes.Buffer{}, now: time.UnixMilli(1_800_000_000_000).UTC()}
}

func (f *fixture) answer(t *testing.T, yes bool) {
	t.Helper()
	id := ""
	if yes {
		id = NewInstallID()
	}
	if err := f.st.Telemetry().Set(t.Context(), yes, id, f.now); err != nil {
		t.Fatal(err)
	}
}

// Nothing is sent unless the admin said yes, HEARTH_TELEMETRY is not off,
// there is an endpoint and this hub leads.
func TestNothingSentUnlessAllowed(t *testing.T) {
	for _, tt := range []struct {
		name     string
		answer   string // "", "yes", "no"
		off      bool
		endpoint bool
		leader   Leader
	}{
		{name: "never answered", endpoint: true},
		{name: "answered no", answer: "no", endpoint: true},
		{name: "HEARTH_TELEMETRY=off beats a stored yes", answer: "yes", off: true, endpoint: true},
		{name: "empty endpoint", answer: "yes"},
		{name: "follower", answer: "yes", endpoint: true, leader: leader(false)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t)
			c := newCollector(t, true)
			switch tt.answer {
			case "yes":
				f.answer(t, true)
			case "no":
				f.answer(t, false)
			}
			cfg := Config{Off: tt.off, Leader: tt.leader, Client: c.srv.Client()}
			if tt.endpoint {
				cfg.Endpoint = c.srv.URL
			}
			s := f.sender(cfg)
			for range 3 {
				if s.Tick(t.Context()) {
					t.Error("Tick sent")
				}
				f.now = f.now.Add(Interval)
			}
			if c.count() != 0 {
				t.Errorf("collector got %d requests, want none", c.count())
			}
		})
	}
}

func TestEmptyEndpointLogsOnce(t *testing.T) {
	f := newFixture(t)
	f.answer(t, true)
	s := f.sender(Config{})
	s.Tick(t.Context())
	s.Tick(t.Context())
	if n := strings.Count(f.logs.String(), "no collector endpoint"); n != 1 {
		t.Errorf("logged %d times, want once:\n%s", n, f.logs)
	}
}

// The leader sends once after the opt-in, then not again for a week, also
// after a failed send; a new opt-in sends at once.
func TestLeaderSendsWeekly(t *testing.T) {
	f := newFixture(t)
	c := newCollector(t, false)
	f.answer(t, true)
	s := f.sender(Config{Endpoint: c.srv.URL, Leader: leader(true), Client: c.srv.Client()})
	steps := []struct {
		advance time.Duration
		status  int
		want    int
	}{
		{0, http.StatusNoContent, 1},
		{time.Hour, http.StatusNoContent, 1},
		{Interval - 2*time.Hour, http.StatusNoContent, 1},
		{2 * time.Hour, http.StatusInternalServerError, 2},
		// The failed send is not retried before the next week.
		{time.Hour, http.StatusNoContent, 2},
		{Interval, http.StatusNoContent, 3},
	}
	for i, st := range steps {
		f.now = f.now.Add(st.advance)
		c.mu.Lock()
		c.status = st.status
		c.mu.Unlock()
		s.Tick(t.Context())
		if got := c.count(); got != st.want {
			t.Fatalf("step %d: %d sends, want %d", i, got, st.want)
		}
	}
	if strings.Contains(f.logs.String(), "level=ERROR") || strings.Contains(f.logs.String(), "level=WARN") {
		t.Errorf("a failed send logged above debug:\n%s", f.logs)
	}
	f.answer(t, true)
	s.Tick(t.Context())
	if got := c.count(); got != 4 {
		t.Errorf("after a new opt-in: %d sends, want 4", got)
	}
}

// The payload holds exactly the documented keys, and nothing else: no
// hostnames, cluster names or URLs.
func TestPayloadKeys(t *testing.T) {
	f := newFixture(t)
	c := newCollector(t, false)
	ctx := t.Context()
	if err := f.st.Devices().Upsert(ctx, store.Device{ID: "d1", Name: "secret-host", Hostname: "secret-host.lan"}); err != nil {
		t.Fatal(err)
	}
	if err := f.st.KubeClusters().Add(ctx, store.KubeCluster{ID: "k", Name: "secret-cluster", Sealed: []byte{1}, CreatedAt: f.now}); err != nil {
		t.Fatal(err)
	}
	f.answer(t, true)
	s := f.sender(Config{
		Endpoint: c.srv.URL, Client: c.srv.Client(),
		Integrations: []string{Prometheus, "http://secret.lan:9090", PiHole, Prometheus},
	})
	if !s.Tick(ctx) || c.count() != 1 {
		t.Fatalf("sent %d, want 1", c.count())
	}
	body := c.bodies[0]
	var got map[string]any
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	keys := slices.Sorted(maps.Keys(got))
	if want := []string{"arch", "devices", "install_id", "integrations", "os", "version"}; !slices.Equal(keys, want) {
		t.Errorf("payload keys = %v, want %v", keys, want)
	}
	// The struct itself, marshalled empty, has the same keys.
	b, _ := json.Marshal(Payload{})
	var empty map[string]any
	_ = json.Unmarshal(b, &empty)
	if k := slices.Sorted(maps.Keys(empty)); !slices.Equal(k, keys) {
		t.Errorf("Payload keys = %v, want %v", k, keys)
	}
	set, _ := f.st.Telemetry().Get(ctx)
	want := Payload{
		InstallID: set.InstallID, Version: "v0.1.0", OS: runtime.GOOS, Arch: runtime.GOARCH,
		Devices: "1-5", Integrations: []string{Kubernetes, PiHole, Prometheus},
	}
	var p Payload
	if err := json.Unmarshal(body, &p); err != nil {
		t.Fatal(err)
	}
	if !equalPayload(p, want) {
		t.Errorf("payload = %+v, want %+v", p, want)
	}
	for _, secret := range []string{"secret", ".lan", "http"} {
		if bytes.Contains(body, []byte(secret)) {
			t.Errorf("payload %s holds %q", body, secret)
		}
	}
}

func equalPayload(a, b Payload) bool {
	return a.InstallID == b.InstallID && a.Version == b.Version && a.OS == b.OS && a.Arch == b.Arch &&
		a.Devices == b.Devices && slices.Equal(a.Integrations, b.Integrations)
}

func TestBucket(t *testing.T) {
	for _, tt := range []struct {
		n    int
		want string
	}{
		{0, "0"}, {1, "1-5"}, {5, "1-5"}, {6, "6-20"}, {20, "6-20"},
		{21, "21-50"}, {50, "21-50"}, {51, "51+"}, {10_000, "51+"},
	} {
		if got := Bucket(tt.n); got != tt.want {
			t.Errorf("Bucket(%d) = %q, want %q", tt.n, got, tt.want)
		}
	}
}

func TestNewInstallIDIsRandom(t *testing.T) {
	a, b := NewInstallID(), NewInstallID()
	if a == b || len(a) < 16 {
		t.Errorf("NewInstallID() = %q, %q; want two different random IDs", a, b)
	}
}

func TestParseMode(t *testing.T) {
	for _, tt := range []struct {
		in      string
		off, ok bool
	}{
		{"", false, true},
		{"off", true, true},
		{"on", false, false},
		{"false", false, false},
	} {
		off, err := ParseMode(tt.in)
		if off != tt.off || (err == nil) != tt.ok {
			t.Errorf("ParseMode(%q) = %v, %v", tt.in, off, err)
		}
	}
}

func TestCheckEndpoint(t *testing.T) {
	for _, tt := range []struct {
		in string
		ok bool
	}{
		{"", true},
		{"https://telemetry.example.com/v1", true},
		{"http://telemetry.example.com/v1", false},
		{"telemetry.example.com", false},
	} {
		if err := CheckEndpoint(tt.in); (err == nil) != tt.ok {
			t.Errorf("CheckEndpoint(%q) = %v", tt.in, err)
		}
	}
}
