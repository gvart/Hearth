// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"context"
	"errors"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/automation"
	"github.com/gvart/hearth/internal/metrics"
	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

// metricMasters is one master of a test cluster whose masters serve their
// /agents/ handlers at srvs, by id.
type metricMasters struct {
	self string
	c    *metricCluster
}

type metricCluster struct {
	mu   sync.Mutex
	live map[string]bool
	srvs map[string]*url.URL
}

func (c *metricCluster) setLive(id string, live bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.live[id] = live
}

func (m metricMasters) Self() string { return m.self }
func (m metricMasters) Live(id string) bool {
	m.c.mu.Lock()
	defer m.c.mu.Unlock()
	return m.c.live[id]
}
func (m metricMasters) OwnerOf(string) string { return "y" }
func (m metricMasters) AgentURLOf(_ context.Context, id string) string {
	return "https://" + id + ".lan:8443"
}

func (m metricMasters) Client() *http.Client {
	return &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		m.c.mu.Lock()
		u := m.c.srvs[r.URL.Host]
		m.c.mu.Unlock()
		if u == nil {
			return nil, errors.New("unreachable")
		}
		r = r.Clone(r.Context())
		r.URL.Scheme, r.URL.Host = u.Scheme, u.Host
		return http.DefaultTransport.RoundTrip(r)
	})}
}

// metricMaster is one master: its own metrics, agents and metric source.
type metricMaster struct {
	ms      *metrics.Store
	agents  *Agents
	metrics automation.Metrics
	srv     *httptest.Server
}

// newMetricCluster starts masters ids sharing st, each with its metrics
// database and /agents/ handler, all live.
func newMetricCluster(t *testing.T, st *store.Store, ids ...string) (*metricCluster, map[string]*metricMaster) {
	t.Helper()
	c := &metricCluster{live: map[string]bool{}, srvs: map[string]*url.URL{}}
	out := map[string]*metricMaster{}
	for _, id := range ids {
		m := &metricMaster{ms: newMetricsStore(t), agents: NewAgents(st.Devices())}
		m.agents.SetMasters(metricMasters{self: id, c: c}, st.DeviceRoutes())
		m.metrics = AutomationMetrics(st, nil, m.ms, m.agents)
		m.srv = httptest.NewServer(AgentsHandler(m.agents, m.ms, slog.New(slog.DiscardHandler)))
		t.Cleanup(m.srv.Close)
		u, _ := url.Parse(m.srv.URL)
		c.live[id], c.srvs[id] = true, u
		out[id] = m
	}
	return c, out
}

// TestBuiltinMetricFromTheStreamHolder: without Prometheus, a device's metric
// is read on the master its agent streams to, where its samples are; with
// no live holder, it is read here, and is not there.
func TestBuiltinMetricFromTheStreamHolder(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	st := newTestStore(t)
	addDevice(t, st, "d1", "nas", "192.168.2.10/24")
	c, ms := newMetricCluster(t, st, "x", "y")
	if err := ms["x"].ms.Write(ctx, "d1", time.Now(), []metrics.Sample{{Name: "cpu", Value: 95}}); err != nil {
		t.Fatal(err)
	}
	if err := st.DeviceRoutes().Set(ctx, "d1", "x", time.Now()); err != nil {
		t.Fatal(err)
	}
	y := ms["y"].metrics

	if v, err := y.DeviceMetric(ctx, "nas", "cpu"); err != nil || v != 95 {
		t.Fatalf("DeviceMetric on y = %v, %v; want 95 from x", v, err)
	}
	if v, err := ms["x"].metrics.DeviceMetric(ctx, "nas", "cpu"); err != nil || v != 95 {
		t.Fatalf("DeviceMetric on the holder x = %v, %v; want 95", v, err)
	}
	if _, err := y.DeviceMetric(ctx, "nas", "memory"); !errors.Is(err, metrics.ErrNoData) {
		t.Errorf("no memory samples on x: err = %v, want ErrNoData", err)
	}
	// A forwarded read is not forwarded again, and only knows the
	// built-in metrics.
	if _, err := ms["x"].agents.call(ctx, "x", opMetric, agentCall{Device: "d1", Metric: "../cpu"}, nil, nil); err == nil {
		t.Error("forwarded read of an unknown metric: no error")
	}

	// x is unreachable while still live: a clear error, the same each time.
	c.mu.Lock()
	c.srvs["x"] = nil
	c.mu.Unlock()
	_, err1 := y.DeviceMetric(ctx, "nas", "cpu")
	_, err2 := y.DeviceMetric(ctx, "nas", "cpu")
	if !errors.Is(err1, ErrStreamElsewhere) || errors.Is(err1, automation.ErrOutcomeUnknown) {
		t.Errorf("holder unreachable: err = %v, want ErrStreamElsewhere", err1)
	}
	if err1 == nil || err2 == nil || err1.Error() != err2.Error() {
		t.Errorf("holder unreachable: errors %v and %v differ", err1, err2)
	}
	// x left: y has no samples of d1.
	c.setLive("x", false)
	if _, err := y.DeviceMetric(ctx, "nas", "cpu"); !errors.Is(err, metrics.ErrNoData) {
		t.Errorf("holder gone: err = %v, want ErrNoData", err)
	}
}

// countAction counts its runs.
type countAction struct{ n *atomic.Int32 }

func (countAction) Describe() string                              { return "count" }
func (countAction) Policy() policy.Action                         { return policy.AutomationLog }
func (countAction) Target() automation.Text                       { return automation.Text{} }
func (a countAction) Run(context.Context, automation.Event) error { a.n.Add(1); return nil }

// warnCounter counts warnings.
type warnCounter struct {
	slog.Handler
	n *atomic.Int32
}

func (warnCounter) Enabled(context.Context, slog.Level) bool { return true }

func (h warnCounter) Handle(_ context.Context, r slog.Record) error {
	if r.Level == slog.LevelWarn {
		h.n.Add(1)
	}
	return nil
}

const metricAutomation = "id: hot\ntriggers:\n" +
	"  - {type: metric, device: nas, metric: cpu, above: 90, every: 1s}\n" +
	"actions: [{id: count, type: count}]\n"

// runMetricAutomations runs metricAutomation on every master, owned by y,
// and returns the runs and warnings on each.
func runMetricAutomations(t *testing.T, st *store.Store, ms map[string]*metricMaster) (runs, warns map[string]*atomic.Int32) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "hot.yaml"), []byte(metricAutomation), 0o600); err != nil {
		t.Fatal(err)
	}
	runs, warns = map[string]*atomic.Int32{}, map[string]*atomic.Int32{}
	for id, m := range ms {
		runs[id], warns[id] = &atomic.Int32{}, &atomic.Int32{}
		log := slog.New(warnCounter{Handler: slog.DiscardHandler, n: warns[id]})
		kinds := automation.Builtin(log)
		maps.Copy(kinds.Triggers, automation.Triggers(automation.TriggerDeps{Metrics: m.metrics, Log: log}))
		n := runs[id]
		kinds.Actions["count"] = func(automation.Params) (automation.Action, error) { return countAction{n: n}, nil }
		rt := automation.New(automation.Config{
			Dir: dir, Kinds: kinds, Policy: policy.New(st.Audit()), Runs: st.AutomationRuns(), Log: log,
			Owns: func(string) bool { return id == "y" },
		})
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- rt.Run(ctx) }()
		t.Cleanup(func() {
			cancel()
			if err := <-done; err != nil {
				t.Error(err)
			}
		})
	}
	return runs, warns
}

// TestMetricTriggerAcrossMasters: three masters, no Prometheus. The device
// streams to x, the automation is owned by y: y reads the device's cpu from
// x, and the automation runs exactly once, on y, through policy and into
// the audit log.
func TestMetricTriggerAcrossMasters(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	st := newTestStore(t)
	addDevice(t, st, "d1", "nas", "192.168.2.10/24")
	_, ms := newMetricCluster(t, st, "x", "y", "z")
	if err := st.DeviceRoutes().Set(ctx, "d1", "x", time.Now()); err != nil {
		t.Fatal(err)
	}
	// Fresh samples on x for as long as the test runs.
	write := func() {
		if err := ms["x"].ms.Write(ctx, "d1", time.Now(), []metrics.Sample{{Name: "cpu", Value: 97}}); err != nil {
			t.Error(err)
		}
	}
	write()
	runs, warns := runMetricAutomations(t, st, ms)
	waitFor(t, "the automation to run on y", func() bool { return runs["y"].Load() == 1 })
	for range 3 { // a few more checks, still past the threshold
		time.Sleep(time.Second)
		write()
	}
	for id, n := range runs {
		want := int32(0)
		if id == "y" {
			want = 1
		}
		if got := n.Load(); got != want {
			t.Errorf("runs on %s = %d, want %d", id, got, want)
		}
		if w := warns[id].Load(); w != 0 {
			t.Errorf("warnings on %s = %d, want 0", id, w)
		}
	}
	entries, err := st.Audit().List(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	audited := 0
	for _, e := range entries {
		if e.ActorKind == "automation" && e.ActorID == "hot" && e.Action == string(policy.AutomationLog) {
			audited++
		}
	}
	if audited != 1 {
		t.Errorf("audit entries for the run = %d, want 1: %+v", audited, entries)
	}
}

// TestMetricTriggerHolderDown: the master holding the device's stream is
// down, gone from the live masters or still live but unreachable. The owner
// reads no value: nothing fires, and it warns once, not on every check.
func TestMetricTriggerHolderDown(t *testing.T) {
	t.Parallel()
	for name, stillLive := range map[string]bool{"gone": false, "unreachable": true} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()
			st := newTestStore(t)
			addDevice(t, st, "d1", "nas", "192.168.2.10/24")
			c, ms := newMetricCluster(t, st, "x", "y", "z")
			if err := ms["x"].ms.Write(ctx, "d1", time.Now(), []metrics.Sample{{Name: "cpu", Value: 97}}); err != nil {
				t.Fatal(err)
			}
			if err := st.DeviceRoutes().Set(ctx, "d1", "x", time.Now()); err != nil {
				t.Fatal(err)
			}
			c.setLive("x", stillLive)
			ms["x"].srv.Close()
			runs, warns := runMetricAutomations(t, st, ms)
			waitFor(t, "y to warn", func() bool { return warns["y"].Load() > 0 })
			time.Sleep(3 * time.Second) // three more checks
			for id, n := range runs {
				if got := n.Load(); got != 0 {
					t.Errorf("runs on %s = %d, want 0", id, got)
				}
			}
			if w := warns["y"].Load(); w != 1 {
				t.Errorf("warnings on y = %d, want 1", w)
			}
		})
	}
}
