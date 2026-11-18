// SPDX-License-Identifier: AGPL-3.0-only

package automation

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// fakeMetrics serves one value, or an error, for every read.
type fakeMetrics struct {
	mu     sync.Mutex
	values []float64
	err    error
	asked  []string
}

func (m *fakeMetrics) set(err error, values ...float64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.values, m.err = values, err
}

func (m *fakeMetrics) DeviceMetric(_ context.Context, device, metric string) (float64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.asked = append(m.asked, device+"/"+metric)
	if m.err != nil {
		return 0, m.err
	}
	return m.values[0], nil
}

func (m *fakeMetrics) Query(_ context.Context, q string) ([]float64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.asked = append(m.asked, q)
	return m.values, m.err
}

func TestMetricTriggerFiresAfterDuration(t *testing.T) {
	clock := newFakeClock(time.Unix(1_700_000_000, 0))
	m := &fakeMetrics{}
	m.set(nil, 10)
	tr := mustBuildTrigger(t, TriggerDeps{Clock: clock, Metrics: m}, `
type: metric
device: nas
metric: cpu
above: 90
for: 5m
`)
	w := watch(t, tr)
	if d := clock.waitForWaiter(t); d != defaultMetricEvery {
		t.Fatalf("polls every %s, want %s", d, defaultMetricEvery)
	}

	// step advances to the next check and waits for it to finish.
	step := func() {
		clock.Advance(defaultMetricEvery)
		clock.waitForWaiter(t)
	}
	m.set(nil, 95)
	// Above from the first check at 30 s: 5 m later is the check at 5m30s.
	for i := range 10 {
		step()
		if n := w.fires.Load(); n != 0 {
			t.Fatalf("fired after %d checks above, before 5m", i+1)
		}
	}
	step()
	if n := w.fires.Load(); n != 1 {
		t.Fatalf("fires = %d after 5m above, want 1", n)
	}
	// Still above: no second firing.
	for range 20 {
		step()
	}
	if n := w.fires.Load(); n != 1 {
		t.Fatalf("fires = %d while staying above, want 1", n)
	}
	// Back below re-arms it; above again needs a full 5m again.
	m.set(nil, 50)
	step()
	m.set(nil, 99)
	for range 10 {
		step()
	}
	if n := w.fires.Load(); n != 1 {
		t.Fatalf("fires = %d before the second 5m, want 1", n)
	}
	step()
	if n := w.fires.Load(); n != 2 {
		t.Fatalf("fires = %d after the second 5m, want 2", n)
	}
	if err := w.stop(t); err != nil {
		t.Fatalf("Watch = %v", err)
	}
	if m.asked[0] != "nas/cpu" {
		t.Errorf("asked %q, want nas/cpu", m.asked[0])
	}
}

func TestMetricTriggerReadErrorResetsDuration(t *testing.T) {
	clock := newFakeClock(time.Unix(1_700_000_000, 0))
	m := &fakeMetrics{}
	m.set(nil, 95)
	tr := mustBuildTrigger(t, TriggerDeps{Clock: clock, Metrics: m}, `
type: metric
device: nas
metric: memory
above: 90
for: 1m
every: 20s
`)
	w := watch(t, tr)
	clock.waitForWaiter(t)
	step := func() { clock.Advance(20 * time.Second); clock.waitForWaiter(t) }
	step() // above for 20 s
	m.set(errors.New("prometheus down"))
	step()
	m.set(nil, 95)
	step()
	step()
	step() // above for 40 s since the error
	if n := w.fires.Load(); n != 0 {
		t.Fatalf("fires = %d: a read error must reset the duration", n)
	}
	step()
	if n := w.fires.Load(); n != 1 {
		t.Fatalf("fires = %d after a full minute above, want 1", n)
	}
}

func TestMetricTriggerQueryBelowFiresAtOnce(t *testing.T) {
	clock := newFakeClock(time.Unix(1_700_000_000, 0))
	m := &fakeMetrics{}
	m.set(nil) // no series: not below anything
	tr := mustBuildTrigger(t, TriggerDeps{Clock: clock, Metrics: m}, `
type: metric
query: up{job="pihole"}
below: 1
`)
	w := watch(t, tr)
	clock.waitForWaiter(t)
	if n := w.fires.Load(); n != 0 {
		t.Fatalf("fired on an empty result")
	}
	m.set(nil, 1, 0) // one series of two is down
	clock.Advance(defaultMetricEvery)
	clock.waitForWaiter(t)
	if n := w.fires.Load(); n != 1 {
		t.Fatalf("fires = %d, want 1 on the first check below", n)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.asked[0] != `up{job="pihole"}` {
		t.Errorf("queried %q", m.asked[0])
	}
}

func TestMetricTriggerWithoutPrometheus(t *testing.T) {
	tr := mustBuildTrigger(t, TriggerDeps{}, "type: metric\ndevice: nas\nmetric: cpu\nabove: 90")
	err := tr.Watch(t.Context(), func(map[string]any) {})
	wantErrContains(t, err, "--prometheus-url")
}

func TestMetricTriggerInvalid(t *testing.T) {
	for _, tc := range []struct{ src, want string }{
		{"type: metric\nmetric: cpu\nabove: 1", "device and metric, or query"},
		{"type: metric\ndevice: nas\nmetric: load\nabove: 1", "metric must be cpu, memory or disk"},
		{"type: metric\ndevice: nas\nquery: up\nabove: 1", "either query"},
		{"type: metric\nquery: up", "exactly one of above and below"},
		{"type: metric\nquery: up\nabove: 1\nbelow: 2", "exactly one of above and below"},
		{"type: metric\nquery: up\nabove: 1\nevery: 100ms", "at least 1s"},
		{"type: metric\nquery: up\nabove: 1\nfor: -1m", "negative"},
		{"type: metric\nquery: up\nabove: 1\nduration: 1m", `unknown field "duration"`},
	} {
		_, err := buildTrigger(t, TriggerDeps{}, tc.src)
		wantErrContains(t, err, tc.want)
	}
}

func TestMetricTriggerDescribe(t *testing.T) {
	tr := mustBuildTrigger(t, TriggerDeps{}, "type: metric\ndevice: nas\nmetric: cpu\nabove: 90\nfor: 5m")
	want := "fires when cpu of device nas is above 90 for 5m0s (checked every 30s)"
	if got := tr.Describe(); got != want {
		t.Errorf("Describe = %q, want %q", got, want)
	}
}
