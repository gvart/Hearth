// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"context"
	"log/slog"
	"os/exec"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
)

// restoreGOMAXPROCS puts the test process back as it was.
func restoreGOMAXPROCS(t *testing.T) {
	t.Helper()
	prev := runtime.GOMAXPROCS(0)
	t.Cleanup(func() { runtime.GOMAXPROCS(prev) })
}

func TestTuneRuntimeGOMAXPROCS(t *testing.T) {
	tests := []struct {
		name, env string
		start     int
		want      int
	}{
		{name: "unset means one P", env: "", start: 4, want: 1},
		{name: "explicit value is respected", env: "3", start: 3, want: 3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			restoreGOMAXPROCS(t)
			t.Setenv("GOMAXPROCS", tt.env)
			runtime.GOMAXPROCS(tt.start)
			_, _, stop := tuneRuntime(time.Hour, time.Hour, time.Now, func() {}, func() {})
			defer stop()
			if got := runtime.GOMAXPROCS(0); got != tt.want {
				t.Errorf("GOMAXPROCS = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestTuneRuntimeCollectsOnce(t *testing.T) {
	restoreGOMAXPROCS(t)
	var runs atomic.Int32
	done := make(chan struct{}, 2)
	connected, _, stop := tuneRuntime(time.Millisecond, time.Hour, time.Now, func() {
		runs.Add(1)
		done <- struct{}{}
	}, func() { t.Error("failed collection ran") })
	defer stop()
	wait := func(what string) {
		t.Helper()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatalf("%s did not run", what)
		}
	}
	wait("first collection")
	time.Sleep(20 * time.Millisecond)
	if got := runs.Load(); got != 1 {
		t.Errorf("collections after start = %d, want 1", got)
	}
	connected()
	wait("collection after connecting")
	time.Sleep(20 * time.Millisecond)
	if got := runs.Load(); got != 2 {
		t.Errorf("collections after connecting = %d, want 2", got)
	}
}

func TestTuneRuntimeStopCancelsCollection(t *testing.T) {
	restoreGOMAXPROCS(t)
	var runs atomic.Int32
	_, _, stop := tuneRuntime(20*time.Millisecond, time.Hour, time.Now, func() { runs.Add(1) }, func() {})
	stop()
	time.Sleep(60 * time.Millisecond)
	if got := runs.Load(); got != 0 {
		t.Errorf("collections after stop = %d, want 0", got)
	}
}

// TestTuneRuntimeCollectsAfterFailures checks that failed collects after a
// failed attempt at most once per gap, on an injected clock.
func TestTuneRuntimeCollectsAfterFailures(t *testing.T) {
	restoreGOMAXPROCS(t)
	const gap = 30 * time.Second
	start := time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)
	steps := []struct {
		at   time.Duration // since start, when the attempt failed
		want int           // collections so far
	}{
		{at: 0, want: 1},           // the first failure collects
		{at: time.Second, want: 1}, // quick retries share it
		{at: 3 * time.Second, want: 1},
		{at: 29 * time.Second, want: 1}, // just under the gap
		{at: 30 * time.Second, want: 2}, // the gap has passed
		{at: 45 * time.Second, want: 2},
		{at: 100 * time.Second, want: 3}, // backed-off retries each collect
		{at: 150 * time.Second, want: 4},
		{at: 179 * time.Second, want: 4},
		{at: 1800 * time.Second, want: 5}, // a long outage
	}
	var now time.Time
	runs := 0
	_, failed, stop := tuneRuntime(time.Hour, gap, func() time.Time { return now }, func() { t.Error("delayed collection ran") }, func() { runs++ })
	defer stop()
	for _, s := range steps {
		now = start.Add(s.at)
		failed()
		if runs != s.want {
			t.Errorf("after a failure at +%v: %d collections, want %d", s.at, runs, s.want)
		}
	}
}

// TestOnePKeepsWorkOnTime checks that with one P a metrics collection and a
// heartbeat-rate ticker keep running while an exec is in progress and a
// goroutine burns CPU.
func TestOnePKeepsWorkOnTime(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skipf("sh not found: %v", err)
	}
	restoreGOMAXPROCS(t)
	runtime.GOMAXPROCS(1)

	const (
		tick    = 100 * time.Millisecond
		maxLate = time.Second
		run     = 2 * time.Second
	)
	ctx, cancel := context.WithTimeout(t.Context(), run)
	defer cancel()

	var wg sync.WaitGroup
	defer wg.Wait()
	wg.Go(func() { // CPU load inside the agent's own process
		for ctx.Err() == nil {
			for range 1 << 16 {
				_ = time.Now()
			}
		}
	})
	execDone := make(chan *agentv1.ExecResult, 1)
	wg.Go(func() {
		req := &agentv1.ExecRequest{Action: &agentv1.ExecRequest_Command{Command: &agentv1.Command{
			Argv: []string{sh, "-c", "sleep 1"},
		}}}
		execDone <- Ceiling{Exec: []string{sh}}.execute(context.WithoutCancel(ctx), req)
	})

	c := newCollector(slog.New(slog.DiscardHandler))
	ticker := time.NewTicker(tick)
	defer ticker.Stop()
	last, ticks := time.Now(), 0
	var worst time.Duration
loop:
	for {
		select {
		case <-ctx.Done():
			break loop
		case now := <-ticker.C:
			c.collect(ctx, now)
			if gap := time.Since(last); gap > worst {
				worst = gap
			}
			last = time.Now()
			ticks++
		}
	}
	t.Logf("%d ticks of %v, longest gap %v", ticks, tick, worst)
	if worst > maxLate {
		t.Errorf("longest gap between ticks = %v, want at most %v", worst, maxLate)
	}
	if ticks < 5 {
		t.Errorf("ticks = %d in %v, want at least 5", ticks, run)
	}
	res := <-execDone
	if res.GetError() != "" || res.GetExitCode() != 0 {
		t.Errorf("exec during load: exit %d, error %q", res.GetExitCode(), res.GetError())
	}
}

// TestStopMemProfile: heap profiling is off unless GODEBUG asks for it. Not
// parallel: it sets the process's GODEBUG and profile rate.
func TestStopMemProfile(t *testing.T) {
	rate := runtime.MemProfileRate
	t.Cleanup(func() { runtime.MemProfileRate = rate })
	for _, tc := range []struct {
		godebug string
		want    int
	}{
		{"", 0},
		{"gctrace=1", 0},
		{"memprofilerate=1", 4096},
		{"gctrace=1,memprofilerate=0", 4096},
	} {
		t.Setenv("GODEBUG", tc.godebug)
		runtime.MemProfileRate = 4096
		StopMemProfile()
		if runtime.MemProfileRate != tc.want {
			t.Errorf("GODEBUG=%q: MemProfileRate = %d, want %d", tc.godebug, runtime.MemProfileRate, tc.want)
		}
	}
}
