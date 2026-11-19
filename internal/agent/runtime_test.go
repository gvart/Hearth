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
			_, stop := tuneRuntime(time.Hour, func() {})
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
	connected, stop := tuneRuntime(time.Millisecond, func() {
		runs.Add(1)
		done <- struct{}{}
	})
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
	_, stop := tuneRuntime(20*time.Millisecond, func() { runs.Add(1) })
	stop()
	time.Sleep(60 * time.Millisecond)
	if got := runs.Load(); got != 0 {
		t.Errorf("collections after stop = %d, want 0", got)
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
