// SPDX-License-Identifier: AGPL-3.0-only

package automation

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeNode struct {
	leader atomic.Bool
	ready  chan struct{}
}

func (n *fakeNode) IsLeader() bool { return n.leader.Load() }

func (n *fakeNode) WaitReady(ctx context.Context) error {
	select {
	case <-n.ready:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Automations run only while the hub leads the cluster and has caught up,
// and stop as soon as it steps down.
func TestRunWhileLeading(t *testing.T) {
	node := &fakeNode{ready: make(chan struct{})}
	changed := make(chan struct{})
	var (
		mu      sync.Mutex
		active  int
		started int
	)
	state := func() (int, int) {
		mu.Lock()
		defer mu.Unlock()
		return active, started
	}
	run := func(ctx context.Context) error {
		mu.Lock()
		active++
		started++
		mu.Unlock()
		<-ctx.Done()
		mu.Lock()
		active--
		mu.Unlock()
		return nil
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- RunWhileLeading(ctx, node, changed, slog.New(slog.DiscardHandler), run) }()
	signal := func() { changed <- struct{}{} }
	settle := func() { time.Sleep(20 * time.Millisecond) }

	// A follower runs nothing.
	signal()
	settle()
	if a, s := state(); a != 0 || s != 0 {
		t.Fatalf("follower: active %d, started %d; want nothing", a, s)
	}

	// A leader that has not caught up waits.
	node.leader.Store(true)
	signal()
	settle()
	if _, s := state(); s != 0 {
		t.Fatal("started before the hub caught up with the cluster")
	}
	close(node.ready)
	eventually(t, "started on the leader", func() bool { a, _ := state(); return a == 1 })

	// Another signal while still leading does not start a second copy.
	signal()
	settle()
	if a, s := state(); a != 1 || s != 1 {
		t.Fatalf("still leading: active %d, started %d; want 1, 1", a, s)
	}

	// Stepping down stops it.
	node.leader.Store(false)
	signal()
	eventually(t, "stopped on step-down", func() bool { a, _ := state(); return a == 0 })

	// Leading again starts it again.
	node.leader.Store(true)
	signal()
	eventually(t, "restarted on the leader", func() bool { a, s := state(); return a == 1 && s == 2 })

	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if a, _ := state(); a != 0 {
		t.Error("RunWhileLeading returned with automations still running")
	}
}
