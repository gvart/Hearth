// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/store"
)

// gatedObserver records whether each SetBootTime was reported as local, and
// holds the apply goroutine on the entry whose boot time is gate.
type gatedObserver struct {
	gate    int64
	entered chan struct{}
	release chan struct{}

	mu    sync.Mutex
	local map[int64]bool
}

func (o *gatedObserver) Applied(cmd store.Command, _ store.Result, local bool) {
	c, ok := cmd.(store.SetBootTime)
	if !ok || c.BootTime == nil {
		return
	}
	o.mu.Lock()
	o.local[*c.BootTime] = local
	o.mu.Unlock()
	if *c.BootTime == o.gate {
		close(o.entered)
		<-o.release
	}
}

func (*gatedObserver) Restored() {}

func (o *gatedObserver) localOf(boot int64) (local, seen bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	local, seen = o.local[boot]
	return local, seen
}

// TestAppliedLocalForwardedWrite: a write a follower forwarded comes back to
// it through the log, and its caller reacts to the returned result, so the
// entry is local there and on no other follower. A leader stepping down with
// a registry write in flight takes this path, and published that write's
// event twice (#143).
func TestAppliedLocalForwardedWrite(t *testing.T) {
	hubs := startHubs(t, hubOpts{offlineAfter: time.Minute, flushEvery: time.Minute, forwardWait: waitFor})
	leader := leaderHub(t, hubs)
	rest := followers(hubs, leader)
	writer, other := rest[0], rest[1]
	upsert(t, leader.testNode, "pi")
	for _, h := range rest {
		eventually(t, "the device on "+h.ID(), func() bool { return hasDevice(h.testNode, "pi") })
	}

	observe := func(h *testHub) *gatedObserver {
		o := &gatedObserver{gate: -1, local: map[int64]bool{}}
		h.ObserveApplies(o)
		return o
	}
	onWriter, onOther := observe(writer), observe(other)
	boot := time.UnixMilli(3_000_000).UTC()
	if _, err := writer.st.Devices().SetBootTime(t.Context(), "pi", boot); err != nil {
		t.Fatalf("forwarded write: %v", err)
	}
	if local, seen := onWriter.localOf(boot.UnixMilli()); !seen || !local {
		t.Errorf("on the forwarding hub: local %v, seen %v; want a local entry", local, seen)
	}
	eventually(t, "the entry on the other follower", func() bool {
		_, seen := onOther.localOf(boot.UnixMilli())
		return seen
	})
	if local, _ := onOther.localOf(boot.UnixMilli()); local {
		t.Error("another follower reported the forwarded entry as local")
	}
}

// TestAppliedLocalAfterStepDown: an entry that committed while this node led
// is local even when the node has stepped down by the time it applies it.
// Its proposer gets the result and reacts to the write itself, so reporting
// the entry as not local made the hub publish its event twice (#143).
func TestAppliedLocalAfterStepDown(t *testing.T) {
	nodes := threeNodes(t, newTestCA(t))
	leader := leaderOf(t, nodes...)
	upsert(t, leader, "pi")
	for _, n := range nodes {
		eventually(t, "the device on "+n.ID(), func() bool { return hasDevice(n, "pi") })
	}

	gate, last := time.UnixMilli(1_000_000).UTC(), time.UnixMilli(2_000_000).UTC()
	obs := &gatedObserver{
		gate: gate.UnixMilli(), entered: make(chan struct{}), release: make(chan struct{}),
		local: map[int64]bool{},
	}
	leader.ObserveApplies(obs)
	var release sync.Once
	open := func() { release.Do(func() { close(obs.release) }) }
	t.Cleanup(open)

	ctx, cancel := context.WithTimeout(t.Context(), waitFor)
	defer cancel()
	results := make(chan error, 2)
	propose := func(boot time.Time) {
		_, err := leader.st.Devices().SetBootTime(ctx, "pi", boot)
		results <- err
	}
	// The first entry holds the leader's apply goroutine, so the second one
	// commits and waits behind it.
	go propose(gate)
	select {
	case <-obs.entered:
	case <-ctx.Done():
		t.Fatal("the gate entry was not applied")
	}
	go propose(last)
	for _, n := range nodes {
		if n == leader {
			continue
		}
		eventually(t, "the entry committed on "+n.ID(), func() bool {
			d, err := n.st.Devices().Get(ctx, "pi")
			return err == nil && d.BootTime.Equal(last)
		})
	}

	if err := leader.raft.LeadershipTransfer().Error(); err != nil {
		t.Fatalf("LeadershipTransfer: %v", err)
	}
	eventually(t, "the leader to step down", func() bool { return !leader.IsLeader() })
	open()

	for range 2 {
		select {
		case err := <-results:
			if err != nil {
				t.Fatalf("proposer: %v", err)
			}
		case <-ctx.Done():
			t.Fatal("a proposer did not return")
		}
	}
	local, seen := obs.localOf(last.UnixMilli())
	if !seen {
		t.Fatal("the entry was not observed")
	}
	if !local {
		t.Error("an entry this node proposed and answered was reported as not local")
	}
}
