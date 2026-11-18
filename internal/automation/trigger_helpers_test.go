// SPDX-License-Identifier: AGPL-3.0-only

package automation

import (
	"context"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"
)

// fakeClock is a Clock that moves only when told to.
type fakeClock struct {
	mu      sync.Mutex
	now     time.Time
	waiters []clockWaiter
}

type clockWaiter struct {
	at time.Time
	ch chan time.Time
}

func newFakeClock(now time.Time) *fakeClock { return &fakeClock{now: now} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) After(d time.Duration) <-chan time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	ch := make(chan time.Time, 1)
	if d <= 0 {
		ch <- c.now
		return ch
	}
	c.waiters = append(c.waiters, clockWaiter{at: c.now.Add(d), ch: ch})
	return ch
}

// Advance moves the clock by d and wakes every waiter that is due.
func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
	kept := c.waiters[:0]
	for _, w := range c.waiters {
		if w.at.After(c.now) {
			kept = append(kept, w)
			continue
		}
		w.ch <- c.now
	}
	c.waiters = kept
}

// next returns how long until the earliest waiter is due.
func (c *fakeClock) next() (time.Duration, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.waiters) == 0 {
		return 0, false
	}
	d := c.waiters[0].at.Sub(c.now)
	for _, w := range c.waiters[1:] {
		d = min(d, w.at.Sub(c.now))
	}
	return d, true
}

// waitForWaiter waits until something waits on the clock, which a watching
// trigger does once it is done with its current check, and returns how long
// until it is due.
func (c *fakeClock) waitForWaiter(t *testing.T) time.Duration {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if d, ok := c.next(); ok {
			return d
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("nothing waits on the clock")
	return 0
}

// watching is a trigger being watched in the background.
type watching struct {
	fires  atomic.Int32
	cancel context.CancelFunc
	done   chan error

	mu   sync.Mutex
	data []map[string]any // of each firing
}

// fired returns the data of each firing so far.
func (w *watching) fired() []map[string]any {
	w.mu.Lock()
	defer w.mu.Unlock()
	return slices.Clone(w.data)
}

func watch(t *testing.T, tr Trigger) *watching {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	w := &watching{cancel: cancel, done: make(chan error, 1)}
	go func() {
		w.done <- tr.Watch(ctx, func(data map[string]any) {
			w.mu.Lock()
			w.data = append(w.data, data)
			w.mu.Unlock()
			w.fires.Add(1)
		})
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-w.done:
			if err != nil {
				t.Errorf("Watch = %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("trigger did not stop")
		}
	})
	return w
}

// stop stops the watch and returns what Watch returned.
func (w *watching) stop(t *testing.T) error {
	t.Helper()
	w.cancel()
	select {
	case err := <-w.done:
		w.done <- err // for the cleanup
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("trigger did not stop")
		return nil
	}
}

// buildTrigger builds a trigger from YAML fields, as a file would give them.
func buildTrigger(t *testing.T, deps TriggerDeps, src string) (Trigger, error) {
	t.Helper()
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(src), &doc); err != nil {
		t.Fatalf("yaml: %v", err)
	}
	m := doc.Content[0]
	typ := ""
	params := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == "type" {
			typ = m.Content[i+1].Value
			continue
		}
		params.Content = append(params.Content, m.Content[i], m.Content[i+1])
	}
	build, ok := Triggers(deps)[typ]
	if !ok {
		t.Fatalf("no trigger type %q", typ)
	}
	return build(Params{node: params})
}

func mustBuildTrigger(t *testing.T, deps TriggerDeps, src string) Trigger {
	t.Helper()
	tr, err := buildTrigger(t, deps, src)
	if err != nil {
		t.Fatalf("build %q: %v", src, err)
	}
	return tr
}

func wantErrContains(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("err = %v, want it to contain %q", err, want)
	}
}
