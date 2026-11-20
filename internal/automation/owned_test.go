// SPDX-License-Identifier: AGPL-3.0-only

package automation

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/policy"
)

// TestEventTriggersFireWhereTheEventHappens: three masters run one
// automation owned by y. A device event published on x (its stream holder)
// fires it once, on x; the owner-only trigger is watched on y alone; a
// manual fire runs on the master it was made on.
func TestEventTriggersFireWhereTheEventHappens(t *testing.T) {
	dir := t.TempDir()
	const src = "id: watch\nmode: queued\ntriggers:\n" +
		"  - {id: off, type: device, to: offline}\n" +
		"  - {id: tick, type: fake}\n" +
		"  - {id: go, type: manual}\n" +
		"actions: [{id: act, type: fake}]\n"
	if err := os.WriteFile(filepath.Join(dir, "watch.yaml"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	type master struct {
		devs *fakeDevices
		act  *fakeAction
		trig *fakeTrigger
		rt   *Runtime
	}
	ms := map[string]*master{}
	for _, id := range []string{"x", "y", "z"} {
		m := &master{devs: &fakeDevices{ch: make(chan DeviceEvent)}, act: &fakeAction{policy: policy.AutomationLog}, trig: &fakeTrigger{}}
		kinds := testKinds(m.act, &fakeCondition{holds: true}, m.trig)
		kinds.Triggers["device"] = func(p Params) (Trigger, error) { return buildDevice(p, TriggerDeps{Devices: m.devs}) }
		m.rt = New(Config{
			Dir: dir, Kinds: kinds, Policy: policy.New(&auditLog{}), Runs: &recorder{},
			Owns: func(string) bool { return id == "y" },
		})
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan struct{})
		go func() { _ = m.rt.Run(ctx); close(done) }()
		t.Cleanup(func() { cancel(); <-done })
		ms[id] = m
	}
	for id, m := range ms {
		eventually(t, "watch running on "+id, func() bool { return running(m.rt, "watch") })
	}
	ms["x"].devs.ch <- DeviceEvent{ID: "d1", Name: "nas", Online: false}
	eventually(t, "x to run the automation", func() bool { return ms["x"].act.started() == 1 })
	time.Sleep(100 * time.Millisecond)
	for id, m := range ms {
		want := 0
		if id == "x" {
			want = 1
		}
		if got := m.act.started(); got != want {
			t.Errorf("runs on %s = %d, want %d", id, got, want)
		}
		m.trig.mu.Lock()
		watchedTick := m.trig.watched
		m.trig.mu.Unlock()
		if wantTick := map[bool]int{true: 1, false: 0}[id == "y"]; watchedTick != wantTick {
			t.Errorf("owner-only trigger watched %d times on %s, want %d", watchedTick, id, wantTick)
		}
	}
	if err := ms["z"].rt.Fire("watch", "go"); err != nil {
		t.Fatalf("manual fire on z, not the owner: %v", err)
	}
	eventually(t, "z to run the manual fire", func() bool { return ms["z"].act.started() == 1 })
}

// running reports whether rt runs automation id.
func running(rt *Runtime, id string) bool {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return rt.live[id] != nil
}
