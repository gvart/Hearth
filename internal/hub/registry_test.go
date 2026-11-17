// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
	"github.com/gvart/hearth/internal/store"
)

func testHello() *agentv1.Hello {
	return hello(ProtocolMajor).GetHello()
}

// drain returns the event types buffered on ch without blocking.
func drain(ch <-chan Event) []string {
	var out []string
	for {
		select {
		case e, ok := <-ch:
			if !ok {
				return out
			}
			out = append(out, e.Type)
		default:
			return out
		}
	}
}

// TestRegistryTransitions drives one device through every status transition
// with a fake clock (OfflineAfter = 30s) and checks the events and final status.
func TestRegistryTransitions(t *testing.T) {
	type step struct {
		advance time.Duration
		op      string // hello, facts, heartbeat, sweep
	}
	const (
		on  = EventDeviceOnline
		off = EventDeviceOffline
		upd = EventDeviceUpdated
	)
	tests := []struct {
		name       string
		steps      []step
		wantEvents []string
		wantStatus string
	}{
		{"hello brings unknown online", []step{{0, "hello"}}, []string{on}, store.StatusOnline},
		{"heartbeat brings unknown online", []step{{0, "heartbeat"}}, []string{on}, store.StatusOnline},
		{"facts bring unknown online", []step{{0, "facts"}}, []string{on}, store.StatusOnline},
		{"heartbeat while online is silent", []step{{0, "hello"}, {10 * time.Second, "heartbeat"}}, []string{on}, store.StatusOnline},
		{"facts while online are an update", []step{{0, "hello"}, {5 * time.Second, "facts"}}, []string{on, upd}, store.StatusOnline},
		{"reconnect hello while online is an update", []step{{0, "hello"}, {time.Second, "hello"}}, []string{on, upd}, store.StatusOnline},
		{"sweep before timeout keeps online", []step{{0, "hello"}, {29 * time.Second, "sweep"}}, []string{on}, store.StatusOnline},
		{"sweep exactly at timeout keeps online", []step{{0, "hello"}, {30 * time.Second, "sweep"}}, []string{on}, store.StatusOnline},
		{"online goes offline after timeout", []step{{0, "hello"}, {31 * time.Second, "sweep"}}, []string{on, off}, store.StatusOffline},
		{
			"heartbeats keep it online",
			[]step{{0, "hello"}, {20 * time.Second, "heartbeat"}, {20 * time.Second, "sweep"}, {20 * time.Second, "heartbeat"}, {20 * time.Second, "sweep"}},
			[]string{on},
			store.StatusOnline,
		},
		{"offline sweep is idempotent", []step{{0, "hello"}, {31 * time.Second, "sweep"}, {time.Hour, "sweep"}}, []string{on, off}, store.StatusOffline},
		{"heartbeat brings offline back", []step{{0, "hello"}, {31 * time.Second, "sweep"}, {time.Second, "heartbeat"}}, []string{on, off, on}, store.StatusOnline},
		{"hello brings offline back", []step{{0, "hello"}, {31 * time.Second, "sweep"}, {time.Second, "hello"}}, []string{on, off, on}, store.StatusOnline},
		{"facts bring offline back", []step{{0, "hello"}, {31 * time.Second, "sweep"}, {time.Second, "facts"}}, []string{on, off, on}, store.StatusOnline},
		{"never-seen device is not swept", []step{{time.Hour, "sweep"}}, nil, store.StatusUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := t.Context()
			st := newTestStore(t)
			enrollDevice(t, st, "pi")
			clk := newFakeClock()
			reg := NewRegistry(RegistryConfig{Store: st, OfflineAfter: 30 * time.Second, Now: clk.Now})
			events, unsubscribe := reg.Subscribe()
			defer unsubscribe()

			for _, s := range tt.steps {
				clk.Advance(s.advance)
				var err error
				switch s.op {
				case "hello", "facts":
					err = reg.ReportFacts(ctx, "pi", testHello())
				case "heartbeat":
					err = reg.Heartbeat(ctx, "pi")
				case "sweep":
					err = reg.Sweep(ctx)
				default:
					t.Fatalf("unknown op %q", s.op)
				}
				if err != nil {
					t.Fatalf("%s: %v", s.op, err)
				}
			}
			if got := drain(events); !reflect.DeepEqual(got, tt.wantEvents) {
				t.Errorf("events = %v, want %v", got, tt.wantEvents)
			}
			d, err := st.Devices().Get(ctx, "pi")
			if err != nil {
				t.Fatal(err)
			}
			if d.Status != tt.wantStatus {
				t.Errorf("status = %q, want %q", d.Status, tt.wantStatus)
			}
		})
	}
}

func TestRegistryReportFacts(t *testing.T) {
	ctx := t.Context()
	st := newTestStore(t)
	enrollDevice(t, st, "pi")
	clk := newFakeClock()
	reg := NewRegistry(RegistryConfig{Store: st, Now: clk.Now})
	events, unsubscribe := reg.Subscribe()
	defer unsubscribe()

	if err := reg.ReportFacts(ctx, "pi", testHello()); err != nil {
		t.Fatal(err)
	}
	ev := <-events
	d := ev.Device
	if d.Name != "pi-name" || !reflect.DeepEqual(d.Labels, map[string]string{"room": "attic"}) {
		t.Errorf("enrollment name/labels overwritten: name=%q labels=%v", d.Name, d.Labels)
	}
	if d.Hostname != "pi" || d.OS != "linux" || d.Arch != "arm64" || !d.LastSeen.Equal(clk.Now()) {
		t.Errorf("device = %+v, want hostname pi, linux/arm64, last_seen now", d)
	}
	var f Facts
	if err := json.Unmarshal(d.Facts, &f); err != nil {
		t.Fatal(err)
	}
	if f.CPUCores != 4 || len(f.Interfaces) != 1 || f.Interfaces[0].MAC != "aa:bb:cc:dd:ee:ff" || f.AgentVersion != "v0.0.0-test" {
		t.Errorf("facts = %+v", f)
	}

	clk.Advance(time.Second)
	if err := reg.Heartbeat(ctx, "pi"); err != nil {
		t.Fatal(err)
	}
	if got, _ := st.Devices().Get(ctx, "pi"); !got.LastSeen.Equal(clk.Now()) {
		t.Errorf("heartbeat: last_seen = %v, want %v", got.LastSeen, clk.Now())
	}
}

func TestRegistryUnknownDevice(t *testing.T) {
	reg := NewRegistry(RegistryConfig{Store: newTestStore(t)})
	if err := reg.Heartbeat(t.Context(), "ghost"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("Heartbeat(ghost) = %v, want ErrNotFound", err)
	}
	if err := reg.ReportFacts(t.Context(), "ghost", testHello()); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("ReportFacts(ghost) = %v, want ErrNotFound", err)
	}
}

func TestRegistryRunStopsOnCancel(t *testing.T) {
	st := newTestStore(t)
	enrollDevice(t, st, "pi")
	reg := NewRegistry(RegistryConfig{Store: st, OfflineAfter: 60 * time.Millisecond})
	events, unsubscribe := reg.Subscribe()
	defer unsubscribe()
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- reg.Run(ctx) }()

	if err := reg.Heartbeat(t.Context(), "pi"); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{EventDeviceOnline, EventDeviceOffline} {
		select {
		case e := <-events:
			if e.Type != want {
				t.Fatalf("event = %s, want %s", e.Type, want)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("no %s event", want)
		}
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not stop on cancel")
	}
}

func TestBus(t *testing.T) {
	var b bus
	fast, unsubFast := b.subscribe()
	slow, unsubSlow := b.subscribe()
	defer unsubSlow()

	for i := range subscriberBuffer + 1 {
		b.publish(Event{Type: EventDeviceUpdated})
		if i < subscriberBuffer {
			<-fast // keep up
		}
	}
	// The slow subscriber overflowed: its buffered events are still readable,
	// then the channel is closed.
	n := 0
	for range slow {
		n++
	}
	if n != subscriberBuffer {
		t.Errorf("slow subscriber got %d events before close, want %d", n, subscriberBuffer)
	}
	if e, ok := <-fast; !ok || e.Type != EventDeviceUpdated {
		t.Errorf("fast subscriber: got %v, %v", e, ok)
	}

	unsubFast()
	unsubFast() // idempotent
	if _, ok := <-fast; ok {
		t.Error("channel open after unsubscribe")
	}
	b.publish(Event{Type: EventDeviceUpdated}) // no subscribers left: must not block or panic
}
