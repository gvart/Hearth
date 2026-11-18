// SPDX-License-Identifier: AGPL-3.0-only

package automation

import (
	"context"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/policy"
)

// fakeNetwork hands every event to every watcher, as the hub's bus does.
type fakeNetwork struct {
	mu   sync.Mutex
	subs []chan NetworkEvent
}

func (f *fakeNetwork) WatchNetwork(ctx context.Context, fn func(NetworkEvent)) error {
	ch := make(chan NetworkEvent)
	f.mu.Lock()
	f.subs = append(f.subs, ch)
	f.mu.Unlock()
	for {
		select {
		case <-ctx.Done():
			return nil
		case e := <-ch:
			fn(e)
		}
	}
}

// send waits for watchers watching, then hands e to each, unbuffered: when
// it returns, every watcher is done with the events before e.
func (f *fakeNetwork) send(t *testing.T, watchers int, e NetworkEvent) {
	t.Helper()
	var subs []chan NetworkEvent
	eventually(t, "the watchers", func() bool {
		f.mu.Lock()
		defer f.mu.Unlock()
		subs = slices.Clone(f.subs)
		return len(subs) >= watchers
	})
	for _, ch := range subs {
		ch <- e
	}
}

func TestNetworkTrigger(t *testing.T) {
	phone := NetworkEvent{MAC: "3c:2e:f9:00:00:03", IP: "192.168.2.30", Vendor: "Apple", Name: "phone.local"}
	back := phone
	back.Returned = true
	ignored := NetworkEvent{MAC: "00:11:32:00:00:02", IP: "192.168.2.20", Silenced: true}
	ignoredBack := ignored
	ignoredBack.Returned = true
	for _, tc := range []struct {
		name   string
		src    string
		events []NetworkEvent
		want   []string // the Event of each firing
	}{
		{"new only", "event: new", []NetworkEvent{phone, back}, []string{"new"}},
		{"returned only", "event: returned", []NetworkEvent{phone, back}, []string{"returned"}},
		{"both", "", []NetworkEvent{phone, back}, []string{"new", "returned"}},
		{"silenced host", "", []NetworkEvent{ignored, ignoredBack}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			net := &fakeNetwork{}
			w := watch(t, mustBuildTrigger(t, TriggerDeps{Network: net}, "type: network\n"+tc.src))
			for _, e := range tc.events {
				net.send(t, 1, e)
			}
			// Silenced: handled after every event before it, and never
			// fires.
			net.send(t, 1, NetworkEvent{MAC: "ff:ff:ff:ff:ff:ff", Silenced: true})
			var got []string
			for _, d := range w.fired() {
				got = append(got, d["Event"].(string))
			}
			if strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Errorf("fired %v, want %v", got, tc.want)
			}
		})
	}
}

func TestNetworkTriggerData(t *testing.T) {
	net := &fakeNetwork{}
	tr := mustBuildTrigger(t, TriggerDeps{Network: net}, "type: network")
	w := watch(t, tr)
	// A randomized ("private") MAC: the locally administered bit is set.
	net.send(t, 1, NetworkEvent{MAC: "3e:00:00:00:00:03", IP: "192.168.2.31"})
	net.send(t, 1, NetworkEvent{MAC: "ff:ff:ff:ff:ff:ff", Silenced: true})
	got := w.fired()
	want := map[string]any{"Event": "new", "MAC": "3e:00:00:00:00:03", "IP": "192.168.2.31", "Vendor": "", "Name": "", "Private": true}
	if len(got) != 1 || !maps.Equal(got[0], want) {
		t.Fatalf("fired %v, want %v", got, want)
	}
	// Every firing has the Sample's fields, so templates checked against it
	// at load time render.
	for k := range tr.Sample() {
		if _, ok := got[0][k]; !ok {
			t.Errorf("a firing lacks the sample's field %s", k)
		}
	}
}

func TestNetworkTriggerInvalid(t *testing.T) {
	_, err := buildTrigger(t, TriggerDeps{}, "type: network\nevent: gone")
	wantErrContains(t, err, "event must be new or returned")
	_, err = buildTrigger(t, TriggerDeps{}, "type: network\nmac: aa:bb:cc:dd:ee:ff")
	wantErrContains(t, err, `unknown field "mac"`)

	tr := mustBuildTrigger(t, TriggerDeps{}, "type: network")
	wantErrContains(t, tr.Watch(t.Context(), func(map[string]any) {}), "not available")
}

func networkKinds(n Notifier, net NetworkEvents) Kinds {
	k := Builtin(slog.New(slog.DiscardHandler))
	maps.Copy(k.Triggers, Triggers(TriggerDeps{Network: net}))
	maps.Copy(k.Actions, Actions(ActionDeps{Notifier: n}))
	return k
}

func TestNewDeviceAlerts(t *testing.T) {
	n := &fakeNotifier{has: []string{"phone"}}
	net := &fakeNetwork{}
	kinds := networkKinds(n, net)

	for _, ch := range []string{"pager", "phone\nmode: restart", ""} {
		if _, err := NewDeviceAlerts(ch, kinds); err == nil {
			t.Errorf("NewDeviceAlerts(%q) succeeded", ch)
		}
	}
	a, err := NewDeviceAlerts("phone", kinds)
	if err != nil {
		t.Fatal(err)
	}
	if a.ID != NewDeviceAlertsID || a.Mode != ModeQueued || len(a.Triggers) != 2 || len(a.Actions) != 1 {
		t.Fatalf("automation = %+v", a)
	}

	rec := &recorder{}
	rt := New(Config{Kinds: kinds, Policy: policy.New(&auditLog{}), Runs: rec})
	ctx, cancel := context.WithCancel(t.Context())
	rt.reconcile(ctx, []*Automation{a})
	t.Cleanup(func() {
		cancel()
		rt.reconcile(ctx, nil)
	})
	// Both triggers (new and returned) watch, and see every event.
	net.send(t, 2, NetworkEvent{MAC: "3c:2e:f9:00:00:03", IP: "192.168.2.30", Vendor: "Apple", Name: "phone.local"})
	net.send(t, 2, NetworkEvent{MAC: "3e:00:00:00:00:04", IP: "192.168.2.31", Returned: true})
	net.send(t, 2, NetworkEvent{MAC: "00:11:32:00:00:02", IP: "192.168.2.20", Silenced: true})
	eventually(t, "two runs", func() bool { return len(rec.all()) == 2 })
	n.mu.Lock()
	defer n.mu.Unlock()
	want := []sent{
		{
			"phone", "New device on your network",
			"phone.local 192.168.2.30 (3c:2e:f9:00:00:03, Apple). Mark it known or ignored on the Devices page to silence it.",
		},
		{
			"phone", "Device back on your network",
			"192.168.2.31 (3e:00:00:00:00:04, private address). Mark it known or ignored on the Devices page to silence it.",
		},
	}
	// The triggers watch independently, so either run may go first.
	if len(n.sent) != 2 || !slices.Contains(n.sent, want[0]) || !slices.Contains(n.sent, want[1]) {
		t.Errorf("sent %+v\nwant %+v", n.sent, want)
	}
}

// A file with the built-in's id replaces it; without one the built-in runs.
func TestBuiltinReplacedByFile(t *testing.T) {
	kinds := networkKinds(&fakeNotifier{has: []string{"phone"}}, &fakeNetwork{})
	a, err := NewDeviceAlerts("phone", kinds)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	rt := New(Config{
		Dir: dir, Builtin: []*Automation{a}, Kinds: kinds, Policy: policy.New(&auditLog{}),
		Runs: &recorder{}, ReloadEvery: 10 * time.Millisecond,
	})
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- rt.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
	file := func() string {
		rt.mu.Lock()
		defer rt.mu.Unlock()
		if in, ok := rt.live[NewDeviceAlertsID]; ok {
			return in.a.File
		}
		return ""
	}
	eventually(t, "the built-in to run", func() bool { return file() == "built-in "+NewDeviceAlertsID })

	own := filepath.Join(dir, "mine.yaml")
	src := "id: new-device-alerts\ntriggers:\n  - type: network\n    event: new\nactions:\n  - type: log\n    message: new {{ .Trigger.MAC }}\n"
	if err := os.WriteFile(own, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the file to replace it", func() bool { return file() == own })
}
