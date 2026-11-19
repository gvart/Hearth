// SPDX-License-Identifier: AGPL-3.0-only

package automation

import (
	"context"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/gvart/hearth/internal/policy"
)

// fakeNetwork hands every event to every watcher, as the hub's bus does.
type fakeNetwork struct {
	mu   sync.Mutex
	subs []chan []NetworkEvent
}

func (f *fakeNetwork) WatchNetwork(ctx context.Context, fn func([]NetworkEvent)) error {
	ch := make(chan []NetworkEvent)
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

// send is sendScan of a scan that found only e.
func (f *fakeNetwork) send(t *testing.T, watchers int, e NetworkEvent) {
	t.Helper()
	f.sendScan(t, watchers, e)
}

// sendScan waits for watchers watching, then hands the hosts of one scan to
// each, unbuffered: when it returns, every watcher is done with the scans
// before this one.
func (f *fakeNetwork) sendScan(t *testing.T, watchers int, hosts ...NetworkEvent) {
	t.Helper()
	var subs []chan []NetworkEvent
	eventually(t, "the watchers", func() bool {
		f.mu.Lock()
		defer f.mu.Unlock()
		subs = slices.Clone(f.subs)
		return len(subs) >= watchers
	})
	for _, ch := range subs {
		ch <- hosts
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

func TestNetworkTriggerScan(t *testing.T) {
	a := NetworkEvent{MAC: "00:11:32:00:00:01", IP: "192.168.2.1"}
	b := NetworkEvent{MAC: "00:11:32:00:00:02", IP: "192.168.2.2"}
	quiet := NetworkEvent{MAC: "00:11:32:00:00:03", IP: "192.168.2.3", Silenced: true}
	for _, tc := range []struct {
		name  string
		src   string
		hosts []NetworkEvent
		want  []int // the Count of each firing; 0 for a firing about one host
	}{
		{"without batch, one firing per host", "", []NetworkEvent{a, b}, []int{0, 0}},
		{"batch, one firing per scan", "batch: true", []NetworkEvent{a, b}, []int{2}},
		{"batch counts no silenced host", "batch: true", []NetworkEvent{a, quiet, b}, []int{2}},
		{"batch of silenced hosts", "batch: true", []NetworkEvent{quiet}, nil},
		{"batch of another event", "batch: true\nevent: returned", []NetworkEvent{a, b}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			net := &fakeNetwork{}
			w := watch(t, mustBuildTrigger(t, TriggerDeps{Network: net}, "type: network\n"+tc.src))
			net.sendScan(t, 1, tc.hosts...)
			net.send(t, 1, quiet) // handled after the scan, and never fires
			var got []int
			for _, d := range w.fired() {
				n, _ := d["Count"].(int)
				got = append(got, n)
			}
			if !slices.Equal(got, tc.want) {
				t.Errorf("fired %v, want %v", got, tc.want)
			}
		})
	}
}

// worstHosts are n hosts whose lines in a list are as long as they can be.
func worstHosts(n int) []NetworkEvent {
	hosts := make([]NetworkEvent, n)
	for i := range hosts {
		hosts[i] = NetworkEvent{
			MAC: fmt.Sprintf("00:11:32:10:%02x:%02x", i>>8, i&0xff), IP: fmt.Sprintf("192.168.%03d.%03d", 100+i/100, 100+i%100),
			Name: strings.Repeat("\u00e9", 200), Vendor: strings.Repeat("\u00e9", 200),
		}
	}
	return hosts
}

// 50 hosts always fit, however long their names, and the text stays valid.
func TestHostListFitsFiftyHosts(t *testing.T) {
	hosts := worstHosts(50)
	got := hostList(hosts)
	if len(got) > maxHostList || !utf8.ValidString(got) {
		t.Errorf("list is %d bytes (valid UTF-8: %v)", len(got), utf8.ValidString(got))
	}
	for _, e := range hosts {
		if !strings.Contains(got, e.MAC) {
			t.Errorf("%s is not listed", e.MAC)
		}
	}
	if strings.Contains(got, "more") {
		t.Errorf("list says hosts are left out: %q", got)
	}
}

// The most hosts that fit are all listed; one more is counted instead.
func TestHostListLimit(t *testing.T) {
	fit := 1
	for !strings.Contains(hostList(worstHosts(fit+1)), "more") {
		fit++
	}
	over := hostList(worstHosts(fit + 1))
	if strings.Count(over, "00:11:32:10:") != fit || !strings.HasSuffix(over, "\nand 1 more") {
		t.Errorf("%d hosts fit, but %d give %q", fit, fit+1, over)
	}
	if got := hostList(worstHosts(maxScanHosts)); len(got) > maxHostList || !strings.HasSuffix(got, fmt.Sprintf("\nand %d more", maxScanHosts-fit)) {
		t.Errorf("%d bytes, ending %q", len(got), got[len(got)-20:])
	}
}

// maxScanHosts is discovery.MaxHosts, the most hosts one scan can find.
const maxScanHosts = 1024

// The built-in's notification stays within what ntfy and Telegram accept.
func TestNewDeviceAlertsSummarySize(t *testing.T) {
	a, err := NewDeviceAlerts("phone", networkKinds(&fakeNotifier{has: []string{"phone"}}, &fakeNetwork{}))
	if err != nil {
		t.Fatal(err)
	}
	n := a.Actions[0].Impl.(*notifyAction)
	ev := Event{TriggerID: "new", TriggerType: "network", Data: batchData(worstHosts(maxScanHosts))}
	title, err := n.title.Render(t.Context(), ev)
	if err != nil {
		t.Fatal(err)
	}
	msg, err := n.message.Render(t.Context(), ev)
	if err != nil {
		t.Fatal(err)
	}
	if title != "1024 new devices on your network" {
		t.Errorf("title = %q", title)
	}
	if size := len(title) + 1 + len(msg); size > 4096 {
		t.Errorf("notification is %d bytes", size)
	}
	if !strings.HasSuffix(msg, "more\nMark them known or ignored on the Devices page to silence them.") {
		t.Errorf("message ends %q", msg[len(msg)-90:])
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
