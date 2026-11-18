// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/automation"
	"github.com/gvart/hearth/internal/discovery"
	"github.com/gvart/hearth/internal/notify"
	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

// alertHarness is the new-device alert path of a hub, end to end: scans
// recorded in a real store and published on a real registry, the built-in
// automation watching it, and an ntfy server counting what it is sent.
type alertHarness struct {
	st  *store.Store
	reg *Registry
	t0  time.Time

	mu   sync.Mutex
	sent []map[string]string
}

func newAlertHarness(t *testing.T) *alertHarness {
	t.Helper()
	h := &alertHarness{st: newTestStore(t), t0: time.UnixMilli(1_700_000_000_000).UTC()}
	h.reg = NewRegistry(RegistryConfig{Store: h.st})
	ntfy := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		var body map[string]string
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &body)
		h.mu.Lock()
		h.sent = append(h.sent, body)
		h.mu.Unlock()
	}))
	t.Cleanup(ntfy.Close)
	n, err := notify.Parse([]byte("channels:\n  phone: {type: ntfy, url: \"" + ntfy.URL + "\", topic: lab}\n"))
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.DiscardHandler)
	kinds := automation.Builtin(log)
	maps.Copy(kinds.Triggers, automation.Triggers(automation.TriggerDeps{Network: AutomationNetwork(h.reg)}))
	maps.Copy(kinds.Actions, automation.Actions(automation.ActionDeps{Notifier: n}))
	a, err := automation.NewDeviceAlerts("phone", kinds)
	if err != nil {
		t.Fatal(err)
	}
	rt := automation.New(automation.Config{
		Dir: t.TempDir(), Builtin: []*automation.Automation{a}, Kinds: kinds,
		Policy: policy.New(h.st.Audit()), Runs: h.st.AutomationRuns(), Log: log,
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- rt.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
	// Both triggers (new, returned) subscribe before any scan.
	waitFor(t, "the triggers to subscribe", func() bool {
		h.reg.bus.mu.Lock()
		defer h.reg.bus.mu.Unlock()
		return len(h.reg.bus.subs) == 2
	})
	return h
}

// scan does what discovery.Scanner.Scan does with what a sweep found, at t0
// plus at: records it, then publishes the new and returned hosts.
func (h *alertHarness) scan(t *testing.T, at time.Duration, hosts ...store.NetworkHost) {
	t.Helper()
	res, err := h.st.NetworkHosts().RecordScan(t.Context(), h.t0.Add(at), discovery.DefaultAbsentAfter, hosts)
	if err != nil {
		t.Fatal(err)
	}
	for _, x := range res.New {
		h.reg.NetworkHost(discovery.EventNew, x)
	}
	for _, x := range res.Returned {
		h.reg.NetworkHost(discovery.EventReturned, x)
	}
}

// settle waits until every notification for the scans so far is sent and
// returns them. Last scans find a sentinel host new, then back, and another new: runs
// of each trigger are queued in order, so once both sentinels' notifications
// are in, so is everything before them. The sentinels are left out. The
// present hosts stay on the network meanwhile, never away for an hour.
func (h *alertHarness) settle(t *testing.T, at time.Duration, present ...store.NetworkHost) []map[string]string {
	t.Helper()
	back := store.NetworkHost{MAC: "02:00:00:00:00:fe", IP: "192.168.2.254"}
	h.scan(t, at, append([]store.NetworkHost{back}, present...)...)
	h.scan(t, at+40*time.Minute, present...)
	h.scan(t, at+80*time.Minute, append([]store.NetworkHost{back, {MAC: "02:00:00:00:00:ff", IP: "192.168.2.253"}}, present...)...)
	var out []map[string]string
	waitFor(t, "the sentinel notifications", func() bool {
		h.mu.Lock()
		defer h.mu.Unlock()
		out = out[:0]
		seen := 0
		for _, m := range h.sent {
			if strings.Contains(m["message"], "02:00:00:00:00:f") {
				seen++
				continue
			}
			out = append(out, m)
		}
		return seen == 3
	})
	return out
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

var (
	router = store.NetworkHost{MAC: "00:11:32:00:00:01", IP: "192.168.2.1", Vendor: "Synology"}
	phone  = store.NetworkHost{MAC: "3c:2e:f9:00:00:03", IP: "192.168.2.30", Vendor: "Apple", Hostname: "phone.local"}
)

// Done when: plugging a new phone into Wi-Fi produces exactly one
// notification. The phone appears in scan N+1 and stays for N+2 and N+3.
func TestNewDeviceAlertExactlyOnce(t *testing.T) {
	h := newAlertHarness(t)
	h.scan(t, 0, router) // N: the baseline, silent
	h.scan(t, 5*time.Minute, router, phone)
	h.scan(t, 10*time.Minute, router, phone)
	h.scan(t, 15*time.Minute, router, phone)
	got := h.settle(t, 20*time.Minute, router, phone)
	if len(got) != 1 {
		t.Fatalf("notifications = %v, want exactly one", got)
	}
	if got[0]["title"] != "New device on your network" ||
		!strings.HasPrefix(got[0]["message"], "phone.local 192.168.2.30 (3c:2e:f9:00:00:03, Apple)") {
		t.Errorf("notification = %v", got[0])
	}
}

// A host away for an hour or more alerts again when it comes back, unless it
// is marked known or ignored; marking it neither again restores the alert.
func TestNewDeviceAlertMarkedHostsAreSilent(t *testing.T) {
	for _, tc := range []struct {
		state string
		want  int
	}{
		{store.HostIgnored, 0},
		{store.HostKnown, 0},
		{store.HostUnreviewed, 1},
	} {
		t.Run("state "+tc.state, func(t *testing.T) {
			h := newAlertHarness(t)
			h.scan(t, 0, router, phone) // the baseline: the phone is already there
			if err := h.st.NetworkHosts().SetState(t.Context(), phone.MAC, tc.state); err != nil {
				t.Fatal(err)
			}
			// The router stays, scan after scan; the phone is away.
			for at := 30 * time.Minute; at < 3*time.Hour; at += 30 * time.Minute {
				h.scan(t, at, router)
			}
			h.scan(t, 3*time.Hour, router, phone) // back after more than an hour
			h.scan(t, 3*time.Hour+5*time.Minute, router, phone)
			got := h.settle(t, 4*time.Hour, router, phone)
			if len(got) != tc.want {
				t.Fatalf("notifications = %v, want %d", got, tc.want)
			}
			if tc.want == 1 && got[0]["title"] != "Device back on your network" {
				t.Errorf("notification = %v", got[0])
			}
		})
	}
}

// A host that is one of an enrolled device's interfaces is that device: no
// alert.
func TestNewDeviceAlertSkipsEnrolledDevices(t *testing.T) {
	h := newAlertHarness(t)
	if err := h.st.Devices().Upsert(t.Context(), store.Device{
		ID: "pi", Name: "pi", Hostname: "pi5", FirstSeen: h.t0, LastSeen: h.t0, Status: store.StatusOnline,
		Facts: json.RawMessage(`{"interfaces":[{"name":"eth0","mac":"2C:CF:67:00:00:01"}]}`),
	}); err != nil {
		t.Fatal(err)
	}
	h.scan(t, 0, router)
	pi := store.NetworkHost{MAC: "2c:cf:67:00:00:01", IP: "192.168.2.171"}
	h.scan(t, 5*time.Minute, router, pi)
	if got := h.settle(t, 10*time.Minute, router, pi); len(got) != 0 {
		t.Fatalf("notifications = %v, want none", got)
	}
}

// imported records what Pi-hole knows, as discovery.Importer does, at t0
// plus at. Imports publish nothing.
func (h *alertHarness) imported(t *testing.T, at time.Duration, hosts ...store.ImportedHost) {
	t.Helper()
	if err := h.st.NetworkHosts().RecordImport(t.Context(), h.t0.Add(at), hosts); err != nil {
		t.Fatal(err)
	}
}

// piholeKnows is host as Pi-hole reports it, seen at t.
func piholeKnows(host store.NetworkHost, name string, t time.Time) store.ImportedHost {
	return store.ImportedHost{
		MAC: host.MAC, IP: host.IP, Hostname: name, HostnameSource: store.SourcePihole,
		Sources: []string{store.SourcePihole}, Seen: t.UnixMilli(),
	}
}

// A host Pi-hole knew first alerts once, at the first scan that finds it and
// with its Pi-hole name; a host only an import knows never alerts.
func TestNewDeviceAlertImportedHosts(t *testing.T) {
	h := newAlertHarness(t)
	vlanTV := store.NetworkHost{MAC: "aa:bb:cc:00:00:04", IP: "192.168.20.5"}
	h.scan(t, 0, router)
	h.imported(t, time.Minute, piholeKnows(phone, "iphone", h.t0.Add(time.Minute)), piholeKnows(vlanTV, "tv", h.t0.Add(time.Minute)))
	h.scan(t, 5*time.Minute, router)
	h.scan(t, 10*time.Minute, router, phone)
	h.imported(t, 11*time.Minute, piholeKnows(phone, "iphone", h.t0.Add(11*time.Minute)), piholeKnows(vlanTV, "tv", h.t0.Add(11*time.Minute)))
	h.scan(t, 15*time.Minute, router, phone)
	got := h.settle(t, 20*time.Minute, router, phone)
	if len(got) != 1 {
		t.Fatalf("notifications = %v, want one, for the phone", got)
	}
	if got[0]["title"] != "New device on your network" || !strings.HasPrefix(got[0]["message"], "iphone 192.168.2.30 (3c:2e:f9:00:00:03") {
		t.Errorf("notification = %v; want the phone, by its Pi-hole name", got[0])
	}
}

// An import before the first scan does not end the baseline: turning
// discovery on next to a Pi-hole does not report the whole LAN.
func TestNewDeviceAlertImportBeforeBaseline(t *testing.T) {
	h := newAlertHarness(t)
	h.imported(t, 0, piholeKnows(phone, "iphone", h.t0))
	h.scan(t, time.Minute, router, phone)
	if got := h.settle(t, 5*time.Minute, router, phone); len(got) != 0 {
		t.Fatalf("notifications = %v, want none from the baseline", got)
	}
}

// A host marked while only an import knew it stays silent when a scan finds
// it.
func TestNewDeviceAlertImportedHostMarkedBeforeScan(t *testing.T) {
	h := newAlertHarness(t)
	h.scan(t, 0, router)
	h.imported(t, time.Minute, piholeKnows(phone, "iphone", h.t0.Add(time.Minute)))
	if err := h.st.NetworkHosts().SetState(t.Context(), phone.MAC, store.HostKnown); err != nil {
		t.Fatal(err)
	}
	h.scan(t, 5*time.Minute, router, phone)
	if got := h.settle(t, 10*time.Minute, router, phone); len(got) != 0 {
		t.Fatalf("notifications = %v, want none for a known host", got)
	}
}

// Pi-hole seeing a host moves its last seen, but only a scan decides it was
// away: the phone still alerts when it comes back.
func TestNewDeviceAlertReturnedDespiteImport(t *testing.T) {
	h := newAlertHarness(t)
	h.scan(t, 0, router, phone)
	for at := 30 * time.Minute; at < 3*time.Hour; at += 30 * time.Minute {
		h.scan(t, at, router)
	}
	// Its first DNS query back home reaches Pi-hole just before the scan.
	h.imported(t, 3*time.Hour-time.Minute, piholeKnows(phone, "iphone", h.t0.Add(3*time.Hour-time.Minute)))
	h.scan(t, 3*time.Hour, router, phone)
	got := h.settle(t, 3*time.Hour+5*time.Minute, router, phone)
	if len(got) != 1 || got[0]["title"] != "Device back on your network" {
		t.Fatalf("notifications = %v, want one: the phone is back", got)
	}
}

// A phone that rotates its randomized ("private") MAC is a new host to
// discovery each time: one alert per address, each saying it is private.
// Ignoring one address does not silence the next.
func TestNewDeviceAlertRotatingPrivateMAC(t *testing.T) {
	h := newAlertHarness(t)
	first := store.NetworkHost{MAC: "3e:00:00:00:00:01", IP: "192.168.2.40"}
	rotated := store.NetworkHost{MAC: "3e:00:00:00:00:02", IP: "192.168.2.40"}
	h.scan(t, 0, router)
	h.scan(t, 5*time.Minute, router, first)
	if err := h.st.NetworkHosts().SetState(t.Context(), first.MAC, store.HostIgnored); err != nil {
		t.Fatal(err)
	}
	h.scan(t, 10*time.Minute, router, rotated)
	h.scan(t, 15*time.Minute, router, rotated)
	got := h.settle(t, 20*time.Minute, router, rotated)
	if len(got) != 2 {
		t.Fatalf("notifications = %v, want one per address", got)
	}
	for _, m := range got {
		if !strings.Contains(m["message"], "private address") {
			t.Errorf("notification = %v; want it to say the address is private", m)
		}
	}
}
