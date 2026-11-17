// SPDX-License-Identifier: AGPL-3.0-only

package cluster

// Live device events on every hub of a cluster (#27): followers publish the
// events of the entries they apply; the leader publishes from its own calls.

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/hub"
	"github.com/gvart/hearth/internal/store"
)

// Bounds of the event tests. An online or updated event reaches a follower
// one Raft round after the leader's write; offline needs the leader's sweep.
const (
	eventWithin   = 2 * time.Second
	testOffline   = 800 * time.Millisecond
	offlineWithin = testOffline + 2*time.Second
)

// sseEvent is one server-sent event: its name and its raw JSON data.
type sseEvent struct {
	name string
	data map[string]any
}

func (e sseEvent) device() map[string]any {
	d, _ := e.data["device"].(map[string]any)
	return d
}

func (e sseEvent) deviceID() string {
	id, _ := e.device()["id"].(string)
	return id
}

// sseStream is an /api/v1/events subscription over HTTPS.
type sseStream struct {
	mu     sync.Mutex
	events []sseEvent
}

func (s *sseStream) all() []sseEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]sseEvent(nil), s.events...)
}

// of returns the events of the given names, in order.
func (s *sseStream) of(names ...string) []sseEvent {
	var out []sseEvent
	for _, e := range s.all() {
		for _, n := range names {
			if e.name == n {
				out = append(out, e)
			}
		}
	}
	return out
}

func (s *sseStream) waitFor(t *testing.T, name string, n int, within time.Duration) sseEvent {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		if got := s.of(name); len(got) >= n {
			return got[n-1]
		}
		if time.Now().After(deadline) {
			t.Fatalf("no %d× %s within %v; got %v", n, name, within, names(s.all()))
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func names(es []sseEvent) []string {
	var out []string
	for _, e := range es {
		out = append(out, e.name)
	}
	return out
}

// setPassword sets the admin password through the leader and waits until
// every hub has it.
func setPassword(t *testing.T, hubs []*testHub, leader *testHub) {
	t.Helper()
	if err := hub.SetAdminPassword(t.Context(), leader.st, leader.pol, "test", "correct horse"); err != nil {
		t.Fatal(err)
	}
	for _, h := range hubs {
		eventually(t, "password on "+h.ID(), func() bool {
			_, err := h.st.Admin().PasswordHash(t.Context())
			return err == nil
		})
	}
}

// subscribe logs in to h's API and streams its /api/v1/events until the test
// ends. It returns once the hub confirmed the subscription.
func subscribe(t *testing.T, h *testHub) (*sseStream, *apiClient) {
	t.Helper()
	api := &apiClient{t: t, base: h.url, c: tlsClient(h.ca)}
	if code, body := api.do(http.MethodPost, "/api/v1/login", map[string]string{"password": "correct horse"}); code != http.StatusOK {
		t.Fatalf("login on %s: %d %s", h.ID(), code, body)
	}
	// A follower forwards the session write; wait until it applied it.
	eventually(t, "the session on "+h.ID(), func() bool {
		code, _ := api.do(http.MethodGet, "/api/v1/session", nil)
		return code == http.StatusOK
	})
	ctx, cancel := context.WithCancel(context.Background())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.url+"/api/v1/events", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range api.cook {
		req.AddCookie(c)
	}
	resp, err := api.c.Do(req) //nolint:bodyclose // closed in t.Cleanup below
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("events on %s: %d", h.ID(), resp.StatusCode)
	}
	s := &sseStream{}
	subscribed, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		sc := bufio.NewScanner(resp.Body)
		var name, data string
		for sc.Scan() {
			switch line := sc.Text(); {
			case line == ": subscribed":
				close(subscribed)
			case strings.HasPrefix(line, "event: "):
				name = strings.TrimPrefix(line, "event: ")
			case strings.HasPrefix(line, "data: "):
				data = strings.TrimPrefix(line, "data: ")
			case line == "" && name != "":
				var m map[string]any
				if err := json.Unmarshal([]byte(data), &m); err != nil {
					t.Errorf("bad event data %q: %v", data, err)
				}
				s.mu.Lock()
				s.events = append(s.events, sseEvent{name: name, data: m})
				s.mu.Unlock()
				name, data = "", ""
			}
		}
	}()
	t.Cleanup(func() {
		cancel()
		_ = resp.Body.Close()
		<-done
	})
	select {
	case <-subscribed:
	case <-time.After(waitFor):
		t.Fatalf("no subscription on %s", h.ID())
	}
	return s, api
}

// deviceItem returns the device as h's /api/v1/devices lists it.
func deviceItem(t *testing.T, api *apiClient, id string) map[string]any {
	t.Helper()
	code, body := api.do(http.MethodGet, "/api/v1/devices", nil)
	if code != http.StatusOK {
		t.Fatalf("list devices: %d %s", code, body)
	}
	var out struct {
		Devices []map[string]any `json:"devices"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	for _, d := range out.Devices {
		if d["id"] == id {
			return d
		}
	}
	t.Fatalf("device %s not listed", id)
	return nil
}

// transitions are the online and offline events of the hub's registry, as
// "type id" strings.
func transitions(h *testHub) []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []string
	for _, e := range h.events {
		if e.Type != hub.EventDeviceUpdated {
			out = append(out, e.Type+" "+e.Device.ID)
		}
	}
	return out
}

// noRepeats fails if two consecutive events of h are the same event.
func noRepeats(t *testing.T, h *testHub) {
	t.Helper()
	h.mu.Lock()
	defer h.mu.Unlock()
	for i := 1; i < len(h.events); i++ {
		if reflect.DeepEqual(h.events[i], h.events[i-1]) {
			t.Errorf("%s published %s for %s twice in a row", h.ID(), h.events[i].Type, h.events[i].Device.ID)
		}
	}
}

// TestFollowerSSE: a UI on a follower receives online, updated and offline
// for a device whose agent streams to the leader, in order, within bounds,
// with the same payload as the follower's device list. The leader publishes
// each of them once.
func TestFollowerSSE(t *testing.T) {
	hubs := startHubs(t, hubOpts{offlineAfter: testOffline, flushEvery: 200 * time.Millisecond})
	leader := leaderHub(t, hubs)
	f := followers(hubs, leader)[0]
	setPassword(t, hubs, leader)
	onF, apiF := subscribe(t, f)
	onL, _ := subscribe(t, leader)

	cert := enrollTestDevice(t, leader, "pi")
	start := time.Now()
	agent := runTestAgent(t, []*testHub{leader}, "pi", cert, 50*time.Millisecond, 50*time.Millisecond)
	online := onF.waitFor(t, hub.EventDeviceOnline, 1, eventWithin)
	if online.deviceID() != "pi" || online.device()["status"] != store.StatusOnline {
		t.Fatalf("online event on the follower: %v", online.data)
	}
	t.Logf("follower: online %v after the agent started", time.Since(start).Round(time.Millisecond))
	// The first heartbeat sets the boot time; batches then move last_seen.
	first := onF.waitFor(t, hub.EventDeviceUpdated, 1, eventWithin)
	later := onF.waitFor(t, hub.EventDeviceUpdated, 3, eventWithin)
	if first.device()["boot_time"] == nil {
		t.Errorf("first update carries no boot time: %v", first.data)
	}
	if a, b := first.device()["last_seen"].(string), later.device()["last_seen"].(string); b <= a {
		t.Errorf("last_seen did not move on the follower: %s then %s", a, b)
	}

	agent.stop()
	stopped := time.Now()
	off := onF.waitFor(t, hub.EventDeviceOffline, 1, offlineWithin)
	t.Logf("follower: offline %v after the agent stopped", time.Since(stopped).Round(time.Millisecond))
	if off.device()["status"] != store.StatusOffline {
		t.Errorf("offline event: %v", off.data)
	}
	// Same shape and values as the follower's own list, which nothing
	// changes after the offline transition.
	if item := deviceItem(t, apiF, "pi"); !reflect.DeepEqual(off.device(), item) {
		t.Errorf("offline event device = %v\nlist item = %v", off.device(), item)
	}
	onL.waitFor(t, hub.EventDeviceOffline, 1, offlineWithin)
	time.Sleep(300 * time.Millisecond) // anything late would show now

	order := []string{hub.EventDeviceOnline, hub.EventDeviceOffline}
	for name, s := range map[string]*sseStream{"follower": onF, "leader": onL} {
		if got := names(s.of(order...)); !reflect.DeepEqual(got, order) {
			t.Errorf("%s transitions = %v, want %v", name, got, order)
		}
		all := s.all()
		if all[len(all)-1].name != hub.EventDeviceOffline {
			t.Errorf("%s: events after offline: %v", name, names(all))
		}
	}
	for _, h := range hubs {
		if got := transitions(h); !reflect.DeepEqual(got, []string{"device.online pi", "device.offline pi"}) {
			t.Errorf("%s transitions = %v", h.ID(), got)
		}
		noRepeats(t, h)
	}
}

// TestSlowSubscriberDoesNotBlockApplies: a follower subscriber that never
// reads is dropped once its buffer is full; the follower keeps applying, and
// other subscribers keep receiving.
func TestSlowSubscriberDoesNotBlockApplies(t *testing.T) {
	hubs := startHubs(t, hubOpts{offlineAfter: time.Minute, flushEvery: time.Minute})
	leader := leaderHub(t, hubs)
	f := followers(hubs, leader)[0]
	stuck, unsubscribe := f.reg.Subscribe()
	defer unsubscribe()
	upsert(t, leader.testNode, "pi")

	const writes = 200
	ctx := t.Context()
	start := time.Now()
	for i := 1; i <= writes; i++ {
		boot := time.UnixMilli(int64(i) * 1000).UTC()
		if _, err := leader.st.Devices().SetBootTime(ctx, "pi", boot); err != nil {
			t.Fatal(err)
		}
	}
	want := time.UnixMilli(writes * 1000).UTC()
	eventually(t, "the follower to apply every write", func() bool {
		d, err := f.st.Devices().Get(ctx, "pi")
		return err == nil && d.BootTime.Equal(want)
	})
	t.Logf("%d writes applied on the follower in %v", writes, time.Since(start).Round(time.Millisecond))
	// The reading subscriber (the test hub's own) got every update.
	eventually(t, "every update on the reading subscriber", func() bool {
		return len(f.eventsOf(hub.EventDeviceUpdated)) == writes
	})
	// The stuck one holds a full buffer and was closed.
	n := 0
	for range stuck {
		n++
	}
	if n == 0 || n >= writes {
		t.Errorf("stuck subscriber held %d events, want a full buffer then a close", n)
	}
}

// TestLeadershipChangeMidStream: leadership moves while an agent streams;
// every hub publishes the device's transitions exactly once, in order, and
// its events follow the agent to the new leader.
func TestLeadershipChangeMidStream(t *testing.T) {
	hubs := startHubs(t, hubOpts{offlineAfter: testOffline, flushEvery: 200 * time.Millisecond})
	leader := leaderHub(t, hubs)
	setPassword(t, hubs, leader)
	streams := map[*testHub]*sseStream{}
	for _, h := range hubs {
		streams[h], _ = subscribe(t, h)
	}
	cert := enrollTestDevice(t, leader, "pi")
	agent := runTestAgent(t, hubs, "pi", cert, 50*time.Millisecond, 50*time.Millisecond)
	for _, h := range hubs {
		streams[h].waitFor(t, hub.EventDeviceOnline, 1, eventWithin)
	}
	eventually(t, "the agent on the leader", func() bool { return agent.url() == leader.url })
	before := map[*testHub]int{}
	for _, h := range hubs {
		before[h] = len(streams[h].of(hub.EventDeviceUpdated))
	}

	if err := leader.raft.LeadershipTransfer().Error(); err != nil {
		t.Fatalf("LeadershipTransfer: %v", err)
	}
	next := leaderHub(t, hubs)
	if next == leader {
		t.Fatal("leadership did not move")
	}
	eventually(t, "the agent on the new leader", func() bool { return agent.url() == next.url })
	// Its Hello on the new leader is an update everywhere, the old leader
	// included: it now publishes from the log.
	for _, h := range hubs {
		streams[h].waitFor(t, hub.EventDeviceUpdated, before[h]+1, eventWithin)
	}

	agent.stop()
	for _, h := range hubs {
		streams[h].waitFor(t, hub.EventDeviceOffline, 1, offlineWithin)
	}
	time.Sleep(300 * time.Millisecond)
	for _, h := range hubs {
		want := []string{"device.online pi", "device.offline pi"}
		if got := transitions(h); !reflect.DeepEqual(got, want) {
			t.Errorf("%s transitions = %v, want %v", h.ID(), got, want)
		}
		order := []string{hub.EventDeviceOnline, hub.EventDeviceOffline}
		if got := names(streams[h].of(order...)); !reflect.DeepEqual(got, order) {
			t.Errorf("%s SSE transitions = %v", h.ID(), got)
		}
		noRepeats(t, h)
	}
	if n := sweptOffline(next); n != 1 {
		t.Errorf("new leader swept %d, want 1", n)
	}
	for _, h := range hubs {
		if h != next && sweptOffline(h) != 0 {
			t.Errorf("%s swept %d devices", h.ID(), sweptOffline(h))
		}
	}
}
