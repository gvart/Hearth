// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/discovery"
	"github.com/gvart/hearth/internal/policy"
)

// fakeScanner is a NetworkScanner that runs one scan at a time, as
// discovery.Scanner does. Before accepting it fails with before; once
// accepted it waits for release and ends with sum and after.
type fakeScanner struct {
	mu            sync.Mutex
	before, after error
	sum           discovery.ScanSummary
	release       chan struct{}
	actor         string
}

func (f *fakeScanner) ScanAs(ctx context.Context, kind, id string, accepted func()) (discovery.ScanSummary, error) {
	if !f.mu.TryLock() {
		return discovery.ScanSummary{}, discovery.ErrScanRunning
	}
	defer f.mu.Unlock()
	if f.before != nil {
		return discovery.ScanSummary{}, f.before
	}
	f.actor = kind + "/" + id
	accepted()
	select {
	case <-f.release:
	case <-ctx.Done():
		return discovery.ScanSummary{}, ctx.Err()
	}
	return f.sum, f.after
}

// scanFixture is an API fixture whose network scans run on scanner.
func scanFixture(t *testing.T, scanner NetworkScanner) (*apiFixture, *http.Cookie, <-chan Event) {
	t.Helper()
	var scans *NetworkScans
	f := newAPIFixture(t, true, func(c *Config) {
		scans = NewNetworkScans(scanner, c.Registry, c.Log)
		c.NetworkScans = scans
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = scans.Run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	events, unsubscribe := f.api.registry.SubscribeUI()
	t.Cleanup(unsubscribe)
	return f, sessionCookie(t, f.login(t, testPassword)), events
}

func scanDone(t *testing.T, events <-chan Event) NetworkScanJSON {
	t.Helper()
	for {
		select {
		case ev := <-events:
			if ev.Type == EventNetworkScanDone {
				return *ev.Scan
			}
		case <-time.After(5 * time.Second):
			t.Fatal("no network.scan.done event")
		}
	}
}

func TestAPINetworkScan(t *testing.T) {
	tests := []struct {
		name       string
		before     error
		after      error
		wantStatus int
		wantCode   string
		// wantDone is the event the scan ends with; nil if it never ran.
		wantDone *NetworkScanJSON
	}{
		{
			name: "allowed", wantStatus: http.StatusAccepted,
			wantDone: &NetworkScanJSON{Type: EventNetworkScanDone, Hosts: 14, New: 3, Returned: 1, DurationMS: 1500},
		},
		{
			name: "fails after it started", after: errors.New("sweep: boom"), wantStatus: http.StatusAccepted,
			wantDone: &NetworkScanJSON{Type: EventNetworkScanDone, Error: "sweep: boom"},
		},
		{name: "nothing to scan", before: discovery.ErrNoSubnet, wantStatus: http.StatusConflict, wantCode: "no_subnet"},
		{name: "denied", before: policy.ErrDenied, wantStatus: http.StatusForbidden, wantCode: "forbidden"},
		{name: "store down", before: errors.New("boom"), wantStatus: http.StatusInternalServerError, wantCode: "internal"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sc := &fakeScanner{
				before: tt.before, after: tt.after, release: make(chan struct{}),
				sum: discovery.ScanSummary{Hosts: 14, New: 3, Returned: 1, Duration: 1500 * time.Millisecond},
			}
			close(sc.release)
			f, cookie, events := scanFixture(t, sc)
			resp := f.do(t, http.MethodPost, "/api/v1/network/scan", "", cookie)
			if resp.StatusCode != tt.wantStatus {
				t.Fatalf("status %d (%s), want %d", resp.StatusCode, resp.body, tt.wantStatus)
			}
			if tt.wantCode != "" {
				if e := decode[ErrorJSON](t, resp); e.Code != tt.wantCode {
					t.Errorf("code = %q, want %q", e.Code, tt.wantCode)
				}
			}
			if tt.wantDone == nil {
				return
			}
			if got := scanDone(t, events); got != *tt.wantDone {
				t.Errorf("done = %+v, want %+v", got, *tt.wantDone)
			}
			if !strings.HasPrefix(sc.actor, policy.ActorWeb+"/") {
				t.Errorf("scan actor = %q, want web", sc.actor)
			}
		})
	}
}

func TestAPINetworkScanNeedsASession(t *testing.T) {
	f, _, _ := scanFixture(t, &fakeScanner{release: make(chan struct{})})
	if resp := f.do(t, http.MethodPost, "/api/v1/network/scan", "", nil); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("without a session: %d, want 401", resp.StatusCode)
	}
}

// A scan asked for while one runs is refused with 409, and the running one
// still ends with its event.
func TestAPINetworkScanOneAtATime(t *testing.T) {
	sc := &fakeScanner{release: make(chan struct{}), sum: discovery.ScanSummary{Hosts: 2}}
	f, cookie, events := scanFixture(t, sc)
	if resp := f.do(t, http.MethodPost, "/api/v1/network/scan", "", cookie); resp.StatusCode != http.StatusAccepted {
		t.Fatalf("first scan: %d (%s)", resp.StatusCode, resp.body)
	}
	resp := f.do(t, http.MethodPost, "/api/v1/network/scan", "", cookie)
	if resp.StatusCode != http.StatusConflict || decode[ErrorJSON](t, resp).Code != "scan_running" {
		t.Fatalf("second scan: %d (%s), want 409 scan_running", resp.StatusCode, resp.body)
	}
	close(sc.release)
	if got := scanDone(t, events); got.Hosts != 2 || got.Error != "" {
		t.Errorf("done = %+v", got)
	}
}

// A scan policy denies is refused with 403 and audited as a denial with the
// web actor, and sweeps nothing: here a real scanner, whose subnet is never
// swept since policy decides first.
func TestAPINetworkScanDeniedByPolicy(t *testing.T) {
	var scans *NetworkScans
	f := newAPIFixture(t, true, func(c *Config) {
		scanner := discovery.New(discovery.Config{
			Subnets: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/30")},
			Hosts:   c.Store.NetworkHosts(), Policy: c.Policy,
		})
		scans = NewNetworkScans(scanner, c.Registry, c.Log)
		c.NetworkScans = scans
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = scans.Run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	cookie := sessionCookie(t, f.login(t, testPassword))
	f.api.policy.SetConfig(policy.Config{Actors: map[string]map[policy.Class]policy.Mode{
		policy.ActorWeb: {policy.Read: policy.ModeDeny},
	}})

	resp := f.do(t, http.MethodPost, "/api/v1/network/scan", "", cookie)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status %d (%s), want 403", resp.StatusCode, resp.body)
	}
	entries, err := f.st.Audit().List(t.Context(), 20)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, e := range entries {
		if e.Action == string(policy.NetworkScan) {
			found = true
			if e.ActorKind != policy.ActorWeb || e.Decision != policy.Deny || e.Target != "192.0.2.0/30" {
				t.Errorf("audit entry = %+v; want a web denial of the subnet", e)
			}
		}
	}
	if !found {
		t.Error("the denied scan was not audited")
	}
	if hosts, _ := f.st.NetworkHosts().List(t.Context()); len(hosts) != 0 {
		t.Errorf("a denied scan recorded %v", hosts)
	}
}

// The end of a scan reaches the UI's event stream with its counts.
func TestAPINetworkScanDoneEvent(t *testing.T) {
	f := newAPIFixture(t, true)
	cookie := sessionCookie(t, f.login(t, testPassword))
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, f.srv.URL+"/api/v1/events", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(cookie)
	resp, err := f.srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	sc := bufio.NewScanner(resp.Body)
	if !sc.Scan() || sc.Text() != ": subscribed" {
		t.Fatalf("first line %q", sc.Text())
	}
	f.api.registry.ScanDone(NetworkScanJSON{Type: EventNetworkScanDone, Hosts: 5, New: 2, DurationMS: 900})
	var name string
	for sc.Scan() {
		line := sc.Text()
		if v, ok := strings.CutPrefix(line, "event: "); ok {
			name = v
		}
		if v, ok := strings.CutPrefix(line, "data: "); ok {
			if name != EventNetworkScanDone {
				t.Fatalf("event %q", name)
			}
			var got map[string]any
			if err := json.Unmarshal([]byte(v), &got); err != nil {
				t.Fatal(err)
			}
			if got["hosts"] != float64(5) || got["new"] != float64(2) || got["returned"] != float64(0) ||
				got["duration_ms"] != float64(900) || got["error"] != nil {
				t.Errorf("data = %s", v)
			}
			return
		}
	}
	t.Fatal("no event")
}
