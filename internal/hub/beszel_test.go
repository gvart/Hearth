// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/integrations/beszel"
	"github.com/gvart/hearth/internal/store"
)

type fixedSnapshot beszel.Snapshot

func (s fixedSnapshot) Snapshot() beszel.Snapshot { return beszel.Snapshot(s) }

func TestAPIBeszelSystemsNotConfigured(t *testing.T) {
	f := newAPIFixture(t, true)
	if resp := f.do(t, http.MethodGet, "/api/v1/beszel/systems", "", nil); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("without a session: %d, want 401", resp.StatusCode)
	}
	cookie := sessionCookie(t, f.login(t, testPassword))
	resp := f.do(t, http.MethodGet, "/api/v1/beszel/systems", "", cookie)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	got := decode[BeszelSystemsJSON](t, resp)
	if got.Status != "not_configured" || got.Systems == nil || len(got.Systems) != 0 || got.ReadAt != nil {
		t.Errorf("body = %+v", got)
	}
}

// Each system is matched to the enrolled device or the network host it is,
// so it is listed once: by address first, then by name.
func TestAPIBeszelSystems(t *testing.T) {
	now := time.UnixMilli(1_700_000_000_000).UTC()
	snap := fixedSnapshot{State: beszel.StateOK, ReadAt: now, Systems: []beszel.System{
		{ID: "1", Name: "raspberry", Host: "192.168.2.171", Status: beszel.StatusUp, CPU: 5},
		{ID: "2", Name: "Mini.lan", Host: "mini.lan", Status: beszel.StatusUp},
		{ID: "3", Name: "nas", Host: "192.168.2.20", Status: beszel.StatusUp},
		{ID: "4", Name: "tv", Host: "tv.lan", Status: beszel.StatusDown},
		{ID: "5", Name: "cloud", Host: "203.0.113.9", Status: beszel.StatusPaused},
		{ID: "6", Name: "lo", Host: "127.0.0.1", Status: beszel.StatusPending},
	}}
	f := newAPIFixture(t, true, func(c *Config) { c.Beszel = snap })
	ctx := t.Context()
	for _, d := range []store.Device{
		{
			ID: "pi", Name: "Pi 5", Hostname: "pi5", FirstSeen: now, LastSeen: now, Status: store.StatusOnline,
			Facts: json.RawMessage(`{"interfaces":[{"name":"eth0","mac":"2c:cf:67:00:00:01","ips":["192.168.2.171/24"]}]}`),
		},
		{
			ID: "mini", Name: "Mac mini", Hostname: "MINI.local", FirstSeen: now, LastSeen: now, Status: store.StatusOnline,
			Facts: json.RawMessage(`{"interfaces":[{"name":"lo0","ips":["127.0.0.1/8"]}]}`),
		},
	} {
		if err := f.st.Devices().Upsert(ctx, d); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.st.NetworkHosts().RecordScan(ctx, now, time.Hour, []store.NetworkHost{
		{MAC: "2c:cf:67:00:00:01", IP: "192.168.2.171"},
		{MAC: "00:11:32:00:00:02", IP: "192.168.2.20"},
		{MAC: "aa:bb:cc:00:00:03", IP: "192.168.2.30", Hostname: "tv.local"},
	}); err != nil {
		t.Fatal(err)
	}
	cookie := sessionCookie(t, f.login(t, testPassword))
	resp := f.do(t, http.MethodGet, "/api/v1/beszel/systems", "", cookie)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	got := decode[BeszelSystemsJSON](t, resp)
	if got.Status != "ok" || got.ReadAt == nil || !got.ReadAt.Equal(now) || len(got.Systems) != 6 {
		t.Fatalf("body = %+v", got)
	}
	want := []struct{ device, mac string }{
		{"pi", ""},                // by IP
		{"mini", ""},              // by hostname, case and .local ignored
		{"", "00:11:32:00:00:02"}, // a network host, by IP
		{"", "aa:bb:cc:00:00:03"}, // a network host, by name
		{"", ""},                  // unknown
		{"", ""},                  // loopback never matches
	}
	for i, w := range want {
		s := got.Systems[i]
		if s.DeviceID != w.device || s.NetworkMAC != w.mac {
			t.Errorf("system %s matched device %q host %q; want %q %q", s.Name, s.DeviceID, s.NetworkMAC, w.device, w.mac)
		}
	}
	if got.Systems[0].DeviceName != "Pi 5" || got.Systems[0].CPU != 5 {
		t.Errorf("system 0 = %+v", got.Systems[0])
	}
}

func TestAPIBeszelSystemsUnavailable(t *testing.T) {
	snap := fixedSnapshot{State: beszel.StateUnavailable, Error: "beszel login: HTTP 400"}
	f := newAPIFixture(t, true, func(c *Config) { c.Beszel = snap })
	cookie := sessionCookie(t, f.login(t, testPassword))
	got := decode[BeszelSystemsJSON](t, f.do(t, http.MethodGet, "/api/v1/beszel/systems", "", cookie))
	if got.Status != "unavailable" || got.Error != "beszel login: HTTP 400" || got.ReadAt != nil || len(got.Systems) != 0 {
		t.Errorf("body = %+v", got)
	}
}
