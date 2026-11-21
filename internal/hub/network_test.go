// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"bufio"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/discovery"
	"github.com/gvart/hearth/internal/store"
)

func TestAPINetworkHosts(t *testing.T) {
	f := newAPIFixture(t, true)
	ctx := t.Context()
	now := time.UnixMilli(1_700_000_000_000).UTC()
	// The Pi has an agent: its interface MAC links its host to the device.
	if err := f.st.Devices().Upsert(ctx, store.Device{
		ID: "pi", Name: "pi", Hostname: "pi5", FirstSeen: now, LastSeen: now, Status: store.StatusOnline,
		Facts: json.RawMessage(`{"interfaces":[{"name":"eth0","mac":"2C:CF:67:00:00:01","ips":["192.168.2.171/24"]}]}`),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.st.NetworkHosts().RecordScan(ctx, now, time.Hour, []store.NetworkHost{
		{MAC: "2c:cf:67:00:00:01", IP: "192.168.2.171", Hostname: "pi5.local", Vendor: "Raspberry Pi"},
		{MAC: "00:11:32:00:00:02", IP: "192.168.2.20", Vendor: "Synology"},
	}); err != nil {
		t.Fatal(err)
	}
	// The Pi swept a VLAN the hub is not on and found a camera.
	if _, err := f.st.NetworkHosts().RecordScanFrom(ctx, now, time.Hour, store.ScanScope{ScannedBy: "pi"}, []store.NetworkHost{
		{MAC: "00:11:32:00:00:04", IP: "10.0.5.7"},
	}); err != nil {
		t.Fatal(err)
	}
	// Pi-hole names the NAS and knows a TV on another VLAN.
	if err := f.st.NetworkHosts().RecordImport(ctx, now, []store.ImportedHost{
		{MAC: "00:11:32:00:00:02", IP: "192.168.2.20", Hostname: "nas", HostnameSource: store.SourcePihole, Sources: []string{store.SourcePihole}},
		{MAC: "aa:bb:cc:00:00:03", IP: "192.168.20.5", Hostname: "tv", HostnameSource: store.SourceDHCP, Sources: []string{store.SourceDHCP}},
	}); err != nil {
		t.Fatal(err)
	}

	if resp := f.do(t, http.MethodGet, "/api/v1/network/hosts", "", nil); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("without a session: %d, want 401", resp.StatusCode)
	}
	cookie := sessionCookie(t, f.login(t, testPassword))
	resp := f.do(t, http.MethodGet, "/api/v1/network/hosts", "", cookie)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	got := decode[struct {
		Hosts []NetworkHostJSON `json:"hosts"`
	}](t, resp).Hosts
	if len(got) != 4 {
		t.Fatalf("hosts = %+v", got)
	}
	byMAC := map[string]NetworkHostJSON{}
	for _, h := range got {
		byMAC[h.MAC] = h
	}
	if h := byMAC["2c:cf:67:00:00:01"]; h.DeviceID != "pi" || h.Hostname != "pi5.local" || !h.LastSeen.Equal(now) ||
		strings.Join(h.Sources, ",") != "scan" || h.HostnameSource != "scan" {
		t.Errorf("Pi = %+v; want it linked to device pi, found by a scan", h)
	}
	if h := byMAC["00:11:32:00:00:02"]; h.DeviceID != "" || h.Vendor != "Synology" || h.IP != "192.168.2.20" ||
		h.Hostname != "nas" || h.HostnameSource != "pihole" || strings.Join(h.Sources, ",") != "pihole,scan" {
		t.Errorf("NAS = %+v; want it unmanaged, named by Pi-hole", h)
	}
	if h := byMAC["aa:bb:cc:00:00:03"]; h.Hostname != "tv" || strings.Join(h.Sources, ",") != "dhcp" {
		t.Errorf("TV = %+v; want the lease-only host", h)
	}
	if h := byMAC["00:11:32:00:00:04"]; h.ScannedBy != "pi" || byMAC["00:11:32:00:00:02"].ScannedBy != "" {
		t.Errorf("camera = %+v; want it scanned by pi, the NAS by the hub", h)
	}
}

func TestSSENetworkHostEvent(t *testing.T) {
	st := newTestStore(t)
	reg := NewRegistry(RegistryConfig{Store: st})
	f := newAPIFixture(t, true, func(c *Config) { c.Registry = reg })
	cookie := sessionCookie(t, f.login(t, testPassword))
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, f.srv.URL+"/api/v1/events", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(cookie)
	resp, err := f.srv.Client().Do(req) //nolint:bodyclose // closed by the defer below
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	lines := make(chan string, 16)
	go func() {
		defer close(lines)
		sc := bufio.NewScanner(resp.Body)
		for sc.Scan() {
			lines <- sc.Text()
		}
	}()
	waitLine := func(prefix string) string {
		t.Helper()
		timeout := time.After(2 * time.Second)
		for {
			select {
			case l, ok := <-lines:
				if !ok {
					t.Fatalf("stream closed waiting for %q", prefix)
				}
				if strings.HasPrefix(l, prefix) {
					return strings.TrimPrefix(l, prefix)
				}
			case <-timeout:
				t.Fatalf("no %q line", prefix)
			}
		}
	}
	waitLine(": subscribed")

	// One scan's hosts reach clients as one message each.
	reg.NetworkHosts(discovery.EventNew, []store.NetworkHost{
		{MAC: "3e:00:00:00:00:03", IP: "192.168.2.30"},
		{MAC: "3e:00:00:00:00:04", IP: "192.168.2.31"},
	})
	for _, want := range []struct{ mac, ip string }{
		{"3e:00:00:00:00:03", "192.168.2.30"},
		{"3e:00:00:00:00:04", "192.168.2.31"},
	} {
		if name := waitLine("event: "); name != discovery.EventNew {
			t.Fatalf("event %q, want %s", name, discovery.EventNew)
		}
		var ev NetworkEventJSON
		if err := json.Unmarshal([]byte(waitLine("data: ")), &ev); err != nil {
			t.Fatal(err)
		}
		if ev.Type != discovery.EventNew || ev.Host.MAC != want.mac || ev.Host.IP != want.ip {
			t.Errorf("event = %+v, want %s", ev, want.mac)
		}
	}
}
