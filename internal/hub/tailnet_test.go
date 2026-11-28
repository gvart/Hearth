// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
)

type fixedTailnet TailnetStatus

func (f fixedTailnet) Status() TailnetStatus { return TailnetStatus(f) }

var runningTailnet = fixedTailnet{
	State: TailnetRunning, Hostname: "hearth", DNSName: "hearth.tail-scale.ts.net", IPs: []string{"100.64.0.7"},
	URL: "https://hearth.tail-scale.ts.net/", AgentURL: "https://hearth.tail-scale.ts.net:7443",
}

// TestTailnetCommandHosts checks that install commands made from a browser on
// the tailnet name the tailnet, and those made on the LAN still the LAN.
func TestTailnetCommandHosts(t *testing.T) {
	hosts := []string{"hub.lan", "192.168.1.10", "localhost", "127.0.0.1", "::1"}
	tests := []struct {
		name                string
		tailnet             Tailnet
		reqHost             string
		overTLS             bool
		wantHTTP, wantAgent string
	}{
		{"tailnet name on 443", runningTailnet, "hearth.tail-scale.ts.net", true, "hearth.tail-scale.ts.net:7080", "hearth.tail-scale.ts.net"},
		{"tailnet address", runningTailnet, "100.64.0.7:7080", false, "100.64.0.7:7080", "100.64.0.7"},
		{"lan stays lan", runningTailnet, "hub.lan:7080", false, "hub.lan:7080", "hub.lan"},
		{"loopback goes to the lan name", runningTailnet, "localhost:7080", false, "hub.lan:7080", "hub.lan"},
		{"tailnet not up yet", fixedTailnet{State: TailnetStarting}, "hearth.tail-scale.ts.net", true, "hub.lan:7080", "hub.lan"},
		{"no tailnet", nil, "hearth.tail-scale.ts.net", true, "hub.lan:7080", "hub.lan"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &api{agentHosts: hosts, httpPort: "7080", tailnet: tt.tailnet}
			httpHost, agentHost, ok := a.commandHosts(tt.reqHost, tt.overTLS)
			if !ok || httpHost != tt.wantHTTP || agentHost != tt.wantAgent {
				t.Errorf("commandHosts(%q) = %q, %q, %v; want %q, %q", tt.reqHost, httpHost, agentHost, ok, tt.wantHTTP, tt.wantAgent)
			}
		})
	}
	a := &api{agentHosts: hosts, tailnet: runningTailnet}
	if got := a.certHosts(); !slices.Equal(got, append(slices.Clone(hosts), "hearth.tail-scale.ts.net", "100.64.0.7")) {
		t.Errorf("certHosts = %v, want the tailnet's names last", got)
	}
	if first, _ := a.stableHost(); first != "hub.lan" {
		t.Errorf("stableHost = %q, want the LAN name", first)
	}
}

func TestTailnetInfo(t *testing.T) {
	for _, tc := range []struct {
		name    string
		tailnet Tailnet
		want    TailnetJSON
	}{
		{"off", nil, TailnetJSON{}},
		{"running", runningTailnet, TailnetJSON{Enabled: true, TailnetStatus: TailnetStatus(runningTailnet)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := &api{tailnet: tc.tailnet}
			rec := httptest.NewRecorder()
			a.tailnetInfo(rec, httptest.NewRequest(http.MethodGet, "/api/v1/tailscale", nil))
			if rec.Code != http.StatusOK {
				t.Fatalf("status %d", rec.Code)
			}
			var got TailnetJSON
			if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
				t.Fatal(err)
			}
			if got.Enabled != tc.want.Enabled || got.URL != tc.want.URL || got.DNSName != tc.want.DNSName ||
				!slices.Equal(got.IPs, tc.want.IPs) {
				t.Errorf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}
