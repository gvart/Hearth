// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

func TestAPIAdoptNetworkHost(t *testing.T) {
	f := newAPIFixture(t, true)
	ctx := t.Context()
	now := time.UnixMilli(1_700_000_000_000).UTC()
	f.api.now = func() time.Time { return now }
	if _, err := f.st.NetworkHosts().RecordScan(ctx, now, time.Hour, []store.NetworkHost{
		{MAC: "00:11:32:00:00:05", IP: "192.168.2.50", Vendor: "LG"},
		{MAC: "2c:cf:67:00:00:01", IP: "192.168.2.171"},
	}); err != nil {
		t.Fatal(err)
	}
	// The Pi has an agent: it is that device, and cannot be adopted.
	if err := f.st.Devices().Upsert(ctx, store.Device{
		ID: "pi", Name: "pi", FirstSeen: now, LastSeen: now, Status: store.StatusOnline,
		Facts: json.RawMessage(`{"interfaces":[{"name":"eth0","mac":"2c:cf:67:00:00:01"}]}`),
	}); err != nil {
		t.Fatal(err)
	}
	const path = "/api/v1/network/hosts/00:11:32:00:00:05/"
	if resp := f.do(t, http.MethodPost, path+"adopt", `{"name":"TV"}`, nil); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("without a session: %d, want 401", resp.StatusCode)
	}
	cookie := sessionCookie(t, f.login(t, testPassword))
	tv := func() NetworkHostJSON {
		t.Helper()
		hosts := decode[struct {
			Hosts []NetworkHostJSON `json:"hosts"`
		}](t, f.do(t, http.MethodGet, "/api/v1/network/hosts", "", cookie)).Hosts
		for _, h := range hosts {
			if h.MAC == "00:11:32:00:00:05" {
				return h
			}
		}
		t.Fatalf("no TV in %+v", hosts)
		return NetworkHostJSON{}
	}

	if resp := f.do(t, http.MethodPost, path+"adopt", `{"name":"  Living room TV "}`, cookie); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("adopt: %d %s", resp.StatusCode, resp.body)
	}
	if h := tv(); h.State != store.HostAdopted || h.Name != "Living room TV" || !h.Online {
		t.Fatalf("after adopt = %+v; want it adopted, trimmed, online", h)
	}
	// Presence: online within twice the default interval of the last scan.
	f.api.now = func() time.Time { return now.Add(10 * time.Minute) }
	if !tv().Online {
		t.Error("10 minutes after the scan: want online")
	}
	f.api.now = func() time.Time { return now.Add(10*time.Minute + time.Second) }
	if tv().Online {
		t.Error("past twice the interval: want offline")
	}
	f.api.discoverInterval = time.Hour
	if !tv().Online {
		t.Error("with an hourly schedule: want online")
	}

	if resp := f.do(t, http.MethodPost, path+"unadopt", "", cookie); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("unadopt: %d %s", resp.StatusCode, resp.body)
	}
	if h := tv(); h.State != store.HostUnreviewed || h.Name != "" {
		t.Fatalf("after unadopt = %+v; want unreviewed without a name", h)
	}

	long := strings.Repeat("x", 64)
	for _, tt := range []struct {
		name, path, body string
		status           int
	}{
		{"no body", path + "adopt", "", http.StatusBadRequest},
		{"empty name", path + "adopt", `{"name":"   "}`, http.StatusBadRequest},
		{"too long", path + "adopt", `{"name":"` + long + `"}`, http.StatusBadRequest},
		{"control character", path + "adopt", `{"name":"T\u0007V"}`, http.StatusBadRequest},
		{"newline", path + "adopt", `{"name":"T\nV"}`, http.StatusBadRequest},
		{"not a MAC", "/api/v1/network/hosts/tv/adopt", `{"name":"TV"}`, http.StatusBadRequest},
		{"unknown host", "/api/v1/network/hosts/aa:aa:aa:aa:aa:aa/adopt", `{"name":"TV"}`, http.StatusNotFound},
		{"unknown host unadopt", "/api/v1/network/hosts/aa:aa:aa:aa:aa:aa/unadopt", "", http.StatusNotFound},
		{"enrolled device", "/api/v1/network/hosts/2c:cf:67:00:00:01/adopt", `{"name":"Pi"}`, http.StatusConflict},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if resp := f.do(t, http.MethodPost, tt.path, tt.body, cookie); resp.StatusCode != tt.status {
				t.Errorf("status %d, want %d (%s)", resp.StatusCode, tt.status, resp.body)
			}
		})
	}
	if resp := f.do(t, http.MethodPost, path+"adopt", `{"name":"`+strings.Repeat("é", 63)+`"}`, cookie); resp.StatusCode != http.StatusNoContent {
		t.Errorf("63 characters: %d %s, want 204", resp.StatusCode, resp.body)
	}

	entries, err := f.st.Audit().List(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, e := range entries {
		if e.Action == string(policy.NetworkHostAdopt) {
			if e.ActorKind != policy.ActorWeb {
				t.Errorf("audit entry %+v: want actor web", e)
			}
			got = append(got, e.Target+" "+e.Decision+" "+string(e.Detail))
		}
	}
	// The adopt, the unadopt, the two unknown hosts and the 63-character
	// name; invalid requests never reach policy.
	if len(got) != 5 {
		t.Fatalf("network.host.adopt audit entries = %q, want 5", got)
	}
	if !strings.Contains(strings.Join(got, "\n"), `00:11:32:00:00:05 allow {"name":"Living room TV","op":"adopt"}`) {
		t.Errorf("audit entries = %q; want the adoption with its name", got)
	}
}

func TestAPIAdoptNetworkHostDenied(t *testing.T) {
	f := newAPIFixture(t, true, withPolicy(policy.Config{Classes: map[policy.Class]policy.Mode{policy.Safe: policy.ModeDeny}}))
	ctx := t.Context()
	if _, err := f.st.NetworkHosts().RecordScan(ctx, time.Now(), time.Hour, []store.NetworkHost{
		{MAC: "00:11:32:00:00:05", IP: "192.168.2.50"},
	}); err != nil {
		t.Fatal(err)
	}
	cookie := sessionCookie(t, f.login(t, testPassword))
	if resp := f.do(t, http.MethodPost, "/api/v1/network/hosts/00:11:32:00:00:05/adopt", `{"name":"TV"}`, cookie); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status %d, want 403", resp.StatusCode)
	}
	hosts, err := f.st.NetworkHosts().List(ctx)
	if err != nil || len(hosts) != 1 || hosts[0].State != store.HostUnreviewed || hosts[0].Name != "" {
		t.Errorf("hosts = %+v, %v; a denied adoption must change nothing", hosts, err)
	}
	entries, err := f.st.Audit().List(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	denied := 0
	for _, e := range entries {
		if e.Action == string(policy.NetworkHostAdopt) && e.Decision == "deny" && e.Target == "00:11:32:00:00:05" {
			denied++
		}
	}
	if denied != 1 {
		t.Errorf("deny audit entries = %d, want 1", denied)
	}
}
