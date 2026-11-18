// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"net/http"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

func TestAPIMarkNetworkHost(t *testing.T) {
	f := newAPIFixture(t, true)
	ctx := t.Context()
	now := time.UnixMilli(1_700_000_000_000).UTC()
	if _, err := f.st.NetworkHosts().RecordScan(ctx, now, time.Hour, []store.NetworkHost{
		{MAC: "3c:2e:f9:00:00:03", IP: "192.168.2.30", Vendor: "Apple"},
	}); err != nil {
		t.Fatal(err)
	}
	const path = "/api/v1/network/hosts/3C:2E:F9:00:00:03/"
	if resp := f.do(t, http.MethodPost, path+"known", "", nil); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("without a session: %d, want 401", resp.StatusCode)
	}
	cookie := sessionCookie(t, f.login(t, testPassword))

	state := func() string {
		t.Helper()
		hosts, err := f.st.NetworkHosts().List(ctx)
		if err != nil || len(hosts) != 1 {
			t.Fatalf("List = %+v, %v", hosts, err)
		}
		return hosts[0].State
	}
	for _, step := range []struct{ verb, want string }{
		{"known", store.HostKnown},
		{"ignore", store.HostIgnored},
		{"unmark", store.HostUnreviewed},
	} {
		if resp := f.do(t, http.MethodPost, path+step.verb, "", cookie); resp.StatusCode != http.StatusNoContent {
			t.Fatalf("%s: %d %s", step.verb, resp.StatusCode, resp.body)
		}
		if got := state(); got != step.want {
			t.Errorf("after %s: state %q, want %q", step.verb, got, step.want)
		}
	}
	if resp := f.do(t, http.MethodPost, path+"ignore", "", cookie); resp.StatusCode != http.StatusNoContent {
		t.Fatal(resp.StatusCode)
	}
	got := decode[struct {
		Hosts []NetworkHostJSON `json:"hosts"`
	}](t, f.do(t, http.MethodGet, "/api/v1/network/hosts", "", cookie)).Hosts
	if len(got) != 1 || got[0].State != store.HostIgnored {
		t.Errorf("listed hosts = %+v, want the phone ignored", got)
	}

	for _, tt := range []struct {
		name, path string
		status     int
	}{
		{"unknown host", "/api/v1/network/hosts/aa:aa:aa:aa:aa:aa/known", http.StatusNotFound},
		{"not a MAC", "/api/v1/network/hosts/phone/known", http.StatusBadRequest},
		{"EUI-64", "/api/v1/network/hosts/00:00:00:00:fe:80:00:00/known", http.StatusBadRequest},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if resp := f.do(t, http.MethodPost, tt.path, "", cookie); resp.StatusCode != tt.status {
				t.Errorf("status %d, want %d (%s)", resp.StatusCode, tt.status, resp.body)
			}
		})
	}

	entries, err := f.st.Audit().List(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	var marks []string
	for _, e := range entries {
		if e.Action == string(policy.NetworkHostMark) {
			if e.ActorKind != policy.ActorWeb {
				t.Errorf("audit entry %+v: want actor web", e)
			}
			marks = append(marks, e.Target+" "+e.Decision+" "+string(e.Detail))
		}
	}
	// Four marks and the unknown host; the malformed MACs never reach policy.
	if len(marks) != 5 {
		t.Errorf("network.host.mark audit entries = %q, want 5", marks)
	}
}

func TestAPIMarkNetworkHostDenied(t *testing.T) {
	f := newAPIFixture(t, true, withPolicy(policy.Config{Classes: map[policy.Class]policy.Mode{policy.Safe: policy.ModeDeny}}))
	ctx := t.Context()
	if _, err := f.st.NetworkHosts().RecordScan(ctx, time.Now(), time.Hour, []store.NetworkHost{
		{MAC: "3c:2e:f9:00:00:03", IP: "192.168.2.30"},
	}); err != nil {
		t.Fatal(err)
	}
	cookie := sessionCookie(t, f.login(t, testPassword))
	if resp := f.do(t, http.MethodPost, "/api/v1/network/hosts/3c:2e:f9:00:00:03/ignore", "", cookie); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status %d, want 403", resp.StatusCode)
	}
	hosts, err := f.st.NetworkHosts().List(ctx)
	if err != nil || len(hosts) != 1 || hosts[0].State != store.HostUnreviewed {
		t.Errorf("hosts = %+v, %v; a denied mark must change nothing", hosts, err)
	}
}
