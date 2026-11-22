// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/cluster"
	"github.com/gvart/hearth/internal/pki"
	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

// deviceHubMasters is an AP cluster as a device's page sees it: the counts
// of autoHubMasters and its gossip members.
type deviceHubMasters struct {
	*autoHubMasters
	members []cluster.MemberInfo
}

func (m deviceHubMasters) Status() cluster.Status {
	return cluster.Status{NodeID: "hub-a", Members: m.members}
}

func deviceHubFixture(t *testing.T, pcfg policy.Config, masters, storage int, members ...cluster.MemberInfo) *apiFixture {
	t.Helper()
	m := deviceHubMasters{autoHubMasters: &autoHubMasters{masters: masters, storage: storage}, members: members}
	f := newAPIFixture(t, true, withPolicy(pcfg), func(c *Config) {
		c.ClusterAdmin, c.Masters = &fakeClusterAdmin{}, m
	})
	f.api.argon = testArgon
	for _, d := range []store.Device{
		{ID: "mac", Name: "mac", OS: "darwin 26.1", Arch: "arm64", Status: store.StatusOnline},
		{ID: "pi", Name: "pi", OS: "debian 12", Arch: "arm64", Status: store.StatusOnline},
		{ID: "old-pi", Name: "old-pi", OS: "raspbian 12", Arch: "arm", Status: store.StatusOnline},
		{ID: "pc", Name: "pc", OS: "Microsoft Windows 11 Pro", Arch: "amd64", Status: store.StatusOnline},
	} {
		if err := f.st.Devices().Upsert(t.Context(), d); err != nil {
			t.Fatal(err)
		}
	}
	return f
}

// A device that is no hub gets a join token minted for it on its page,
// behind the password again; the command re-runs the installer with it.
// Once a hub joined with it, the device's hub is that member.
func TestDeviceHubMake(t *testing.T) {
	f := deviceHubFixture(t, policy.Config{}, 1, 1, cluster.MemberInfo{
		ID: "mac-1a2b", State: cluster.MemberAlive,
		Roles:        cluster.RolesOf(cluster.RoleStorage, cluster.RoleMaster, cluster.RoleNode),
		AllowedRoles: cluster.HubRoles,
	})
	c := sessionCookie(t, f.login(t, testPassword))
	resp := f.do(t, http.MethodGet, "/api/v1/devices/mac/hub", "", c)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET hub = %d %s", resp.StatusCode, resp.body)
	}
	if got := decode[DeviceHubJSON](t, resp); got.NodeID != "" || got.Masters != 1 || got.MaxMasters != cluster.MaxAutoMasters ||
		!strings.HasSuffix(got.AgentOnlyCommand, "| sh -s -- --agent-only") {
		t.Fatalf("GET hub of an agent = %+v", got)
	}

	resp = f.do(t, http.MethodPost, "/api/v1/devices/mac/hub", "", c)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("POST hub = %d %s", resp.StatusCode, resp.body)
	}
	made := decode[MakeHubJSON](t, resp)
	if made.Roles != cluster.HubRoles {
		t.Fatalf("roles = %s, want storage and master under the caps", made.Roles)
	}
	env, rest, ok := strings.Cut(made.Command, " sh -s -- ")
	if !ok || rest != "--make-hub https://192.0.2.10:7443" || !strings.Contains(env, "| HEARTH_JOIN_TOKEN=") {
		t.Fatalf("command = %q", made.Command)
	}
	_, enc, _ := strings.Cut(env, "HEARTH_JOIN_TOKEN=")
	tok, err := pki.ParseJoinToken(enc)
	if err != nil {
		t.Fatalf("the command's token: %v", err)
	}
	for _, where := range []string{f.logs.String(), allAuditText(t, f)} {
		if strings.Contains(where, tok.Secret) || strings.Contains(where, enc) {
			t.Fatal("the join token is in the logs or the audit log")
		}
	}
	entries := auditOf(t, f, policy.ClusterTokenCreate)
	if len(entries) != 1 || entries[0].Target != "mac" || entries[0].Result != "ok" ||
		!strings.Contains(string(entries[0].Detail), `"via":"device"`) {
		t.Fatalf("cluster.token.create audit = %+v", entries)
	}

	// The device's hub joins with it: the page shows the member.
	if _, err := f.st.JoinTokens().Use(t.Context(), tok.Secret, "mac-1a2b", time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := f.st.Hubs().RecordCert(t.Context(), "c-1", "mac-1a2b"); err != nil {
		t.Fatal(err)
	}
	got := decode[DeviceHubJSON](t, f.do(t, http.MethodGet, "/api/v1/devices/mac/hub", "", c))
	if got.NodeID != "mac-1a2b" || got.State != cluster.MemberAlive || got.Roles != cluster.HubRoles ||
		got.AllowedRoles != cluster.HubRoles {
		t.Fatalf("GET hub of a hub = %+v", got)
	}
	resp = f.do(t, http.MethodPost, "/api/v1/devices/mac/hub", "", c)
	if resp.StatusCode != http.StatusConflict || errorCode(t, resp) != "already_hub" {
		t.Fatalf("POST hub of a hub = %d %s, want 409 already_hub", resp.StatusCode, resp.body)
	}
}

// Past the master cap a device's token grants storage only.
func TestDeviceHubMakeStorageOnly(t *testing.T) {
	f := deviceHubFixture(t, policy.Config{}, cluster.MaxAutoMasters, 3)
	c := sessionCookie(t, f.login(t, testPassword))
	resp := f.do(t, http.MethodPost, "/api/v1/devices/pi/hub", "", c)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("POST hub = %d %s", resp.StatusCode, resp.body)
	}
	if got := decode[MakeHubJSON](t, resp); got.Roles != cluster.RolesOf(cluster.RoleStorage) {
		t.Fatalf("roles = %s, want storage only", got.Roles)
	}
}

// Refusals mint no join token.
func TestDeviceHubMakeRefused(t *testing.T) {
	for _, tc := range []struct {
		name             string
		pcfg             policy.Config
		storage          int
		stale            bool
		device           string
		status           int
		code             string
		audited          bool
		withoutAPCluster bool
	}{
		{name: "no re-auth", stale: true, device: "pi", status: http.StatusForbidden, code: "reauth_required", audited: true},
		{
			name: "denied", device: "pi", status: http.StatusForbidden, code: "forbidden", audited: true,
			pcfg: policy.Config{Actors: map[string]map[policy.Class]policy.Mode{policy.ActorWeb: {policy.Dangerous: policy.ModeDeny}}},
		},
		{name: "storage cap full", storage: cluster.MaxAutoStorage, device: "pi", status: http.StatusConflict, code: "hubs_full"},
		{name: "32-bit device", device: "old-pi", status: http.StatusConflict, code: "not_capable"},
		{name: "windows", device: "pc", status: http.StatusConflict, code: "not_capable"},
		{name: "unknown device", device: "nope", status: http.StatusNotFound, code: "not_found"},
		{name: "outside an AP cluster", withoutAPCluster: true, device: "pi", status: http.StatusNotFound, code: "not_ap_cluster"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var f *apiFixture
			if tc.withoutAPCluster {
				f = newAPIFixture(t, true)
				f.api.argon = testArgon
			} else {
				f = deviceHubFixture(t, tc.pcfg, 1, tc.storage)
			}
			c := sessionCookie(t, f.login(t, testPassword))
			if tc.stale {
				c = staleSession(t, f)
			}
			resp := f.do(t, http.MethodPost, "/api/v1/devices/"+tc.device+"/hub", "", c)
			if resp.StatusCode != tc.status || errorCode(t, resp) != tc.code {
				t.Fatalf("POST hub = %d %s, want %d %s", resp.StatusCode, resp.body, tc.status, tc.code)
			}
			if all, _, err := f.st.JoinTokens().PendingMinted(t.Context(), time.Now()); err != nil || all != 0 {
				t.Fatalf("%d join tokens minted, %v; want none", all, err)
			}
			if e := auditOf(t, f, policy.ClusterTokenCreate); (len(e) == 1 && e[0].Decision == policy.Deny) != tc.audited {
				t.Fatalf("cluster.token.create audit = %+v, want a denial %v", e, tc.audited)
			}
		})
	}
	t.Run("GET outside an AP cluster", func(t *testing.T) {
		f := newAPIFixture(t, true)
		f.api.argon = testArgon
		c := sessionCookie(t, f.login(t, testPassword))
		if resp := f.do(t, http.MethodGet, "/api/v1/devices/pi/hub", "", c); resp.StatusCode != http.StatusNotFound {
			t.Fatalf("GET hub outside AP = %d, want 404", resp.StatusCode)
		}
	})
}

// A promotion to master hands the CA key: on the web it needs the password
// again; storage and demotions do not.
func TestClusterPromoteMasterReauth(t *testing.T) {
	admin := &fakeClusterAdmin{}
	f, stale := clusterFixture(t, admin)
	f.api.argon = testArgon
	resp := f.do(t, http.MethodPost, "/api/v1/cluster/members/b/promote", `{"role": "master"}`, stale)
	if resp.StatusCode != http.StatusForbidden || errorCode(t, resp) != "reauth_required" {
		t.Fatalf("promote to master without re-auth = %d %s, want 403 reauth_required", resp.StatusCode, resp.body)
	}
	if len(admin.called()) != 0 {
		t.Fatal("promoted without re-auth")
	}
	if got := strings.Join(clusterAudit(t, f), "|"); got != "cluster.promote b deny" {
		t.Fatalf("audit = %q, want the denial", got)
	}
	for _, body := range []string{`{"role": "storage"}`} {
		if resp := f.do(t, http.MethodPost, "/api/v1/cluster/members/b/promote", body, stale); resp.StatusCode != http.StatusOK {
			t.Fatalf("promote %s on a stale session = %d %s", body, resp.StatusCode, resp.body)
		}
	}
	c := sessionCookie(t, f.login(t, testPassword))
	if resp := f.do(t, http.MethodPost, "/api/v1/cluster/members/b/promote", `{"role": "master"}`, c); resp.StatusCode != http.StatusOK {
		t.Fatalf("promote to master after login = %d %s", resp.StatusCode, resp.body)
	}
}

func TestShellSafeURL(t *testing.T) {
	for _, tc := range []struct {
		in, want string
		ok       bool
	}{
		{"https://192.0.2.10:7443", "https://192.0.2.10:7443", true},
		{"https://hub.lan:7443/", "https://hub.lan:7443", true},
		{"https://hub.lan", "https://hub.lan", true},
		{"http://hub.lan:7443", "", false},
		{"https://[2001:db8::1]:7443", "", false},
		{"https://hub.lan:7443/x", "", false},
		{"https://hub.lan;id:7443", "", false},
		{"https://u@hub.lan:7443", "", false},
		{"https://hub.lan:7443?x=1", "", false},
		{"", "", false},
	} {
		if got, ok := shellSafeURL(tc.in); got != tc.want || ok != tc.ok {
			t.Errorf("shellSafeURL(%q) = %q, %v; want %q, %v", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}
