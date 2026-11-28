// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/gvart/hearth/internal/policy"
	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
)

// reportHello records hello as device id's facts.
func reportHello(t *testing.T, f *apiFixture, id string, hello *agentv1.Hello) {
	t.Helper()
	df, err := factsFromHello(hello, nil)
	if err != nil {
		t.Fatal(err)
	}
	d, err := f.st.Devices().Get(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	d.Facts = df.Facts
	if err := f.st.Devices().Upsert(t.Context(), d); err != nil {
		t.Fatal(err)
	}
}

func agentHello(minor uint32, locked bool, local *agentv1.Ceiling) *agentv1.Hello {
	return &agentv1.Hello{
		ProtocolVersion: &agentv1.ProtocolVersion{Major: 1, Minor: minor}, Hostname: "pi", AgentVersion: "v1",
		Ceiling: local, LocalCeiling: local, CeilingLocked: locked,
	}
}

const capsPath = "/api/v1/devices/pi/capabilities"

// TestCapabilitiesSetAndRaise: lowering and turning on the read
// capabilities needs no password again; raising shell, exec, restart or
// Docker control does, and a refusal is audited and stores nothing.
func TestCapabilitiesSetAndRaise(t *testing.T) {
	f := newWebAdminFixture(t, policy.Config{})
	reportHello(t, f, "pi", agentHello(10, false, &agentv1.Ceiling{Probe: true}))
	stale := staleSession(t, f)

	got := decode[CapabilitiesJSON](t, f.do(t, http.MethodGet, capsPath, "", stale))
	if !got.Manageable || got.Locked || got.Local == nil || !got.Local.Probe || got.Hub.Logs == nil || len(got.Hub.Logs) != 0 {
		t.Fatalf("capabilities = %+v", got)
	}

	// Logs on (the event log too), Docker read, net edges: no re-auth.
	resp := f.do(t, http.MethodPut, capsPath, `{"hub":{"logs":["systemd:*","docker:*","eventlog:Application"],"docker_read":true,"net_edges":true}}`, stale)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("set = %d %s", resp.StatusCode, resp.body)
	}
	if got := decode[CapabilitiesJSON](t, resp); !slices.Equal(got.Hub.Logs, []string{"systemd:*", "docker:*", "eventlog:Application"}) || got.UpdatedBy == "" {
		t.Errorf("after set = %+v", got)
	}
	if e := auditOf(t, f, policy.DeviceCapabilitiesSet); len(e) == 0 || !strings.Contains(string(e[0].Detail), `"logs"`) {
		t.Errorf("set audit = %+v", e)
	}

	// Each risky raise without the password again: refused, audited.
	for _, body := range []string{
		`{"hub":{"shell":true}}`,
		`{"hub":{"exec":["/usr/bin/df"]}}`,
		`{"hub":{"restart":["docker:*"]}}`,
		`{"hub":{"docker":true}}`,
	} {
		before := len(auditOf(t, f, policy.DeviceCapabilitiesRaise))
		resp := f.do(t, http.MethodPut, capsPath, body, stale)
		if resp.StatusCode != http.StatusForbidden || errorCode(t, resp) != "reauth_required" {
			t.Fatalf("%s without re-auth = %d %s, want 403 reauth_required", body, resp.StatusCode, resp.body)
		}
		e := auditOf(t, f, policy.DeviceCapabilitiesRaise)
		if len(e) != before+1 || e[0].Decision != policy.Deny {
			t.Fatalf("%s audit = %+v, want a denial", body, e)
		}
	}
	if got := decode[CapabilitiesJSON](t, f.do(t, http.MethodGet, capsPath, "", stale)); got.Hub.Shell || len(got.Hub.Exec) != 0 || got.Hub.Docker {
		t.Errorf("a refused raise was stored: %+v", got.Hub)
	}

	// With the password again it goes through.
	if resp := f.do(t, http.MethodPost, "/api/v1/session/reauth", passwordBody(testPassword), stale); resp.StatusCode != http.StatusOK {
		t.Fatalf("reauth = %d", resp.StatusCode)
	}
	if resp := f.do(t, http.MethodPut, capsPath, `{"hub":{"shell":true,"exec":["/usr/bin/df"]}}`, stale); resp.StatusCode != http.StatusOK {
		t.Fatalf("raise after re-auth = %d %s", resp.StatusCode, resp.body)
	}

	// Lowering never asks: a fresh stale session turns it all off.
	other := staleSession(t, f)
	if resp := f.do(t, http.MethodPut, capsPath, `{"hub":{}}`, other); resp.StatusCode != http.StatusOK {
		t.Fatalf("lower = %d %s", resp.StatusCode, resp.body)
	}
	if got := decode[CapabilitiesJSON](t, f.do(t, http.MethodGet, capsPath, "", other)); got.Hub.Shell || len(got.Hub.Exec) != 0 {
		t.Errorf("after lowering = %+v", got.Hub)
	}
}

// TestCapabilitiesRefused: bad entries, a locked device, an unknown device
// and a policy that denies are refused, and nothing is stored.
func TestCapabilitiesRefused(t *testing.T) {
	f := newWebAdminFixture(t, policy.Config{Actors: map[string]map[policy.Class]policy.Mode{
		policy.ActorWeb: {policy.Safe: policy.ModeDeny},
	}})
	reportHello(t, f, "pi", agentHello(10, false, &agentv1.Ceiling{}))
	c := sessionCookie(t, f.login(t, testPassword))
	for _, body := range []string{
		`{"hub":{"exec":["df"]}}`,
		`{"hub":{"logs":["syslog:*"]}}`,
		`{"hub":{"logs":["eventlog:"]}}`,
		`{"hub":{"restart":["eventlog:System"]}}`,
		`{"hub":{"scan":["fe80::/64"]}}`,
		`{"hub":{"root":true}}`,
	} {
		if resp := f.do(t, http.MethodPut, capsPath, body, c); resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s = %d %s, want 400", body, resp.StatusCode, resp.body)
		}
	}
	// Denied by policy: safe web actions are denied here.
	resp := f.do(t, http.MethodPut, capsPath, `{"hub":{"probe":true}}`, c)
	if resp.StatusCode != http.StatusForbidden || errorCode(t, resp) != "forbidden" {
		t.Fatalf("denied set = %d %s, want 403 forbidden", resp.StatusCode, resp.body)
	}
	if e := auditOf(t, f, policy.DeviceCapabilitiesSet); len(e) != 1 || e[0].Decision != policy.Deny {
		t.Errorf("denied set audit = %+v", e)
	}
	if got := decode[CapabilitiesJSON](t, f.do(t, http.MethodGet, capsPath, "", c)); got.Hub.Probe {
		t.Error("a denied set was stored")
	}
	if resp := f.do(t, http.MethodPut, "/api/v1/devices/nope/capabilities", `{"hub":{}}`, c); resp.StatusCode != http.StatusNotFound {
		t.Errorf("unknown device = %d", resp.StatusCode)
	}
	// An older agent cannot take a ceiling.
	reportHello(t, f, "pi", agentHello(9, false, &agentv1.Ceiling{}))
	if got := decode[CapabilitiesJSON](t, f.do(t, http.MethodGet, capsPath, "", c)); got.Manageable {
		t.Error("an agent of minor 9 reported manageable")
	}
}

// TestCapabilitiesActors: only an admin, on the hub host or in the web UI,
// changes a device's capabilities; never an automation or an MCP client.
func TestCapabilitiesActors(t *testing.T) {
	for _, a := range []policy.Action{policy.DeviceCapabilitiesSet, policy.DeviceCapabilitiesRaise} {
		for _, kind := range []string{policy.ActorMCP, policy.ActorAutomation, policy.ActorGuest, policy.ActorToken} {
			if policy.Admits(a, kind) {
				t.Errorf("%s admits %s", a, kind)
			}
		}
		if !policy.Admits(a, policy.ActorWeb) || !policy.Admits(a, policy.ActorAdmin) {
			t.Errorf("%s does not admit the admin", a)
		}
	}
	if c, _ := policy.ClassOf(policy.DeviceCapabilitiesRaise); c != policy.Dangerous {
		t.Errorf("raise class %s", c)
	}
}

func TestChangeOf(t *testing.T) {
	for _, tt := range []struct {
		old, next *agentv1.Ceiling
		want      policy.Action
	}{
		{&agentv1.Ceiling{}, &agentv1.Ceiling{Logs: AllLogs, Probe: true, DockerRead: true, NetEdges: true, Scan: AllScan}, policy.DeviceCapabilitiesSet},
		{&agentv1.Ceiling{Shell: true, Exec: []string{"/a"}, Docker: true}, &agentv1.Ceiling{}, policy.DeviceCapabilitiesSet},
		{&agentv1.Ceiling{Exec: []string{"/a"}}, &agentv1.Ceiling{Exec: []string{"/a", "/b"}}, policy.DeviceCapabilitiesRaise},
		{&agentv1.Ceiling{Restart: []string{"docker:web"}}, &agentv1.Ceiling{Restart: AllRestart}, policy.DeviceCapabilitiesRaise},
		{&agentv1.Ceiling{Restart: AllRestart}, &agentv1.Ceiling{Restart: []string{"docker:*"}}, policy.DeviceCapabilitiesSet},
		{&agentv1.Ceiling{DockerRead: true}, &agentv1.Ceiling{Docker: true}, policy.DeviceCapabilitiesRaise},
	} {
		if got := ChangeOf(tt.old, tt.next); got.Action != tt.want {
			t.Errorf("ChangeOf(%v, %v) = %+v, want %s", tt.old, tt.next, got, tt.want)
		}
	}
}

// TestCapabilitiesWithNoRecord: with no ceiling recorded for a device (one
// set before the ceilings were cluster-wide may not have reached this
// master, #382), the change is measured from nothing, so a raise still
// needs the password again; and with no ceiling the agent reported either,
// the change is refused, audited as a denial.
func TestCapabilitiesWithNoRecord(t *testing.T) {
	f := newWebAdminFixture(t, policy.Config{})
	stale := staleSession(t, f)
	reportHello(t, f, "pi", agentHello(10, false, nil))
	if resp := f.do(t, http.MethodPut, capsPath, `{"hub":{"probe":true}}`, stale); resp.StatusCode != http.StatusConflict ||
		errorCode(t, resp) != "ceiling_unknown" {
		t.Fatalf("no record, nothing reported = %d %s, want 409 ceiling_unknown", resp.StatusCode, resp.body)
	}
	if e := auditOf(t, f, policy.DeviceCapabilitiesSet); len(e) != 1 || e[0].Decision != policy.Deny {
		t.Fatalf("the refusal is not audited as a denial: %+v", e)
	}
	reportHello(t, f, "pi", agentHello(10, false, &agentv1.Ceiling{}))
	if resp := f.do(t, http.MethodPut, capsPath, `{"hub":{"shell":true}}`, stale); resp.StatusCode != http.StatusForbidden ||
		errorCode(t, resp) != "reauth_required" {
		t.Fatalf("raise with no record = %d %s, want 403 reauth_required", resp.StatusCode, resp.body)
	}
}

// TestCapabilitiesLocked: a device installed with --local-ceiling is managed
// on the device; the hub refuses a change, audited as a denial, and stores
// nothing.
func TestCapabilitiesLocked(t *testing.T) {
	f := newWebAdminFixture(t, policy.Config{})
	reportHello(t, f, "pi", agentHello(10, true, &agentv1.Ceiling{Shell: true}))
	c := sessionCookie(t, f.login(t, testPassword))
	if resp := f.do(t, http.MethodPut, capsPath, `{"hub":{"probe":true}}`, c); resp.StatusCode != http.StatusConflict || errorCode(t, resp) != "locked" {
		t.Errorf("locked device = %d %s, want 409 locked", resp.StatusCode, resp.body)
	}
	if e := auditOf(t, f, policy.DeviceCapabilitiesSet); len(e) != 1 || e[0].Decision != policy.Deny {
		t.Errorf("the refusal of a locked device is not audited as a denial: %+v", e)
	}
	got := decode[CapabilitiesJSON](t, f.do(t, http.MethodGet, capsPath, "", c))
	if !got.Locked || got.Hub.Probe {
		t.Errorf("locked device = %+v, want locked and nothing stored", got)
	}
}
