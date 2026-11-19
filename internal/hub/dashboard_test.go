// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

const dashboardPath = "/api/v1/dashboard/summary"

// dashboardToken creates a dashboard token through the admin API.
func (f *panelFixture) dashboardToken(t *testing.T, body string) CreatedDashboardTokenJSON {
	t.Helper()
	resp := f.do(t, http.MethodPost, "/api/v1/dashboard/tokens", body, f.cookie)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create dashboard token = %d %s", resp.StatusCode, resp.body)
	}
	return decode[CreatedDashboardTokenJSON](t, resp)
}

func bearer(secret string) http.Header { return http.Header{"Authorization": {"Bearer " + secret}} }

// dashboardEntries are the audit entries of dashboard reads.
func dashboardEntries(t *testing.T, st *store.Store) []store.AuditEntry {
	t.Helper()
	all, err := st.Audit().List(t.Context(), 1000)
	if err != nil {
		t.Fatal(err)
	}
	var out []store.AuditEntry
	for _, e := range all {
		if e.Action == string(policy.DashboardRead) {
			out = append(out, e)
		}
	}
	return out
}

// testClock makes f's api run on a clock the test advances.
func testClock(f *panelFixture) func(time.Duration) {
	var mu sync.Mutex
	now := time.Now()
	f.api.now = func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	f.api.dashboardReads = newLoginLimiter(f.api.now, dashboardReadBurst, dashboardReadEvery)
	return func(d time.Duration) { mu.Lock(); defer mu.Unlock(); now = now.Add(d) }
}

func TestDashboardSummary(t *testing.T) {
	f := newPanelFixture(t)
	advance := testClock(f)
	if _, _, err := f.st.Devices().MarkSeen(t.Context(), "pi", time.Now()); err != nil {
		t.Fatal(err)
	}
	created := f.dashboardToken(t, `{"name": "homepage"}`)
	if created.Secret == "" || created.Token.Status != "active" || created.Token.Name != "homepage" || created.Token.ExpiresAt != nil {
		t.Fatalf("created = %+v", created.Token)
	}

	r := f.raw(t, http.MethodGet, dashboardPath, "", bearer(created.Secret))
	if r.StatusCode != http.StatusOK {
		t.Fatalf("summary = %d %s", r.StatusCode, r.body)
	}
	got := decode[DashboardSummaryJSON](t, r)
	if got.Version != 1 || got.Counts != (DashboardCountsJSON{Total: 2, Online: 1, Offline: 1}) || len(got.Devices) != 2 || got.Truncated {
		t.Fatalf("summary = %+v", got)
	}
	for _, d := range got.Devices {
		if d.ID == "pi" && (d.Name != "pi-name" || d.Status != store.StatusOnline || d.LastSeen == nil) {
			t.Errorf("pi = %+v", d)
		}
	}

	// The shape is small and stable: exactly these keys, and nothing about
	// addresses, facts or labels.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(r.body, &raw); err != nil {
		t.Fatal(err)
	}
	if keys := slices.Sorted(maps.Keys(raw)); !slices.Equal(keys, []string{"counts", "devices", "truncated", "version"}) {
		t.Errorf("keys = %v", keys)
	}
	var devs []map[string]json.RawMessage
	if err := json.Unmarshal(raw["devices"], &devs); err != nil {
		t.Fatal(err)
	}
	if keys := slices.Sorted(maps.Keys(devs[0])); !slices.Equal(keys, []string{"id", "last_seen", "name", "status"}) {
		t.Errorf("device keys = %v", keys)
	}
	for _, leak := range []string{"attic", `"labels"`, `"facts"`, `"hostname"`, `"os"`, `"boot_time"`, `"ip"`} {
		if strings.Contains(string(r.body), leak) {
			t.Errorf("summary %s holds %q", r.body, leak)
		}
	}

	// The first read is audited as the token, class read; the next ones of
	// the hour are not, and the first after it counts them.
	for range 3 {
		if r := f.raw(t, http.MethodGet, dashboardPath, "", bearer(created.Secret)); r.StatusCode != http.StatusOK {
			t.Fatalf("read = %d", r.StatusCode)
		}
	}
	entries := dashboardEntries(t, f.st)
	if len(entries) != 1 {
		t.Fatalf("audit entries = %+v, want one for the hour", entries)
	}
	e := entries[0]
	if e.ActorKind != policy.ActorDashboard || e.ActorID != "token/"+created.Token.ID || e.Decision != policy.Allow || e.Result != policy.ReadAllowed {
		t.Errorf("entry = %+v", e)
	}
	advance(dashboardAuditEvery)
	if r := f.raw(t, http.MethodGet, dashboardPath, "", bearer(created.Secret)); r.StatusCode != http.StatusOK {
		t.Fatalf("read = %d", r.StatusCode)
	}
	entries = dashboardEntries(t, f.st)
	if len(entries) != 2 || !strings.Contains(string(entries[0].Detail), `"reads_unaudited":3`) {
		t.Fatalf("audit after an hour = %+v, want a second entry counting 3 reads", entries)
	}

	// The secret is shown once: never in the list, the audit log or the logs.
	list := f.do(t, http.MethodGet, "/api/v1/dashboard/tokens", "", f.cookie)
	audit, err := f.st.Audit().List(t.Context(), 1000)
	if err != nil {
		t.Fatal(err)
	}
	ab, _ := json.Marshal(audit)
	for where, s := range map[string]string{"list": string(list.body), "audit": string(ab), "logs": f.logs.String()} {
		if strings.Contains(s, created.Secret) {
			t.Errorf("the token's secret is in the %s", where)
		}
	}
	if !auditHas(audit, string(policy.DashboardTokenCreate), policy.ActorWeb) {
		t.Error("no dashboard.token.create entry in the audit log")
	}
}

func TestDashboardSummaryCapsTheList(t *testing.T) {
	f := newPanelFixture(t)
	for i := range maxDashboardDevices {
		enrollDevice(t, f.st, fmt.Sprintf("dev-%03d", i))
	}
	tok := f.dashboardToken(t, `{"name": "homepage"}`)
	got := decode[DashboardSummaryJSON](t, f.raw(t, http.MethodGet, dashboardPath, "", bearer(tok.Secret)))
	if got.Counts.Total != maxDashboardDevices+2 || len(got.Devices) != maxDashboardDevices || !got.Truncated {
		t.Fatalf("counts = %+v, devices = %d, truncated = %v", got.Counts, len(got.Devices), got.Truncated)
	}
}

// TestDashboardDenied: no token, a wrong scheme, a session, an unknown, a
// revoked or an expired token are all 401, and audited as denials, once an
// hour per source and actor, with a running count.
func TestDashboardDenied(t *testing.T) {
	f := newPanelFixture(t)
	advance := testClock(f)
	revoked := f.dashboardToken(t, `{"name": "old"}`)
	if r := f.do(t, http.MethodDelete, "/api/v1/dashboard/tokens/"+revoked.Token.ID, "", f.cookie); r.StatusCode != http.StatusNoContent {
		t.Fatalf("revoke = %d %s", r.StatusCode, r.body)
	}
	expiring := f.dashboardToken(t, `{"name": "brief", "expires_in": "1h"}`)
	if r := f.raw(t, http.MethodGet, dashboardPath, "", bearer(expiring.Secret)); r.StatusCode != http.StatusOK {
		t.Fatalf("before expiry = %d", r.StatusCode)
	}
	advance(time.Hour)

	cases := map[string]http.Header{
		"no token":       nil,
		"unknown":        bearer(rand.Text()),
		"revoked":        bearer(revoked.Secret),
		"expired":        bearer(expiring.Secret),
		"wrong scheme":   {"Authorization": {"Basic " + revoked.Secret}},
		"session cookie": {"Cookie": {SessionCookie + "=panel-session"}},
	}
	for name, h := range cases {
		t.Run(name, func(t *testing.T) {
			for range 3 {
				r := f.raw(t, http.MethodGet, dashboardPath, "", h)
				if r.StatusCode != http.StatusUnauthorized || r.Header.Get("WWW-Authenticate") == "" {
					t.Fatalf("status = %d %s, want 401 with a challenge", r.StatusCode, r.body)
				}
			}
		})
	}
	denied := map[string]int{}
	for _, e := range dashboardEntries(t, f.st) {
		if e.Decision == policy.Deny {
			denied[e.ActorID]++
			if !strings.Contains(string(e.Detail), `"remote":"127.0.0.1"`) {
				t.Errorf("denial %+v names no source", e)
			}
		}
	}
	// One row per known token and source for the hour, and one per reason
	// for unknown ones: no token (the session case too), an unknown token,
	// and not a bearer token.
	want := map[string]int{"token/unknown": 3, "token/" + revoked.Token.ID: 1, "token/" + expiring.Token.ID: 1}
	if !maps.Equal(denied, want) {
		t.Fatalf("denials audited = %v, want %v", denied, want)
	}
	advance(dashboardAuditEvery)
	f.raw(t, http.MethodGet, dashboardPath, "", bearer(revoked.Secret))
	entries := dashboardEntries(t, f.st)
	if e := entries[0]; e.Decision != policy.Deny || !strings.Contains(string(e.Detail), `"denials_unaudited":2`) ||
		!strings.Contains(e.Result, "revoked") {
		t.Errorf("denial after an hour = %+v, want one counting 2 and saying revoked", e)
	}
}

// TestDashboardPolicy: an operator can turn dashboards off, and a read is
// never held for approval.
func TestDashboardPolicy(t *testing.T) {
	for _, mode := range []policy.Mode{policy.ModeDeny, policy.ModeConfirm} {
		t.Run(string(mode), func(t *testing.T) {
			f := newPanelFixture(t)
			tok := f.dashboardToken(t, `{"name": "homepage"}`)
			f.api.policy = policy.NewWithConfig(f.st.Audit(), f.st.Approvals(), policy.Config{
				Actors: map[string]map[policy.Class]policy.Mode{policy.ActorDashboard: {policy.Read: mode}},
			})
			for range 2 {
				if r := f.raw(t, http.MethodGet, dashboardPath, "", bearer(tok.Secret)); r.StatusCode != http.StatusForbidden {
					t.Fatalf("status = %d %s, want 403", r.StatusCode, r.body)
				}
			}
			entries := dashboardEntries(t, f.st)
			if len(entries) != 1 || entries[0].Decision != policy.Deny || entries[0].ActorID != "token/"+tok.Token.ID {
				t.Fatalf("entries = %+v, want one denial", entries)
			}
			aps, err := f.st.Approvals().List(t.Context(), store.ApprovalPending, 10)
			if err != nil || len(aps) != 0 {
				t.Fatalf("approvals = %+v, %v; want none", aps, err)
			}
		})
	}
}

func TestDashboardRateLimit(t *testing.T) {
	f := newPanelFixture(t)
	advance := testClock(f)
	tok, other := f.dashboardToken(t, `{"name": "a"}`), f.dashboardToken(t, `{"name": "b"}`)
	for i := range dashboardReadBurst {
		if r := f.raw(t, http.MethodGet, dashboardPath, "", bearer(tok.Secret)); r.StatusCode != http.StatusOK {
			t.Fatalf("read %d = %d", i, r.StatusCode)
		}
	}
	r := f.raw(t, http.MethodGet, dashboardPath, "", bearer(tok.Secret))
	if r.StatusCode != http.StatusTooManyRequests || r.Header.Get("Retry-After") == "" {
		t.Fatalf("past the burst = %d", r.StatusCode)
	}
	if r := f.raw(t, http.MethodGet, dashboardPath, "", bearer(other.Secret)); r.StatusCode != http.StatusOK {
		t.Fatalf("another token = %d, want its own budget", r.StatusCode)
	}
	advance(dashboardReadEvery)
	if r := f.raw(t, http.MethodGet, dashboardPath, "", bearer(tok.Secret)); r.StatusCode != http.StatusOK {
		t.Fatalf("after a refill = %d", r.StatusCode)
	}
}

func TestDashboardTokenAdmin(t *testing.T) {
	f := newPanelFixture(t)
	for name, body := range map[string]string{
		"no name":         `{"name": " "}`,
		"long name":       `{"name": "` + strings.Repeat("x", maxDashboardTokenName+1) + `"}`,
		"negative expiry": `{"name": "x", "expires_in": "-1h"}`,
		"bad expiry":      `{"name": "x", "expires_in": "soon"}`,
		"unknown field":   `{"name": "x", "scope": "dangerous"}`,
		"not json":        `name=x`,
	} {
		if r := f.do(t, http.MethodPost, "/api/v1/dashboard/tokens", body, f.cookie); r.StatusCode != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400", name, r.StatusCode)
		}
	}
	// Made by JSON only: no form post makes one.
	for _, ct := range []string{"", "text/plain", "application/x-www-form-urlencoded"} {
		if r := f.send(t, http.MethodPost, "/api/v1/dashboard/tokens", ct, `{"name": "x"}`, f.cookie); r.StatusCode != http.StatusUnsupportedMediaType {
			t.Errorf("content type %q = %d, want 415", ct, r.StatusCode)
		}
	}
	// Without a session, nothing.
	for _, rt := range []struct{ method, path, body string }{
		{http.MethodGet, "/api/v1/dashboard/tokens", ""},
		{http.MethodPost, "/api/v1/dashboard/tokens", `{"name": "x"}`},
		{http.MethodDelete, "/api/v1/dashboard/tokens/x", ""},
	} {
		if r := f.raw(t, rt.method, rt.path, rt.body, nil); r.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s %s without a session = %d", rt.method, rt.path, r.StatusCode)
		}
	}

	tok := f.dashboardToken(t, `{"name": "homepage", "expires_in": "720h"}`)
	if tok.Token.ExpiresAt == nil {
		t.Fatalf("token = %+v, want an expiry", tok.Token)
	}
	if r := f.do(t, http.MethodDelete, "/api/v1/dashboard/tokens/"+tok.Token.ID, "", f.cookie); r.StatusCode != http.StatusNoContent {
		t.Fatalf("revoke = %d %s", r.StatusCode, r.body)
	}
	for _, id := range []string{tok.Token.ID, "nope"} {
		if r := f.do(t, http.MethodDelete, "/api/v1/dashboard/tokens/"+id, "", f.cookie); r.StatusCode != http.StatusNotFound {
			t.Errorf("revoke %s = %d, want 404", id, r.StatusCode)
		}
	}
	list := decode[struct{ Tokens []DashboardTokenJSON }](t, f.do(t, http.MethodGet, "/api/v1/dashboard/tokens", "", f.cookie))
	if len(list.Tokens) != 1 || list.Tokens[0].Status != "revoked" || list.Tokens[0].RevokedAt == nil {
		t.Fatalf("tokens = %+v", list.Tokens)
	}
	audit, err := f.st.Audit().List(t.Context(), 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range []policy.Action{policy.DashboardTokenCreate, policy.DashboardTokenRevoke} {
		if !auditHas(audit, string(a), policy.ActorWeb) {
			t.Errorf("no %s entry in the audit log", a)
		}
	}

	// Creating is a policy action: denied, nothing is made.
	f.api.policy = policy.NewWithConfig(f.st.Audit(), nil, policy.Config{
		Actors: map[string]map[policy.Class]policy.Mode{policy.ActorWeb: {policy.Safe: policy.ModeDeny}},
	})
	if r := f.do(t, http.MethodPost, "/api/v1/dashboard/tokens", `{"name": "x"}`, f.cookie); r.StatusCode != http.StatusForbidden {
		t.Errorf("create denied by policy = %d, want 403", r.StatusCode)
	}
	if toks, _ := f.st.DashboardTokens().List(t.Context()); len(toks) != 1 {
		t.Errorf("tokens after a denied create = %+v", toks)
	}
}

// TestDashboardIsolation: a dashboard token reads the summary and nothing
// else, by any route or any way of presenting it; and no other credential
// (an MCP token, a panel link, a session) reads the summary.
func TestDashboardIsolation(t *testing.T) {
	f := newIsolationFixture(t)
	mine := f.createPanel(t, restartPanel)
	other := f.createPanel(t, `{"name": "Office", "widgets": [{"kind": "device", "entity": "nas"}]}`)
	link := f.share(t, mine.ID, "").Token
	dash := f.dashboardToken(t, `{"name": "homepage"}`).Secret
	if r := f.raw(t, http.MethodGet, dashboardPath, "", bearer(dash)); r.StatusCode != http.StatusOK {
		t.Fatalf("own summary = %d %s", r.StatusCode, r.body)
	}

	w := mine.Widgets[0]
	routes := []isolationRoute{
		{"guest", http.MethodGet, "/api/v1/guest/" + dash, ""},
		{"guest", http.MethodGet, "/api/v1/guest/" + dash + "/events", ""},
		{"guest", http.MethodPost, "/api/v1/guest/" + dash + "/actions", `{"widget": "` + w.ID + `", "action": "` + w.Actions[0].ID + `"}`},
		{"guest", http.MethodGet, "/p/" + dash, ""},
	}
	for _, rt := range isolationRoutes(dash, mine, other) {
		if rt.path != dashboardPath {
			routes = append(routes, rt)
		}
	}
	creds := map[string]http.Header{
		"as session cookie":        {"Cookie": {SessionCookie + "=" + dash}},
		"as secure session cookie": {"Cookie": {SecureSessionCookie + "=" + dash}},
		"as bearer token":          bearer(dash),
		"as api key header":        {"X-Api-Key": {dash}},
	}
	for credName, h := range creds {
		for _, rt := range routes {
			t.Run(rt.family+" "+rt.method+" "+rt.path+" "+credName, func(t *testing.T) {
				r := f.raw(t, rt.method, rt.path, rt.body, h)
				gone := strings.HasPrefix(rt.path, "/api/v1/approval-link") && r.StatusCode == http.StatusGone
				if r.StatusCode != http.StatusUnauthorized && r.StatusCode != http.StatusNotFound && !gone {
					t.Fatalf("status = %d %s, want 401 or 404", r.StatusCode, r.body)
				}
			})
		}
	}
	if runs := f.runner.runs(); len(runs) != 0 {
		t.Fatalf("ran %v", runs)
	}
	if toks, _ := f.st.DashboardTokens().List(t.Context()); len(toks) != 1 {
		t.Fatalf("dashboard tokens = %+v, want only the first", toks)
	}

	// Nothing else reads the summary.
	mcp := rand.Text()
	if err := f.st.MCPTokens().Create(t.Context(), "claude", mcp, "dangerous", time.Now()); err != nil {
		t.Fatal(err)
	}
	others := map[string]string{"mcp token": mcp, "panel link": link, "session": "panel-session"}
	for name, secret := range others {
		for how, h := range map[string]http.Header{
			"as bearer token":   bearer(secret),
			"as session cookie": {"Cookie": {SessionCookie + "=" + secret}},
			"as api key header": {"X-Api-Key": {secret}},
		} {
			t.Run(name+" "+how, func(t *testing.T) {
				if r := f.raw(t, http.MethodGet, dashboardPath, "", h); r.StatusCode != http.StatusUnauthorized {
					t.Fatalf("summary = %d %s, want 401", r.StatusCode, r.body)
				}
			})
		}
	}
	// Nor does the dashboard token itself, other than as a bearer token.
	for how, h := range map[string]http.Header{
		"as session cookie":        {"Cookie": {SessionCookie + "=" + dash}},
		"as secure session cookie": {"Cookie": {SecureSessionCookie + "=" + dash}},
		"as api key header":        {"X-Api-Key": {dash}},
		"as basic auth":            {"Authorization": {"Basic " + dash}},
	} {
		t.Run("dashboard token "+how, func(t *testing.T) {
			if r := f.raw(t, http.MethodGet, dashboardPath, "", h); r.StatusCode != http.StatusUnauthorized {
				t.Fatalf("summary = %d %s, want 401", r.StatusCode, r.body)
			}
		})
	}
}
