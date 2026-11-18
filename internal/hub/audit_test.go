// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/store"
)

func TestAPIAudit(t *testing.T) {
	f := newAPIFixture(t, true)
	c := sessionCookie(t, f.login(t, testPassword)) // audits admin.set_password (1) and admin.login (2)
	if err := f.st.Devices().Upsert(t.Context(), store.Device{
		ID: "d1", Name: "pi", Hostname: "pi.lan", Status: store.StatusUnknown,
	}); err != nil {
		t.Fatal(err)
	}
	base := time.Now().Add(-time.Hour).UTC().Truncate(time.Second)
	for i, e := range []store.AuditEntry{
		{ActorKind: "admin", ActorID: "root", Action: "device.revoke", Target: "d1", Decision: "deny", Result: "nope"},  // 3
		{ActorKind: "automation", ActorID: "fix-dns", Action: "automation.restart", Target: "pi", Decision: "allow"},    // 4
		{ActorKind: "automation", ActorID: "fix-dns", Action: "automation.exec", Target: "pi.lan", Decision: "confirm"}, // 5
		{ActorKind: "automation", ActorID: "other", Action: "automation.log", Decision: "allow"},                        // 6
	} {
		e.TS = base.Add(time.Duration(i) * time.Minute)
		if _, err := f.st.Audit().Append(t.Context(), e); err != nil {
			t.Fatal(err)
		}
	}
	ids := func(p AuditPageJSON) []int64 {
		var out []int64
		for _, e := range p.Entries {
			out = append(out, e.ID)
		}
		return out
	}

	if resp := f.do(t, http.MethodGet, "/api/v1/audit", "", nil); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("unauthenticated = %d", resp.StatusCode)
	}
	tests := []struct {
		query string
		want  []int64
		next  int64
	}{
		{"", []int64{6, 5, 4, 3, 2, 1}, 0},
		{"?limit=2", []int64{6, 5}, 5},
		{"?limit=2&before=5", []int64{4, 3}, 3},
		{"?actor_kind=automation&actor=fix", []int64{5, 4}, 0},
		{"?class=dangerous", []int64{5, 3, 1}, 0},
		{"?class=read", []int64{6}, 0},
		{"?action=automation.restart", []int64{4}, 0},
		{"?action=automation.restart&class=dangerous", nil, 0},
		{"?decision=deny", []int64{3}, 0},
		{"?device=d1", []int64{5, 4, 3}, 0}, // by id, name and hostname
		{"?device=unknown", nil, 0},
		{"?since=" + base.Add(2*time.Minute).Format(time.RFC3339), []int64{6, 5, 2, 1}, 0},
		{"?until=" + base.Add(time.Minute).Format(time.RFC3339), []int64{3}, 0},
	}
	for _, tt := range tests {
		t.Run(tt.query, func(t *testing.T) {
			resp := f.do(t, http.MethodGet, "/api/v1/audit"+tt.query, "", c)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status = %d %s", resp.StatusCode, resp.body)
			}
			p := decode[AuditPageJSON](t, resp)
			if !slices.Equal(ids(p), tt.want) || p.NextBefore != tt.next {
				t.Errorf("ids = %v next %d, want %v next %d", ids(p), p.NextBefore, tt.want, tt.next)
			}
			if p.Entries == nil || !slices.Contains(p.Actions, "automation.exec") {
				t.Errorf("entries %v / actions %v", p.Entries, p.Actions)
			}
		})
	}
	p := decode[AuditPageJSON](t, f.do(t, http.MethodGet, "/api/v1/audit?action=device.revoke", "", c))
	if e := p.Entries[0]; e.Class != "dangerous" || e.Result != "nope" || e.ActorID != "root" || e.Target != "d1" {
		t.Errorf("entry = %+v", e)
	}
	for _, q := range []string{"?class=risky", "?since=yesterday", "?before=-1", "?limit=0", "?limit=501"} {
		if resp := f.do(t, http.MethodGet, "/api/v1/audit"+q, "", c); resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s = %d, want 400", q, resp.StatusCode)
		}
	}
}
