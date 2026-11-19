// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

// serveFrom sends a dashboard read from remote straight to f's handler.
func serveFrom(t *testing.T, f *panelFixture, remote string, h http.Header) int {
	t.Helper()
	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, dashboardPath, nil)
	r.RemoteAddr = remote
	for k, v := range h {
		r.Header[k] = v
	}
	w := httptest.NewRecorder()
	f.api.routes().ServeHTTP(w, r)
	return w.Code
}

// detailOf decodes an audit entry's detail.
func detailOf(t *testing.T, e store.AuditEntry) map[string]any {
	t.Helper()
	var d map[string]any
	if err := json.Unmarshal(e.Detail, &d); err != nil {
		t.Fatal(err)
	}
	return d
}

// TestDashboardAuditKeys: allowed reads are throttled per token and source,
// so a token used from a new address gets a row of its own; unknown
// credentials are throttled per reason, whatever the source, and a flush
// writes their count with the last source.
func TestDashboardAuditKeys(t *testing.T) {
	f := newPanelFixture(t)
	tok := f.dashboardToken(t, `{"name": "homepage"}`)
	for range 3 {
		if c := serveFrom(t, f, "192.168.2.10:40000", bearer(tok.Secret)); c != http.StatusOK {
			t.Fatalf("read = %d", c)
		}
	}
	if c := serveFrom(t, f, "203.0.113.7:40000", bearer(tok.Secret)); c != http.StatusOK {
		t.Fatalf("read from elsewhere = %d", c)
	}
	var remotes []string
	for _, e := range dashboardEntries(t, f.st) {
		remotes = append(remotes, fmt.Sprint(detailOf(t, e)["remote"]))
	}
	slices.Sort(remotes)
	if !slices.Equal(remotes, []string{"192.168.2.10", "203.0.113.7"}) {
		t.Fatalf("allowed rows from %v, want one per source", remotes)
	}

	for i := range 50 {
		if c := serveFrom(t, f, fmt.Sprintf("[2001:db8::%x]:40000", i), bearer(rand.Text())); c != http.StatusUnauthorized {
			t.Fatalf("unknown token = %d", c)
		}
	}
	unknown := 0
	for _, e := range dashboardEntries(t, f.st) {
		if e.ActorID == "token/unknown" {
			unknown++
		}
	}
	if unknown != 1 {
		t.Fatalf("rows for 50 unknown tokens from 50 sources = %d, want 1", unknown)
	}

	// The flush writes what waits: 2 allowed reads from the first source,
	// and 49 refusals, with the last source.
	f.api.dashboardAudit.flush(t.Context(), time.Now())
	var flushed []map[string]any
	for _, e := range dashboardEntries(t, f.st) {
		if d := detailOf(t, e); d["flush"] == true {
			flushed = append(flushed, d)
		}
	}
	if len(flushed) != 2 {
		t.Fatalf("flushed rows = %v, want 2", flushed)
	}
	for _, d := range flushed {
		if d[readsUnaudited] != nil {
			if d[readsUnaudited] != float64(2) || d["remote"] != "192.168.2.10" {
				t.Errorf("flushed reads = %v", d)
			}
		} else if d[denialsUnaudited] != float64(49) || d["remote"] != "2001:db8::31" {
			t.Errorf("flushed denials = %v", d)
		}
	}
	before := len(dashboardEntries(t, f.st))
	f.api.dashboardAudit.flush(t.Context(), time.Now())
	if after := len(dashboardEntries(t, f.st)); after != before {
		t.Errorf("a second flush wrote %d rows, want none", after-before)
	}
}

// TestDashboardRateLimitedReadsAreCounted: a read refused for its rate is
// counted, and the flush as the hub stops writes the count.
func TestDashboardRateLimitedReadsAreCounted(t *testing.T) {
	f := newPanelFixture(t)
	testClock(f)
	tok := f.dashboardToken(t, `{"name": "homepage"}`)
	for range dashboardReadBurst + 5 {
		f.raw(t, http.MethodGet, dashboardPath, "", bearer(tok.Secret))
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := f.api.dashboardAudit.Run(ctx); err != nil {
		t.Fatal(err)
	}
	entries := dashboardEntries(t, f.st)
	if len(entries) != 2 {
		t.Fatalf("entries = %+v, want the first read and the flush", entries)
	}
	// The other reads served, and the five refused for their rate.
	if d := detailOf(t, entries[0]); d["flush"] != true || d[readsUnaudited] != float64(dashboardReadBurst-1+5) {
		t.Errorf("flushed = %v", d)
	}
}

// TestDashboardPrecheck: a read is never held for approval, whatever path
// reaches policy.
func TestDashboardPrecheck(t *testing.T) {
	req := policy.Request{ActorKind: policy.ActorDashboard, ActorID: "token/t1", Action: policy.DashboardRead}
	engine := func(m policy.Mode) *policy.Engine {
		return policy.NewWithConfig(nil, nil, policy.Config{
			Actors: map[string]map[policy.Class]policy.Mode{policy.ActorDashboard: {policy.Read: m}},
		})
	}
	if err := dashboardPrecheck(engine(policy.ModeAllow), req, "")(t.Context()); err != nil {
		t.Errorf("allowed = %v", err)
	}
	if err := dashboardPrecheck(engine(policy.ModeConfirm), req, "")(t.Context()); !errors.Is(err, policy.ErrDenied) {
		t.Errorf("confirm = %v, want a denial", err)
	}
	if err := dashboardPrecheck(engine(policy.ModeAllow), req, "dashboard token revoked")(t.Context()); !errors.Is(err, policy.ErrDenied) {
		t.Errorf("with a reason = %v, want a denial", err)
	}
}

// TestDashboardRevokeLongID: an ID no token can have is refused before it
// reaches the audit log.
func TestDashboardRevokeLongID(t *testing.T) {
	f := newPanelFixture(t)
	long := strings.Repeat("x", maxDashboardTokenID+1)
	if r := f.do(t, http.MethodDelete, "/api/v1/dashboard/tokens/"+long, "", f.cookie); r.StatusCode != http.StatusNotFound {
		t.Fatalf("revoke = %d, want 404", r.StatusCode)
	}
	audit, err := f.st.Audit().List(t.Context(), 100)
	if err != nil {
		t.Fatal(err)
	}
	if auditHas(audit, string(policy.DashboardTokenRevoke), policy.ActorWeb) {
		t.Error("a revoke of an over-long ID reached the audit log")
	}
}
