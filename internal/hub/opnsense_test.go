// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/integrations/kubernetes"
	"github.com/gvart/hearth/internal/integrations/opnsense"
	"github.com/gvart/hearth/internal/integrations/opnsense/opnsensemock"
	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

type opnsenseAPIFixture struct {
	a        *api
	f        *apiFixture
	cookie   *http.Cookie
	mock     *opnsensemock.Server
	firewall *httptest.Server
	fp       string
}

func newOPNsenseAPIFixture(t *testing.T, cfg policy.Config) *opnsenseAPIFixture {
	t.Helper()
	mock := opnsensemock.New(opnsensemock.Key, opnsensemock.Secret)
	firewall := httptest.NewTLSServer(mock)
	t.Cleanup(firewall.Close)
	sum := sha256.Sum256(firewall.Certificate().Raw)
	st := newTestStore(t)
	log := slog.New(slog.DiscardHandler)
	sealer, err := kubernetes.NewPurposeSealer([]byte("test CA key"), opnsense.SealInfo)
	if err != nil {
		t.Fatal(err)
	}
	pol := policy.NewWithConfig(st.Audit(), st.Approvals(), cfg)
	m := opnsense.NewManager(opnsense.Config{
		Store: st, Sealer: sealer, Policy: pol, Log: log,
		PollInterval: 20 * time.Millisecond, SyncInterval: 20 * time.Millisecond,
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = m.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-done })

	a := newAPI(Config{Store: st, Policy: pol, Log: log, Registry: NewRegistry(RegistryConfig{Store: st, Log: log}), OPNsense: m})
	srv := httptest.NewServer(a.routes())
	t.Cleanup(srv.Close)
	if err := st.Admin().CreateSession(t.Context(), "opn-session", time.Now(), time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	return &opnsenseAPIFixture{
		a: a, f: &apiFixture{srv: srv, st: st}, cookie: testCookie("opn-session"), mock: mock, firewall: firewall,
		fp: hex.EncodeToString(sum[:]),
	}
}

func (o *opnsenseAPIFixture) add(t *testing.T) opnsense.FirewallInfo {
	t.Helper()
	r := o.f.do(t, http.MethodPost, "/api/v1/opnsense/firewalls",
		`{"name":"edge","url":"`+o.firewall.URL+`","key":"`+opnsensemock.Key+`","secret":"`+opnsensemock.Secret+
			`","fingerprint":"`+o.fp+`"}`, o.cookie)
	if r.StatusCode != http.StatusCreated {
		t.Fatalf("add = %d %s", r.StatusCode, r.body)
	}
	return decodeBody[opnsense.FirewallInfo](t, string(r.body))
}

func (o *opnsenseAPIFixture) waitConnected(t *testing.T, id string) opnsense.Snapshot {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		r := o.f.do(t, http.MethodGet, "/api/v1/opnsense/firewalls/"+id, "", o.cookie)
		snap := decodeBody[opnsense.Snapshot](t, string(r.body))
		if snap.Firewall.State == opnsense.StateConnected {
			return snap
		}
		if time.Now().After(deadline) {
			t.Fatalf("firewall never connected: %s", r.body)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// The issue's "done when", through the hub API: a firewall adopted from the
// web UI is read from the emulated instance, its clients served.
func TestOPNsenseFirewallThroughTheAPI(t *testing.T) {
	o := newOPNsenseAPIFixture(t, policy.Config{})
	for _, path := range []string{"/api/v1/opnsense/firewalls", "/api/v1/opnsense/firewalls/x"} {
		if r := o.f.do(t, http.MethodGet, path, "", nil); r.StatusCode != http.StatusUnauthorized {
			t.Errorf("unauthenticated GET %s = %d", path, r.StatusCode)
		}
	}
	info := o.add(t)
	snap := o.waitConnected(t, info.ID)
	if snap.System.Hostname != "edge.home.arpa" || len(snap.Clients) != 6 || snap.RestartClass != "dangerous" {
		t.Errorf("snapshot = %+v", snap)
	}
	for _, path := range []string{"/api/v1/opnsense/firewalls", "/api/v1/opnsense/firewalls/" + info.ID} {
		r := o.f.do(t, http.MethodGet, path, "", o.cookie)
		body := string(r.body)
		if r.StatusCode != http.StatusOK || strings.Contains(body, opnsensemock.Key) || strings.Contains(body, opnsensemock.Secret) {
			t.Errorf("GET %s = %d, serving a credential: %s", path, r.StatusCode, body)
		}
	}
	for name, tc := range map[string]struct {
		method, path, body string
		want               int
	}{
		"unknown firewall": {http.MethodGet, "/api/v1/opnsense/firewalls/nope", "", http.StatusNotFound},
		"unknown restart":  {http.MethodPost, "/api/v1/opnsense/firewalls/nope/restart-unbound", "", http.StatusNotFound},
		"unknown remove":   {http.MethodDelete, "/api/v1/opnsense/firewalls/nope", "", http.StatusNotFound},
		"taken name":       {http.MethodPost, "/api/v1/opnsense/firewalls", `{"name":"edge","url":"https://192.0.2.1","key":"k","secret":"s"}`, http.StatusConflict},
		"plain http":       {http.MethodPost, "/api/v1/opnsense/firewalls", `{"name":"fw2","url":"http://192.0.2.1","key":"k","secret":"sec-ret-1"}`, http.StatusBadRequest},
		"missing secret":   {http.MethodPost, "/api/v1/opnsense/firewalls", `{"name":"fw2","url":"https://192.0.2.1","key":"k"}`, http.StatusBadRequest},
	} {
		r := o.f.do(t, tc.method, tc.path, tc.body, o.cookie)
		if r.StatusCode != tc.want {
			t.Errorf("%s = %d %s, want %d", name, r.StatusCode, r.body, tc.want)
		}
		if strings.Contains(string(r.body), "sec-ret-1") {
			t.Errorf("%s: the answer quotes the secret", name)
		}
	}
	if r := o.f.do(t, http.MethodDelete, "/api/v1/opnsense/firewalls/"+info.ID, "", o.cookie); r.StatusCode != http.StatusNoContent {
		t.Errorf("delete = %d %s", r.StatusCode, r.body)
	}
}

func TestOPNsenseRestartNeedsReauth(t *testing.T) {
	o := newOPNsenseAPIFixture(t, policy.Config{})
	info := o.add(t)
	o.waitConnected(t, info.ID)
	path := "/api/v1/opnsense/firewalls/" + info.ID + "/restart-unbound"

	r := o.f.do(t, http.MethodPost, path, "", o.cookie)
	if r.StatusCode != http.StatusForbidden || !strings.Contains(string(r.body), "reauth_required") {
		t.Fatalf("restart without re-authentication = %d %s, want 403 reauth_required", r.StatusCode, r.body)
	}
	if o.mock.Restarts() != 0 {
		t.Fatal("a restart without re-authentication reached the firewall")
	}

	o.a.reauths.mark("opn-session", o.a.now())
	r = o.f.do(t, http.MethodPost, path, "", o.cookie)
	if r.StatusCode != http.StatusOK || !strings.Contains(string(r.body), `"class":"dangerous"`) {
		t.Fatalf("restart = %d %s", r.StatusCode, r.body)
	}
	if o.mock.Restarts() != 1 {
		t.Errorf("restarts = %d, want 1", o.mock.Restarts())
	}
	entries, err := o.f.st.Audit().Query(t.Context(), store.AuditFilter{Actions: []string{string(policy.OPNsenseUnboundRestart)}}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || entries[0].Decision == entries[1].Decision {
		t.Errorf("audit = %+v, want a denial and an allow", entries)
	}
}

func TestOPNsenseRestartDeniedByPolicy(t *testing.T) {
	o := newOPNsenseAPIFixture(t, policy.Config{Classes: map[policy.Class]policy.Mode{policy.Dangerous: policy.ModeDeny}})
	info := o.add(t)
	o.waitConnected(t, info.ID)
	o.a.reauths.mark("opn-session", o.a.now())
	r := o.f.do(t, http.MethodPost, "/api/v1/opnsense/firewalls/"+info.ID+"/restart-unbound", "", o.cookie)
	if r.StatusCode != http.StatusForbidden || !strings.Contains(string(r.body), `"forbidden"`) {
		t.Errorf("restart = %d %s, want 403 forbidden", r.StatusCode, r.body)
	}
	if o.mock.Restarts() != 0 {
		t.Error("a denied restart reached the firewall")
	}
}
