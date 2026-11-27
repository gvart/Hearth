// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/integrations/kubernetes"
	"github.com/gvart/hearth/internal/integrations/openwrt"
	"github.com/gvart/hearth/internal/integrations/openwrt/openwrtmock"
	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

type openwrtAPIFixture struct {
	a      *api
	f      *apiFixture
	cookie *http.Cookie
	mock   *openwrtmock.Server
	router *httptest.Server
}

func newOpenWrtAPIFixture(t *testing.T, cfg policy.Config) *openwrtAPIFixture {
	t.Helper()
	mock := openwrtmock.New(openwrtmock.Username, openwrtmock.Password)
	router := httptest.NewServer(mock)
	t.Cleanup(router.Close)
	st := newTestStore(t)
	log := slog.New(slog.DiscardHandler)
	sealer, err := kubernetes.NewPurposeSealer([]byte("test CA key"), openwrt.SealInfo)
	if err != nil {
		t.Fatal(err)
	}
	pol := policy.NewWithConfig(st.Audit(), st.Approvals(), cfg)
	m := openwrt.NewManager(openwrt.Config{
		Store: st, Sealer: sealer, Policy: pol, Log: log,
		PollInterval: 20 * time.Millisecond, SyncInterval: 20 * time.Millisecond,
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = m.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-done })

	a := newAPI(Config{Store: st, Policy: pol, Log: log, Registry: NewRegistry(RegistryConfig{Store: st, Log: log}), OpenWrt: m})
	srv := httptest.NewServer(a.routes())
	t.Cleanup(srv.Close)
	if err := st.Admin().CreateSession(t.Context(), "ow-session", time.Now(), time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	return &openwrtAPIFixture{a: a, f: &apiFixture{srv: srv, st: st}, cookie: testCookie("ow-session"), mock: mock, router: router}
}

func (o *openwrtAPIFixture) add(t *testing.T) openwrt.RouterInfo {
	t.Helper()
	r := o.f.do(t, http.MethodPost, "/api/v1/openwrt/routers",
		`{"name":"gateway","url":"`+o.router.URL+`","username":"`+openwrtmock.Username+`","password":"`+openwrtmock.Password+`"}`, o.cookie)
	if r.StatusCode != http.StatusCreated {
		t.Fatalf("add = %d %s", r.StatusCode, r.body)
	}
	return decodeBody[openwrt.RouterInfo](t, string(r.body))
}

func (o *openwrtAPIFixture) waitConnected(t *testing.T, id string) openwrt.Snapshot {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		r := o.f.do(t, http.MethodGet, "/api/v1/openwrt/routers/"+id, "", o.cookie)
		snap := decodeBody[openwrt.Snapshot](t, string(r.body))
		if snap.Router.State == openwrt.StateConnected {
			return snap
		}
		if time.Now().After(deadline) {
			t.Fatalf("router never connected: %s", r.body)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// The issue's "done when", through the hub API: a router adopted from the
// web UI is read from the emulated instance, its clients served.
func TestOpenWrtRouterThroughTheAPI(t *testing.T) {
	o := newOpenWrtAPIFixture(t, policy.Config{})
	for _, path := range []string{"/api/v1/openwrt/routers", "/api/v1/openwrt/routers/x"} {
		if r := o.f.do(t, http.MethodGet, path, "", nil); r.StatusCode != http.StatusUnauthorized {
			t.Errorf("unauthenticated GET %s = %d", path, r.StatusCode)
		}
	}
	info := o.add(t)
	snap := o.waitConnected(t, info.ID)
	if snap.System.Hostname != "gateway" || len(snap.Clients) != 5 || snap.RestartClass != "dangerous" {
		t.Errorf("snapshot = %+v", snap)
	}
	for _, path := range []string{"/api/v1/openwrt/routers", "/api/v1/openwrt/routers/" + info.ID} {
		r := o.f.do(t, http.MethodGet, path, "", o.cookie)
		if r.StatusCode != http.StatusOK || strings.Contains(string(r.body), openwrtmock.Password) {
			t.Errorf("GET %s = %d, serving the password: %v", path, r.StatusCode, strings.Contains(string(r.body), openwrtmock.Password))
		}
	}
	for name, tc := range map[string]struct {
		method, path, body string
		want               int
	}{
		"unknown router":   {http.MethodGet, "/api/v1/openwrt/routers/nope", "", http.StatusNotFound},
		"unknown restart":  {http.MethodPost, "/api/v1/openwrt/routers/nope/restart-dnsmasq", "", http.StatusNotFound},
		"unknown remove":   {http.MethodDelete, "/api/v1/openwrt/routers/nope", "", http.StatusNotFound},
		"taken name":       {http.MethodPost, "/api/v1/openwrt/routers", `{"name":"gateway","url":"http://192.0.2.1","username":"root","password":"pw"}`, http.StatusConflict},
		"bad url":          {http.MethodPost, "/api/v1/openwrt/routers", `{"name":"gw2","url":"telnet://192.0.2.1","username":"root","password":"pw-secret-1"}`, http.StatusBadRequest},
		"missing password": {http.MethodPost, "/api/v1/openwrt/routers", `{"name":"gw2","url":"http://192.0.2.1","username":"root"}`, http.StatusBadRequest},
	} {
		r := o.f.do(t, tc.method, tc.path, tc.body, o.cookie)
		if r.StatusCode != tc.want {
			t.Errorf("%s = %d %s, want %d", name, r.StatusCode, r.body, tc.want)
		}
		if strings.Contains(string(r.body), "pw-secret-1") {
			t.Errorf("%s: the answer quotes the password", name)
		}
	}
	if r := o.f.do(t, http.MethodDelete, "/api/v1/openwrt/routers/"+info.ID, "", o.cookie); r.StatusCode != http.StatusNoContent {
		t.Errorf("delete = %d %s", r.StatusCode, r.body)
	}
}

func TestOpenWrtRestartNeedsReauth(t *testing.T) {
	o := newOpenWrtAPIFixture(t, policy.Config{})
	info := o.add(t)
	o.waitConnected(t, info.ID)
	path := "/api/v1/openwrt/routers/" + info.ID + "/restart-dnsmasq"

	r := o.f.do(t, http.MethodPost, path, "", o.cookie)
	if r.StatusCode != http.StatusForbidden || !strings.Contains(string(r.body), "reauth_required") {
		t.Fatalf("restart without re-authentication = %d %s, want 403 reauth_required", r.StatusCode, r.body)
	}
	if o.mock.Restarts() != 0 {
		t.Fatal("a restart without re-authentication reached the router")
	}

	o.a.reauths.mark("ow-session", o.a.now())
	r = o.f.do(t, http.MethodPost, path, "", o.cookie)
	if r.StatusCode != http.StatusOK || !strings.Contains(string(r.body), `"class":"dangerous"`) {
		t.Fatalf("restart = %d %s", r.StatusCode, r.body)
	}
	if o.mock.Restarts() != 1 {
		t.Errorf("restarts = %d, want 1", o.mock.Restarts())
	}
	entries, err := o.f.st.Audit().Query(t.Context(), store.AuditFilter{Actions: []string{string(policy.OpenWrtDNSRestart)}}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || entries[0].Decision == entries[1].Decision {
		t.Errorf("audit = %+v, want a denial and an allow", entries)
	}
}

func TestOpenWrtRestartDeniedByPolicy(t *testing.T) {
	o := newOpenWrtAPIFixture(t, policy.Config{Classes: map[policy.Class]policy.Mode{policy.Dangerous: policy.ModeDeny}})
	info := o.add(t)
	o.waitConnected(t, info.ID)
	o.a.reauths.mark("ow-session", o.a.now())
	r := o.f.do(t, http.MethodPost, "/api/v1/openwrt/routers/"+info.ID+"/restart-dnsmasq", "", o.cookie)
	if r.StatusCode != http.StatusForbidden || !strings.Contains(string(r.body), `"forbidden"`) {
		t.Errorf("restart = %d %s, want 403 forbidden", r.StatusCode, r.body)
	}
	if o.mock.Restarts() != 0 {
		t.Error("a denied restart reached the router")
	}
}
