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
	"github.com/gvart/hearth/internal/integrations/unifi"
	"github.com/gvart/hearth/internal/integrations/unifi/unifimock"
	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

const unifiAP = "74:ac:b9:00:00:03"

type unifiAPIFixture struct {
	a          *api
	f          *apiFixture
	cookie     *http.Cookie
	mock       *unifimock.Server
	controller *httptest.Server
	fp         string
}

func newUniFiAPIFixture(t *testing.T, cfg policy.Config) *unifiAPIFixture {
	t.Helper()
	mock := unifimock.New(unifimock.UniFiOS)
	controller := httptest.NewTLSServer(mock)
	t.Cleanup(controller.Close)
	sum := sha256.Sum256(controller.Certificate().Raw)
	st := newTestStore(t)
	log := slog.New(slog.DiscardHandler)
	sealer, err := kubernetes.NewPurposeSealer([]byte("test CA key"), unifi.SealInfo)
	if err != nil {
		t.Fatal(err)
	}
	pol := policy.NewWithConfig(st.Audit(), st.Approvals(), cfg)
	m := unifi.NewManager(unifi.Config{
		Store: st, Sealer: sealer, Policy: pol, Log: log,
		PollInterval: 20 * time.Millisecond, SyncInterval: 20 * time.Millisecond,
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = m.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-done })

	a := newAPI(Config{Store: st, Policy: pol, Log: log, Registry: NewRegistry(RegistryConfig{Store: st, Log: log}), UniFi: m})
	srv := httptest.NewServer(a.routes())
	t.Cleanup(srv.Close)
	if err := st.Admin().CreateSession(t.Context(), "ufi-session", time.Now(), time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	return &unifiAPIFixture{
		a: a, f: &apiFixture{srv: srv, st: st}, cookie: testCookie("ufi-session"), mock: mock, controller: controller,
		fp: hex.EncodeToString(sum[:]),
	}
}

func (u *unifiAPIFixture) add(t *testing.T) unifi.ControllerInfo {
	t.Helper()
	r := u.f.do(t, http.MethodPost, "/api/v1/unifi/controllers",
		`{"name":"console","url":"`+u.controller.URL+`","kind":"unifi_os","api_key":"`+unifimock.APIKey+`","fingerprint":"`+u.fp+`"}`, u.cookie)
	if r.StatusCode != http.StatusCreated {
		t.Fatalf("add = %d %s", r.StatusCode, r.body)
	}
	return decodeBody[unifi.ControllerInfo](t, string(r.body))
}

func (u *unifiAPIFixture) waitConnected(t *testing.T, id string) unifi.Snapshot {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		r := u.f.do(t, http.MethodGet, "/api/v1/unifi/controllers/"+id, "", u.cookie)
		snap := decodeBody[unifi.Snapshot](t, string(r.body))
		if snap.Controller.State == unifi.StateConnected {
			return snap
		}
		if time.Now().After(deadline) {
			t.Fatalf("controller never connected: %s", r.body)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// The issue's "done when", through the hub API: a controller adopted from
// the web UI is read from the emulated instance, its devices and clients
// served.
func TestUniFiControllerThroughTheAPI(t *testing.T) {
	u := newUniFiAPIFixture(t, policy.Config{})
	for _, path := range []string{"/api/v1/unifi/controllers", "/api/v1/unifi/controllers/x"} {
		if r := u.f.do(t, http.MethodGet, path, "", nil); r.StatusCode != http.StatusUnauthorized {
			t.Errorf("unauthenticated GET %s = %d", path, r.StatusCode)
		}
	}
	info := u.add(t)
	snap := u.waitConnected(t, info.ID)
	if len(snap.Devices) != 4 || len(snap.Clients) != 5 || snap.RestartClass != "dangerous" || snap.Controller.Auth != unifi.AuthAPIKey {
		t.Errorf("snapshot = %+v", snap)
	}
	for _, path := range []string{"/api/v1/unifi/controllers", "/api/v1/unifi/controllers/" + info.ID} {
		r := u.f.do(t, http.MethodGet, path, "", u.cookie)
		if r.StatusCode != http.StatusOK || strings.Contains(string(r.body), unifimock.APIKey) {
			t.Errorf("GET %s = %d, serving the API key: %v", path, r.StatusCode, strings.Contains(string(r.body), unifimock.APIKey))
		}
	}
	for name, tc := range map[string]struct {
		method, path, body string
		want               int
	}{
		"unknown controller": {http.MethodGet, "/api/v1/unifi/controllers/nope", "", http.StatusNotFound},
		"unknown restart":    {http.MethodPost, "/api/v1/unifi/controllers/nope/devices/" + unifiAP + "/restart", "", http.StatusNotFound},
		"restart no ap":      {http.MethodPost, "/api/v1/unifi/controllers/" + info.ID + "/devices/74:ac:b9:00:00:01/restart", "", http.StatusNotFound},
		"unknown remove":     {http.MethodDelete, "/api/v1/unifi/controllers/nope", "", http.StatusNotFound},
		"taken name":         {http.MethodPost, "/api/v1/unifi/controllers", `{"name":"console","url":"https://192.0.2.1","kind":"classic","username":"a","password":"pw"}`, http.StatusConflict},
		"bad url":            {http.MethodPost, "/api/v1/unifi/controllers", `{"name":"c2","url":"http://192.0.2.1","kind":"classic","username":"a","password":"pw-secret-1"}`, http.StatusBadRequest},
		"key on classic":     {http.MethodPost, "/api/v1/unifi/controllers", `{"name":"c2","url":"https://192.0.2.1","kind":"classic","api_key":"pw-secret-1"}`, http.StatusBadRequest},
	} {
		r := u.f.do(t, tc.method, tc.path, tc.body, u.cookie)
		if r.StatusCode != tc.want {
			t.Errorf("%s = %d %s, want %d", name, r.StatusCode, r.body, tc.want)
		}
		if strings.Contains(string(r.body), "pw-secret-1") {
			t.Errorf("%s: the answer quotes the credential", name)
		}
	}
	if r := u.f.do(t, http.MethodDelete, "/api/v1/unifi/controllers/"+info.ID, "", u.cookie); r.StatusCode != http.StatusNoContent {
		t.Errorf("delete = %d %s", r.StatusCode, r.body)
	}
}

func TestUniFiRestartNeedsReauth(t *testing.T) {
	u := newUniFiAPIFixture(t, policy.Config{})
	info := u.add(t)
	u.waitConnected(t, info.ID)
	path := "/api/v1/unifi/controllers/" + info.ID + "/devices/" + unifiAP + "/restart"

	r := u.f.do(t, http.MethodPost, path, "", u.cookie)
	if r.StatusCode != http.StatusForbidden || !strings.Contains(string(r.body), "reauth_required") {
		t.Fatalf("restart without re-authentication = %d %s, want 403 reauth_required", r.StatusCode, r.body)
	}
	if len(u.mock.Restarts()) != 0 {
		t.Fatal("a restart without re-authentication reached the controller")
	}

	u.a.reauths.mark("ufi-session", u.a.now())
	r = u.f.do(t, http.MethodPost, path, "", u.cookie)
	if r.StatusCode != http.StatusOK || !strings.Contains(string(r.body), `"class":"dangerous"`) {
		t.Fatalf("restart = %d %s", r.StatusCode, r.body)
	}
	if got := u.mock.Restarts(); len(got) != 1 || got[0] != unifiAP {
		t.Errorf("restarts = %v", got)
	}
	entries, err := u.f.st.Audit().Query(t.Context(), store.AuditFilter{Actions: []string{string(policy.UniFiAPRestart)}}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || entries[0].Decision == entries[1].Decision {
		t.Errorf("audit = %+v, want a denial and an allow", entries)
	}
}

func TestUniFiRestartDeniedByPolicy(t *testing.T) {
	u := newUniFiAPIFixture(t, policy.Config{Classes: map[policy.Class]policy.Mode{policy.Dangerous: policy.ModeDeny}})
	info := u.add(t)
	u.waitConnected(t, info.ID)
	u.a.reauths.mark("ufi-session", u.a.now())
	r := u.f.do(t, http.MethodPost, "/api/v1/unifi/controllers/"+info.ID+"/devices/"+unifiAP+"/restart", "", u.cookie)
	if r.StatusCode != http.StatusForbidden || !strings.Contains(string(r.body), `"forbidden"`) {
		t.Errorf("restart = %d %s, want 403 forbidden", r.StatusCode, r.body)
	}
	if len(u.mock.Restarts()) != 0 {
		t.Error("a denied restart reached the controller")
	}
}
