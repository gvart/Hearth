// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/integrations/kubernetes"
	"github.com/gvart/hearth/internal/integrations/proxmox"
	"github.com/gvart/hearth/internal/integrations/proxmox/pvemock"
	"github.com/gvart/hearth/internal/policy"
)

type proxmoxAPIFixture struct {
	f      *apiFixture
	cookie *http.Cookie
	mock   *pvemock.Server
	pve    *httptest.Server
}

func newProxmoxAPIFixture(t *testing.T, cfg policy.Config) *proxmoxAPIFixture {
	t.Helper()
	mock := pvemock.New(pvemock.Token)
	pve := httptest.NewTLSServer(mock)
	t.Cleanup(pve.Close)
	st := newTestStore(t)
	log := slog.New(slog.DiscardHandler)
	sealer, err := kubernetes.NewPurposeSealer([]byte("test CA key"), proxmox.SealInfo)
	if err != nil {
		t.Fatal(err)
	}
	pol := policy.NewWithConfig(st.Audit(), st.Approvals(), cfg)
	m := proxmox.NewManager(proxmox.Config{
		Store: st, Sealer: sealer, Policy: pol, Log: log,
		PollInterval: 20 * time.Millisecond, SyncInterval: 20 * time.Millisecond,
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = m.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-done })

	a := newAPI(Config{Store: st, Policy: pol, Log: log, Registry: NewRegistry(RegistryConfig{Store: st, Log: log}), Proxmox: m})
	srv := httptest.NewServer(a.routes())
	t.Cleanup(srv.Close)
	if err := st.Admin().CreateSession(t.Context(), "pve-session", time.Now(), time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	return &proxmoxAPIFixture{f: &apiFixture{srv: srv, st: st}, cookie: testCookie("pve-session"), mock: mock, pve: pve}
}

// post sends body as JSON with the session.
func (p *proxmoxAPIFixture) post(t *testing.T, path string, body any) (int, string) {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	r := p.f.do(t, http.MethodPost, path, string(b), p.cookie)
	return r.StatusCode, string(r.body)
}

func (p *proxmoxAPIFixture) addServer(t *testing.T) proxmox.ServerInfo {
	t.Helper()
	sum := sha256.Sum256(p.pve.Certificate().Raw)
	code, body := p.post(t, "/api/v1/proxmox/servers", proxmox.AddRequest{
		Name: "lab", URL: p.pve.URL, Token: pvemock.Token, Fingerprint: hex.EncodeToString(sum[:]),
	})
	if code != http.StatusCreated {
		t.Fatalf("add = %d %s", code, body)
	}
	var info proxmox.ServerInfo
	if err := json.Unmarshal([]byte(body), &info); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		r := p.f.do(t, http.MethodGet, "/api/v1/proxmox/servers/"+info.ID, "", p.cookie)
		if decode[proxmox.Snapshot](t, r).Server.State == proxmox.StateConnected {
			return info
		}
		if time.Now().After(deadline) {
			t.Fatalf("server not connected: %s", r.body)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestProxmoxAPI(t *testing.T) {
	p := newProxmoxAPIFixture(t, policy.Config{})
	_, secret, _ := strings.Cut(pvemock.Token, "=")

	for _, path := range []string{"/api/v1/proxmox/servers", "/api/v1/proxmox/servers/x"} {
		if r := p.f.do(t, http.MethodGet, path, "", nil); r.StatusCode != http.StatusUnauthorized {
			t.Errorf("unauthenticated GET %s = %d", path, r.StatusCode)
		}
	}
	if r := p.f.do(t, http.MethodPost, "/api/v1/proxmox/servers/x/actions", `{"action":"stop","vmid":100}`, nil); r.StatusCode != http.StatusUnauthorized {
		t.Errorf("unauthenticated action = %d", r.StatusCode)
	}

	info := p.addServer(t)

	for _, path := range []string{"/api/v1/proxmox/servers", "/api/v1/proxmox/servers/" + info.ID} {
		r := p.f.do(t, http.MethodGet, path, "", p.cookie)
		if r.StatusCode != http.StatusOK {
			t.Fatalf("GET %s = %d %s", path, r.StatusCode, r.body)
		}
		if strings.Contains(string(r.body), secret) || strings.Contains(string(r.body), "hearth@pve") {
			t.Errorf("GET %s serves the token: %s", path, r.body)
		}
	}
	snap := decode[proxmox.Snapshot](t, p.f.do(t, http.MethodGet, "/api/v1/proxmox/servers/"+info.ID, "", p.cookie))
	if len(snap.Nodes) != 3 || len(snap.Guests) != 6 || len(snap.Storage) != 5 {
		t.Errorf("snapshot = %+v", snap)
	}

	code, body := p.post(t, "/api/v1/proxmox/servers/"+info.ID+"/actions", proxmox.ActionRequest{Action: proxmox.ActionStop, VMID: 100})
	if code != http.StatusOK || !strings.Contains(body, `"class":"dangerous"`) {
		t.Errorf("stop = %d %s", code, body)
	}
	if got := p.mock.Posts(); len(got) != 1 || got[0] != "/api2/json/nodes/pve1/qemu/100/status/stop" {
		t.Errorf("POSTs = %v", got)
	}

	for name, tc := range map[string]struct {
		path string
		body any
		want int
	}{
		"bad action":      {"/api/v1/proxmox/servers/" + info.ID + "/actions", proxmox.ActionRequest{Action: "destroy", VMID: 100}, http.StatusBadRequest},
		"unknown guest":   {"/api/v1/proxmox/servers/" + info.ID + "/actions", proxmox.ActionRequest{Action: proxmox.ActionStart, VMID: 7}, http.StatusNotFound},
		"unknown server":  {"/api/v1/proxmox/servers/nope/actions", proxmox.ActionRequest{Action: proxmox.ActionStart, VMID: 100}, http.StatusNotFound},
		"taken name":      {"/api/v1/proxmox/servers", proxmox.AddRequest{Name: "lab", URL: "https://pve.lan", Token: pvemock.Token}, http.StatusConflict},
		"proxmox refuses": {"/api/v1/proxmox/servers/" + info.ID + "/actions", proxmox.ActionRequest{Action: proxmox.ActionReboot, VMID: 101}, http.StatusBadGateway},
	} {
		if code, body := p.post(t, tc.path, tc.body); code != tc.want {
			t.Errorf("%s = %d %s, want %d", name, code, body, tc.want)
		}
	}

	if r := p.f.do(t, http.MethodDelete, "/api/v1/proxmox/servers/"+info.ID, "", p.cookie); r.StatusCode != http.StatusNoContent {
		t.Errorf("delete = %d %s", r.StatusCode, r.body)
	}
}

func TestProxmoxAPIRefusesABadToken(t *testing.T) {
	p := newProxmoxAPIFixture(t, policy.Config{})
	const secret = "a-password-pasted-by-mistake"
	code, body := p.post(t, "/api/v1/proxmox/servers", proxmox.AddRequest{Name: "lab", URL: "https://pve.lan", Token: secret})
	if code != http.StatusBadRequest {
		t.Errorf("add = %d %s", code, body)
	}
	if strings.Contains(body, secret) {
		t.Errorf("the answer quotes the token: %s", body)
	}
}

func TestProxmoxAPIDeniedActionNeverReachesProxmox(t *testing.T) {
	p := newProxmoxAPIFixture(t, policy.Config{Classes: map[policy.Class]policy.Mode{policy.Dangerous: policy.ModeDeny}})
	info := p.addServer(t)
	for _, action := range []string{proxmox.ActionStop, proxmox.ActionReboot} {
		code, body := p.post(t, "/api/v1/proxmox/servers/"+info.ID+"/actions", proxmox.ActionRequest{Action: action, VMID: 100})
		if code != http.StatusForbidden {
			t.Errorf("%s = %d %s, want 403", action, code, body)
		}
	}
	if got := p.mock.Posts(); len(got) != 0 {
		t.Errorf("a denied action reached Proxmox: %v", got)
	}
}

func TestProxmoxAPIAnswersAChangedGuestWithAConflict(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/proxmox/servers/a/actions", nil)
	err := fmt.Errorf("stop lab/qemu/100: %w: VMID 100 is now lxc \"prod-database\"", proxmox.ErrGuestChanged)
	(&api{log: slog.Default()}).writeProxmoxError(w, r, "proxmox action", err)
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "guest_changed") {
		t.Errorf("answer = %d %s, want 409 guest_changed", w.Code, w.Body)
	}
}
