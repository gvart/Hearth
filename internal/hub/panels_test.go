// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/automation"
	"github.com/gvart/hearth/internal/integrations/kubernetes"
	"github.com/gvart/hearth/internal/integrations/proxmox"
	"github.com/gvart/hearth/internal/mcpserver"
	"github.com/gvart/hearth/internal/notify"
	"github.com/gvart/hearth/internal/policy"
	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
	"github.com/gvart/hearth/internal/store"
)

// fakeRunner stands in for the agents: it records each restart and answers
// it with res, after checking it against ceiling.
type fakeRunner struct {
	mu      sync.Mutex
	ceiling *agentv1.Ceiling
	ran     []string
}

func (f *fakeRunner) Check(_ context.Context, _ string, req *agentv1.ExecRequest) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return policy.WithinCeiling(f.ceiling, req)
}

func (f *fakeRunner) Exec(_ context.Context, device string, req *agentv1.ExecRequest) (*agentv1.ExecResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	rs := req.GetRestart()
	f.ran = append(f.ran, device+" "+rs.GetManager()+":"+rs.GetName())
	return &agentv1.ExecResult{Id: req.GetId()}, nil
}

func (f *fakeRunner) runs() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.ran...)
}

type panelFixture struct {
	*apiFixture
	cookie *http.Cookie
	runner *fakeRunner
}

func newPanelFixture(t *testing.T, opts ...func(*Config)) *panelFixture {
	t.Helper()
	f := &panelFixture{apiFixture: newAPIFixture(t, true, opts...)}
	f.runner = &fakeRunner{ceiling: &agentv1.Ceiling{Restart: []string{"docker:nginx", "systemd:kodi"}}}
	f.api.runner = f.runner
	enrollDevice(t, f.st, "pi")
	enrollDevice(t, f.st, "nas")
	if err := f.st.Admin().CreateSession(t.Context(), "panel-session", time.Now(), time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	f.cookie = testCookie("panel-session")
	return f
}

// createPanel saves a panel through the API and returns it.
func (f *panelFixture) createPanel(t *testing.T, body string) PanelJSON {
	t.Helper()
	resp := f.do(t, http.MethodPost, "/api/v1/panels", body, f.cookie)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create panel = %d %s", resp.StatusCode, resp.body)
	}
	return decode[PanelJSON](t, resp)
}

// share creates a share link of panel id and returns its secret.
func (f *panelFixture) share(t *testing.T, id, body string) CreatedPanelLinkJSON {
	t.Helper()
	resp := f.do(t, http.MethodPost, "/api/v1/panels/"+id+"/links", body, f.cookie)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create link = %d %s", resp.StatusCode, resp.body)
	}
	return decode[CreatedPanelLinkJSON](t, resp)
}

// raw sends a request with the given headers and no session.
func (f *panelFixture) raw(t *testing.T, method, path, body string, header http.Header) apiResp {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), method, f.srv.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range header {
		req.Header[k] = v
	}
	resp, err := f.srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return apiResp{StatusCode: resp.StatusCode, Header: resp.Header, body: b}
}

const restartPanel = `{"name": "Living room", "widgets": [
	{"kind": "device", "entity": "pi", "actions": [{"action": "device.restart", "service": "docker:nginx"}]}
]}`

func TestPanelSaveRejects(t *testing.T) {
	f := newPanelFixture(t)
	widget := func(actions string) string {
		return `{"name": "p", "widgets": [{"kind": "device", "entity": "pi", "actions": [` + actions + `]}]}`
	}
	tests := []struct {
		name, body, code string
	}{
		{"device.exec is dangerous", widget(`{"action": "device.exec"}`), "dangerous_action"},
		{"a proxmox stop is dangerous", widget(`{"action": "proxmox.guest.stop"}`), "dangerous_action"},
		{"a drain is dangerous", widget(`{"action": "kube.node.drain"}`), "dangerous_action"},
		{"an approval is dangerous", widget(`{"action": "approval.approve"}`), "dangerous_action"},
		{"safe, but not for guests", widget(`{"action": "proxmox.guest.start"}`), "bad_request"},
		{"safe, but not for guests either", widget(`{"action": "automation.restart", "service": "docker:nginx"}`), "bad_request"},
		{"read, but not for guests", widget(`{"action": "device.read"}`), "bad_request"},
		{"unknown action", widget(`{"action": "device.reboot"}`), "bad_request"},
		{"restart without a service", widget(`{"action": "device.restart"}`), "bad_request"},
		{"restart of an unknown manager", widget(`{"action": "device.restart", "service": "launchd:x"}`), "bad_request"},
		{"restart with a space", widget(`{"action": "device.restart", "service": "docker:a b"}`), "bad_request"},
		{"the same action twice", widget(`{"action": "device.restart", "service": "docker:nginx"}, {"action": "device.restart", "service": "docker:nginx"}`), "bad_request"},
		{"unknown device", `{"name": "p", "widgets": [{"kind": "device", "entity": "toaster"}]}`, "bad_request"},
		{"unknown kind", `{"name": "p", "widgets": [{"kind": "printer", "entity": "pi"}]}`, "bad_request"},
		{"no name", `{"name": " ", "widgets": []}`, "bad_request"},
		{"unknown field", `{"name": "p", "widgets": [], "owner": "x"}`, "bad_request"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := f.do(t, http.MethodPost, "/api/v1/panels", tt.body, f.cookie)
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("status = %d %s, want 400", resp.StatusCode, resp.body)
			}
			if e := decode[ErrorJSON](t, resp); e.Code != tt.code {
				t.Errorf("code = %q (%s), want %q", e.Code, e.Error, tt.code)
			}
		})
	}
	// Nor can a saved panel be changed to allow one.
	p := f.createPanel(t, restartPanel)
	resp := f.do(t, http.MethodPut, "/api/v1/panels/"+p.ID, widget(`{"action": "device.exec"}`), f.cookie)
	if resp.StatusCode != http.StatusBadRequest || decode[ErrorJSON](t, resp).Code != "dangerous_action" {
		t.Fatalf("update to a dangerous action = %d %s", resp.StatusCode, resp.body)
	}
	list := decode[struct{ Panels []PanelJSON }](t, f.do(t, http.MethodGet, "/api/v1/panels", "", f.cookie))
	if len(list.Panels) != 1 {
		t.Fatalf("panels = %+v, want only the valid one", list.Panels)
	}
}

func TestPanelAdminLifecycle(t *testing.T) {
	f := newPanelFixture(t)
	p := f.createPanel(t, restartPanel)
	if len(p.Widgets) != 1 || p.Widgets[0].ID == "" || len(p.Widgets[0].Actions) != 1 {
		t.Fatalf("panel = %+v", p)
	}
	act := p.Widgets[0].Actions[0]
	if act.ID != "device.restart:docker:nginx" || act.Class != string(policy.Safe) {
		t.Errorf("action = %+v", act)
	}

	// Edits keep the widget's ID, so open kiosks keep working.
	wid := p.Widgets[0].ID
	upd := `{"name": "Hall", "widgets": [{"id": "` + wid + `", "kind": "device", "entity": "pi", "actions": []}, {"kind": "device", "entity": "nas"}]}`
	resp := f.do(t, http.MethodPut, "/api/v1/panels/"+p.ID, upd, f.cookie)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("update = %d %s", resp.StatusCode, resp.body)
	}
	got := decode[PanelJSON](t, resp)
	if got.Name != "Hall" || len(got.Widgets) != 2 || got.Widgets[0].ID != wid || got.Widgets[1].ID == "" {
		t.Errorf("updated = %+v", got)
	}
	if r := f.do(t, http.MethodPut, "/api/v1/panels/nope", upd, f.cookie); r.StatusCode != http.StatusNotFound {
		t.Errorf("update unknown = %d", r.StatusCode)
	}

	created := f.share(t, p.ID, `{"expires_in": "24h"}`)
	if created.Token == "" || created.Path != "/p/"+created.Token || created.Link.ExpiresAt == nil || created.Link.Status != "active" {
		t.Fatalf("link = %+v", created)
	}
	// The secret is shown once: never in the panel, the audit log or the logs.
	got = decode[PanelJSON](t, f.do(t, http.MethodGet, "/api/v1/panels/"+p.ID, "", f.cookie))
	if len(got.Links) != 1 || got.Links[0].ID != created.Link.ID {
		t.Fatalf("links = %+v", got.Links)
	}
	b, _ := json.Marshal(got)
	audit, err := f.st.Audit().List(t.Context(), 100)
	if err != nil {
		t.Fatal(err)
	}
	ab, _ := json.Marshal(audit)
	for where, s := range map[string]string{"panel": string(b), "audit": string(ab), "logs": f.logs.String()} {
		if strings.Contains(s, created.Token) {
			t.Errorf("the link's secret is in the %s", where)
		}
	}
	for _, a := range []policy.Action{policy.PanelSave, policy.PanelLinkCreate} {
		if !auditHas(audit, string(a), policy.ActorWeb) {
			t.Errorf("no %s entry in the audit log", a)
		}
	}
	if r := f.do(t, http.MethodPost, "/api/v1/panels/"+p.ID+"/links", `{"expires_in": "-1h"}`, f.cookie); r.StatusCode != http.StatusBadRequest {
		t.Errorf("negative expiry = %d", r.StatusCode)
	}
	if r := f.do(t, http.MethodPost, "/api/v1/panels/nope/links", "", f.cookie); r.StatusCode != http.StatusNotFound {
		t.Errorf("link of an unknown panel = %d", r.StatusCode)
	}

	if r := f.do(t, http.MethodDelete, "/api/v1/panels/"+p.ID+"/links/"+created.Link.ID, "", f.cookie); r.StatusCode != http.StatusNoContent {
		t.Fatalf("revoke = %d %s", r.StatusCode, r.body)
	}
	if r := f.do(t, http.MethodDelete, "/api/v1/panels/"+p.ID+"/links/"+created.Link.ID, "", f.cookie); r.StatusCode != http.StatusNotFound {
		t.Errorf("revoke again = %d", r.StatusCode)
	}
	got = decode[PanelJSON](t, f.do(t, http.MethodGet, "/api/v1/panels/"+p.ID, "", f.cookie))
	if got.Links[0].Status != "revoked" {
		t.Errorf("link after revoke = %+v", got.Links[0])
	}
	if r := f.do(t, http.MethodDelete, "/api/v1/panels/"+p.ID, "", f.cookie); r.StatusCode != http.StatusNoContent {
		t.Fatalf("delete = %d", r.StatusCode)
	}
	if r := f.do(t, http.MethodGet, "/api/v1/panels/"+p.ID, "", f.cookie); r.StatusCode != http.StatusNotFound {
		t.Errorf("get after delete = %d", r.StatusCode)
	}
}

func auditHas(entries []store.AuditEntry, action, kind string) bool {
	for _, e := range entries {
		if e.Action == action && e.ActorKind == kind {
			return true
		}
	}
	return false
}

// TestGuestIsolation is the issue's "Done when": a share link reaches its
// own panel and nothing else, by any route or any way of presenting it.
func TestGuestIsolation(t *testing.T) {
	var mcpCfg mcpserver.Config
	f := newPanelFixture(t, func(c *Config) {
		log := slog.New(slog.DiscardHandler)
		sealer, err := kubernetes.NewSealer([]byte("test CA key"))
		if err != nil {
			t.Fatal(err)
		}
		c.Kube = kubernetes.NewManager(kubernetes.Config{Store: c.Store, Sealer: sealer, Policy: c.Policy, Log: log})
		pveSealer, err := kubernetes.NewPurposeSealer([]byte("test CA key"), proxmox.SealInfo)
		if err != nil {
			t.Fatal(err)
		}
		c.Proxmox = proxmox.NewManager(proxmox.Config{Store: c.Store, Sealer: pveSealer, Policy: c.Policy, Log: log})
		n, err := notify.Parse([]byte("channels:\n  phone: {type: ntfy, url: \"http://127.0.0.1:1\", topic: t}\n"))
		if err != nil {
			t.Fatal(err)
		}
		c.Notify = n
		c.AutomationsDir = t.TempDir()
		c.Runbooks = automation.NewRunbooks(automation.RunbooksConfig{
			Dir: t.TempDir(), Kinds: automation.Builtin(log), Policy: c.Policy, Runs: c.Store.RunbookRuns(), Sealer: sealer,
		})
		c.ConfigDrift = func(context.Context) (any, error) { return map[string]any{}, nil }
		mcpCfg = mcpserver.Config{
			Devices: c.Store.Devices(), Tokens: c.Store.MCPTokens(), Policy: c.Policy, Agents: NewAgents(c.Store.Devices()), Log: log,
		}
	})
	// The hub serves MCP next to the API, as cmd/hearth does.
	mux := http.NewServeMux()
	mux.Handle("/", f.api.routes())
	mux.Handle(mcpserver.Path, mcpserver.Handler(mcpCfg))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	f.srv = srv

	mine := f.createPanel(t, restartPanel)
	other := f.createPanel(t, `{"name": "Office", "widgets": [
		{"kind": "device", "entity": "nas", "actions": [{"action": "device.restart", "service": "systemd:kodi"}]}]}`)
	token := f.share(t, mine.ID, "").Token
	otherToken := f.share(t, other.ID, "").Token
	if r := f.raw(t, http.MethodGet, "/api/v1/guest/"+token, "", nil); r.StatusCode != http.StatusOK {
		t.Fatalf("own panel = %d %s", r.StatusCode, r.body)
	}

	routes := []struct {
		family, method, path, body string
	}{
		{"devices", http.MethodGet, "/api/v1/devices", ""},
		{"devices", http.MethodGet, "/api/v1/devices/pi", ""},
		{"devices", http.MethodGet, "/api/v1/devices/pi/metrics", ""},
		{"devices", http.MethodGet, "/api/v1/metrics/sparklines", ""},
		{"devices", http.MethodGet, "/api/v1/events", ""},
		{"devices", http.MethodPost, "/api/v1/tokens", "{}"},
		{"devices", http.MethodGet, "/api/v1/network/hosts", ""},
		{"devices", http.MethodPost, "/api/v1/network/hosts/aa:bb:cc:dd:ee:ff/known", ""},
		{"devices", http.MethodGet, "/api/v1/beszel/systems", ""},
		{"audit", http.MethodGet, "/api/v1/audit", ""},
		{"approvals", http.MethodGet, "/api/v1/approvals", ""},
		{"approvals", http.MethodPost, "/api/v1/approvals/x/approve", `{"password": "x"}`},
		{"approvals", http.MethodPost, "/api/v1/approvals/x/deny", ""},
		// An approval link's own routes need no session: the panel's
		// secret, sent as an approval link, is one that does not exist.
		{"approvals", http.MethodPost, "/api/v1/approval-link", `{"token": "` + token + `"}`},
		{"approvals", http.MethodPost, "/api/v1/approval-link/deny", `{"token": "` + token + `"}`},
		{"kube", http.MethodGet, "/api/v1/kube/clusters", ""},
		{"kube", http.MethodGet, "/api/v1/kube/clusters/x", ""},
		{"kube", http.MethodPost, "/api/v1/kube/clusters/x/actions", `{"action": "cordon"}`},
		{"proxmox", http.MethodGet, "/api/v1/proxmox/servers", ""},
		{"proxmox", http.MethodPost, "/api/v1/proxmox/servers/x/actions", `{"action": "start", "vmid": 100}`},
		{"automations", http.MethodGet, "/api/v1/automations", ""},
		{"automations", http.MethodPut, "/api/v1/automations/x", `{"yaml": "x"}`},
		{"automations", http.MethodPost, "/api/v1/automations/dry-run", `{"yaml": "x"}`},
		{"runbooks", http.MethodGet, "/api/v1/runbooks", ""},
		{"runbooks", http.MethodPost, "/api/v1/runbooks/x/runs", ""},
		{"runbooks", http.MethodGet, "/api/v1/runbook-runs", ""},
		{"mcp", http.MethodPost, mcpserver.Path, `{"jsonrpc": "2.0", "id": 1, "method": "tools/list"}`},
		{"settings", http.MethodGet, "/api/v1/session", ""},
		{"settings", http.MethodGet, "/api/v1/notify/channels", ""},
		{"settings", http.MethodPost, "/api/v1/notify/channels/phone/test", ""},
		{"settings", http.MethodGet, "/api/v1/cluster/config-drift", ""},
		{"telemetry", http.MethodGet, "/api/v1/telemetry", ""},
		{"telemetry", http.MethodPut, "/api/v1/telemetry", `{"enabled": true}`},
		{"panels", http.MethodGet, "/api/v1/panels", ""},
		{"panels", http.MethodGet, "/api/v1/panels/" + mine.ID, ""},
		{"panels", http.MethodPut, "/api/v1/panels/" + mine.ID, restartPanel},
		{"panels", http.MethodDelete, "/api/v1/panels/" + mine.ID, ""},
		{"panels", http.MethodPost, "/api/v1/panels/" + mine.ID + "/links", ""},
		{"other panels", http.MethodGet, "/api/v1/panels/" + other.ID, ""},
		{"other panels", http.MethodPost, "/api/v1/panels/" + other.ID + "/links", ""},
		{"other panels", http.MethodGet, "/api/v1/guest/" + other.ID, ""},
		{"other panels", http.MethodGet, "/api/v1/guest/" + token + "x", ""},
		{"other panels", http.MethodGet, "/api/v1/guest/" + strings.ToLower(token), ""},
		{"unknown", http.MethodGet, "/api/v1/no-such-endpoint", ""},
	}
	creds := map[string]http.Header{
		"as session cookie":        {"Cookie": {SessionCookie + "=" + token}},
		"as secure session cookie": {"Cookie": {SecureSessionCookie + "=" + token}},
		"as bearer token":          {"Authorization": {"Bearer " + token}},
		"as panel header":          {"X-Hearth-Panel": {token}},
	}
	for credName, h := range creds {
		for _, rt := range routes {
			t.Run(rt.family+" "+rt.method+" "+rt.path+" "+credName, func(t *testing.T) {
				r := f.raw(t, rt.method, rt.path, rt.body, h)
				// 410 is the approval link routes' answer to any link they
				// do not know.
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

	// Within the guest API: only this panel's widgets and actions.
	pi := mine.Widgets[0]
	nas := other.Widgets[0]
	guestActions := []struct {
		name, token, widget, action string
		want                        int
	}{
		{"an action not on the widget", token, pi.ID, "device.restart:systemd:kodi", http.StatusNotFound},
		{"a dangerous action", token, pi.ID, "device.exec:", http.StatusNotFound},
		{"an entity not on the panel", token, nas.ID, nas.Actions[0].ID, http.StatusNotFound},
		{"an unknown widget", token, "nope", pi.Actions[0].ID, http.StatusNotFound},
		{"another panel's link, this panel's widget", otherToken, pi.ID, pi.Actions[0].ID, http.StatusNotFound},
		{"no token", "", pi.ID, pi.Actions[0].ID, http.StatusUnauthorized},
	}
	for _, tt := range guestActions {
		t.Run(tt.name, func(t *testing.T) {
			body := `{"widget": "` + tt.widget + `", "action": "` + tt.action + `"}`
			if r := f.raw(t, http.MethodPost, "/api/v1/guest/"+tt.token+"/actions", body, nil); r.StatusCode != tt.want {
				t.Fatalf("status = %d %s, want %d", r.StatusCode, r.body, tt.want)
			}
		})
	}
	if runs := f.runner.runs(); len(runs) != 0 {
		t.Fatalf("ran %v", runs)
	}

	// The guest view holds no facts, labels or addresses.
	r := f.raw(t, http.MethodGet, "/api/v1/guest/"+token, "", nil)
	for _, leak := range []string{"attic", `"labels"`, `"facts"`, `"hostname"`, `"os"`, `"boot_time"`, `"nas"`, other.Name} {
		if strings.Contains(string(r.body), leak) {
			t.Errorf("guest view %s holds %q", r.body, leak)
		}
	}
}

func TestGuestLinkRevokedAndExpired(t *testing.T) {
	f := newPanelFixture(t)
	p := f.createPanel(t, restartPanel)
	revoked := f.share(t, p.ID, "")
	if r := f.do(t, http.MethodDelete, "/api/v1/panels/"+p.ID+"/links/"+revoked.Link.ID, "", f.cookie); r.StatusCode != http.StatusNoContent {
		t.Fatal(r.StatusCode)
	}
	expired := rand.Text()
	if err := f.st.Panels().CreateLink(t.Context(), store.PanelLink{
		ID: "old", PanelID: p.ID, CreatedAt: time.Now().Add(-2 * time.Hour), ExpiresAt: time.Now().Add(-time.Hour),
	}, expired); err != nil {
		t.Fatal(err)
	}
	gone := f.createPanel(t, restartPanel)
	deleted := f.share(t, gone.ID, "").Token
	if r := f.do(t, http.MethodDelete, "/api/v1/panels/"+gone.ID, "", f.cookie); r.StatusCode != http.StatusNoContent {
		t.Fatal(r.StatusCode)
	}
	w := p.Widgets[0]
	action := `{"widget": "` + w.ID + `", "action": "` + w.Actions[0].ID + `"}`
	for name, token := range map[string]string{
		"revoked": revoked.Token, "expired": expired, "panel deleted": deleted, "unknown": rand.Text(),
	} {
		for _, req := range []struct{ method, path, body string }{
			{http.MethodGet, "/api/v1/guest/" + token, ""},
			{http.MethodGet, "/api/v1/guest/" + token + "/events", ""},
			{http.MethodPost, "/api/v1/guest/" + token + "/actions", action},
			{http.MethodGet, "/p/" + token, ""},
		} {
			t.Run(name+" "+req.method+" "+req.path[:12], func(t *testing.T) {
				if r := f.raw(t, req.method, req.path, req.body, nil); r.StatusCode != http.StatusNotFound {
					t.Fatalf("status = %d %s, want 404", r.StatusCode, r.body)
				}
			})
		}
	}
	if runs := f.runner.runs(); len(runs) != 0 {
		t.Fatalf("ran %v", runs)
	}
}

func TestGuestActionRuns(t *testing.T) {
	f := newPanelFixture(t)
	p := f.createPanel(t, restartPanel)
	link := f.share(t, p.ID, "")
	w := p.Widgets[0]
	body := `{"widget": "` + w.ID + `", "action": "` + w.Actions[0].ID + `"}`

	if r := f.raw(t, http.MethodGet, "/p/"+link.Token+"?kiosk=1", "", nil); r.StatusCode != http.StatusOK {
		t.Fatalf("page = %d", r.StatusCode)
	} else if r.Header.Get("Referrer-Policy") != "no-referrer" {
		t.Errorf("Referrer-Policy = %q", r.Header.Get("Referrer-Policy"))
	}
	view := decode[GuestPanelJSON](t, f.raw(t, http.MethodGet, "/api/v1/guest/"+link.Token, "", nil))
	if view.Name != "Living room" || len(view.Widgets) != 1 || view.Widgets[0].Name != "pi-name" ||
		len(view.Widgets[0].Actions) != 1 || view.Widgets[0].Actions[0].Label != "Restart nginx" {
		t.Fatalf("view = %+v", view)
	}

	r := f.raw(t, http.MethodPost, "/api/v1/guest/"+link.Token+"/actions", body, nil)
	if r.StatusCode != http.StatusOK {
		t.Fatalf("action = %d %s", r.StatusCode, r.body)
	}
	if runs := f.runner.runs(); len(runs) != 1 || runs[0] != "pi docker:nginx" {
		t.Fatalf("runs = %v", runs)
	}
	entries, err := f.st.Audit().Query(t.Context(), store.AuditFilter{ActorKind: policy.ActorGuest}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].ActorID != "panel/"+p.ID || entries[0].Action != string(policy.DeviceRestart) ||
		entries[0].Target != "pi" || entries[0].Decision != policy.Allow || entries[0].Result != "ok" {
		t.Fatalf("audit = %+v", entries)
	}
	if strings.Contains(string(entries[0].Detail), link.Token) || !strings.Contains(string(entries[0].Detail), link.Link.ID) {
		t.Errorf("audit detail = %s, want the link's ID and not its secret", entries[0].Detail)
	}

	// Beyond the device's ceiling: denied, audited, not run.
	f.runner.mu.Lock()
	f.runner.ceiling = &agentv1.Ceiling{}
	f.runner.mu.Unlock()
	if r := f.raw(t, http.MethodPost, "/api/v1/guest/"+link.Token+"/actions", body, nil); r.StatusCode != http.StatusForbidden {
		t.Fatalf("beyond the ceiling = %d %s", r.StatusCode, r.body)
	}
	if runs := f.runner.runs(); len(runs) != 1 {
		t.Fatalf("runs = %v", runs)
	}

	// Rate-limited per link.
	limited := false
	for range guestActionBurst + 1 {
		if r := f.raw(t, http.MethodPost, "/api/v1/guest/"+link.Token+"/actions", body, nil); r.StatusCode == http.StatusTooManyRequests {
			limited = true
			if r.Header.Get("Retry-After") == "" {
				t.Error("429 without Retry-After")
			}
			break
		}
	}
	if !limited {
		t.Error("never rate-limited")
	}
	// Another link of the same panel has a bucket of its own.
	f.runner.mu.Lock()
	f.runner.ceiling = &agentv1.Ceiling{Restart: []string{"docker:nginx"}}
	f.runner.mu.Unlock()
	second := f.share(t, p.ID, "")
	if r := f.raw(t, http.MethodPost, "/api/v1/guest/"+second.Token+"/actions", body, nil); r.StatusCode != http.StatusOK {
		t.Fatalf("second link = %d %s", r.StatusCode, r.body)
	}
	// Tokens travel in paths: none reached the logs.
	for _, s := range []string{link.Token, second.Token} {
		if strings.Contains(f.logs.String(), s) {
			t.Error("a link's secret is in the logs")
		}
	}
}

func TestGuestActionPolicy(t *testing.T) {
	for _, tt := range []struct {
		name string
		mode policy.Mode
	}{{"denied", policy.ModeDeny}, {"held", policy.ModeConfirm}} {
		t.Run(tt.name, func(t *testing.T) {
			f := newPanelFixture(t, func(c *Config) {
				c.Policy = policy.NewWithConfig(c.Store.Audit(), c.Store.Approvals(), policy.Config{
					Actors: map[string]map[policy.Class]policy.Mode{policy.ActorGuest: {policy.Safe: tt.mode}},
				})
			})
			p := f.createPanel(t, restartPanel)
			link := f.share(t, p.ID, "")
			w := p.Widgets[0]
			body := `{"widget": "` + w.ID + `", "action": "` + w.Actions[0].ID + `"}`

			done := make(chan apiResp, 1)
			go func() { done <- f.raw(t, http.MethodPost, "/api/v1/guest/"+link.Token+"/actions", body, nil) }()
			if tt.mode == policy.ModeConfirm {
				// Held, never run on its own: the operator denies it.
				ap := awaitApproval(t, f.st)
				if ap.ActorKind != policy.ActorGuest || ap.ActorID != "panel/"+p.ID || ap.Target != "pi" {
					t.Fatalf("approval = %+v", ap)
				}
				if runs := f.runner.runs(); len(runs) != 0 {
					t.Fatalf("ran %v while held", runs)
				}
				if err := f.st.Approvals().Decide(t.Context(), ap.ID, store.ApprovalDenied, "web/test", time.Now()); err != nil {
					t.Fatal(err)
				}
			}
			select {
			case r := <-done:
				if r.StatusCode != http.StatusForbidden {
					t.Fatalf("status = %d %s, want 403", r.StatusCode, r.body)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("the action never answered")
			}
			if runs := f.runner.runs(); len(runs) != 0 {
				t.Fatalf("ran %v", runs)
			}
		})
	}
}

func awaitApproval(t *testing.T, st *store.Store) store.Approval {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		aps, err := st.Approvals().List(t.Context(), store.ApprovalPending, 10)
		if err != nil {
			t.Fatal(err)
		}
		if len(aps) > 0 {
			return aps[0]
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("no approval held")
	return store.Approval{}
}

func TestGuestEvents(t *testing.T) {
	f := newPanelFixture(t)
	f.api.keepalive = 50 * time.Millisecond
	p := f.createPanel(t, restartPanel)
	link := f.share(t, p.ID, "")

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.srv.URL+"/api/v1/guest/"+link.Token+"/events", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := f.srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	body := resp.Body
	lines := make(chan string, 64)
	go func() {
		defer close(lines)
		buf := make([]byte, 4096)
		for {
			n, err := body.Read(buf)
			if n > 0 {
				lines <- string(buf[:n])
			}
			if err != nil {
				return
			}
		}
	}()
	await := func(want string) string {
		t.Helper()
		var got strings.Builder
		for {
			select {
			case s, ok := <-lines:
				if !ok {
					return got.String() + "<EOF>"
				}
				got.WriteString(s)
				if strings.Contains(got.String(), want) {
					return got.String()
				}
			case <-ctx.Done():
				t.Fatalf("waiting for %q, got %q", want, got.String())
			}
		}
	}
	await(": subscribed")
	// A device not on the panel says nothing; one on it says "changed".
	if err := f.api.registry.Heartbeat(ctx, "nas", time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := f.api.registry.Heartbeat(ctx, "pi", time.Hour); err != nil {
		t.Fatal(err)
	}
	if got := await("event: changed"); strings.Contains(got, "nas") || strings.Contains(got, "pi-name") {
		t.Errorf("stream %q names a device", got)
	}
	// An edit of the panel is a change too, seen at the next keepalive.
	time.Sleep(5 * time.Millisecond) // a later updated_at
	if r := f.do(t, http.MethodPut, "/api/v1/panels/"+p.ID, `{"name": "Renamed", "widgets": []}`, f.cookie); r.StatusCode != http.StatusOK {
		t.Fatal(r.StatusCode)
	}
	await("event: changed")
	// Revoking the link ends the stream.
	if r := f.do(t, http.MethodDelete, "/api/v1/panels/"+p.ID+"/links/"+link.Link.ID, "", f.cookie); r.StatusCode != http.StatusNoContent {
		t.Fatal(r.StatusCode)
	}
	if got := await("<EOF>"); !strings.HasSuffix(got, "<EOF>") {
		t.Errorf("stream did not end: %q", got)
	}
}
