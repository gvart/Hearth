// SPDX-License-Identifier: AGPL-3.0-only

package unifi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/discovery"
	"github.com/gvart/hearth/internal/integrations/kubernetes"
	"github.com/gvart/hearth/internal/integrations/unifi/unifimock"
	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

const (
	webActor = "192.0.2.1"
	apMAC    = "74:ac:b9:00:00:03"
)

type fixture struct {
	m    *Manager
	st   *store.Store
	mock *unifimock.Server
	url  string
	fp   string
	mode mode
	logs *lockedWriter
}

func newFixture(t *testing.T, m mode, cfg policy.Config) *fixture {
	t.Helper()
	mock := unifimock.New(m.kind)
	url, fp := newMockServer(t, mock)
	st, err := store.Open(t.Context(), filepath.Join(t.TempDir(), "hearth.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	sealer, err := kubernetes.NewPurposeSealer([]byte("test CA key"), SealInfo)
	if err != nil {
		t.Fatal(err)
	}
	logs := &lockedWriter{w: &bytes.Buffer{}}
	pol := policy.NewWithConfig(st.Audit(), st.Approvals(), cfg)
	mgr := NewManager(Config{
		Store: st, Sealer: sealer, Policy: pol, Log: slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		PollInterval: 20 * time.Millisecond, SyncInterval: 20 * time.Millisecond,
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- mgr.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Run: %v", err)
		}
	})
	return &fixture{m: mgr, st: st, mock: mock, url: url, fp: fp, mode: m, logs: logs}
}

func (f *fixture) request() AddRequest {
	c := mockConnection(f.mode, f.url, f.fp)
	return AddRequest{
		Name: "console", URL: c.URL, Kind: c.Kind, APIKey: c.APIKey, Username: c.Username, Password: c.Password, Fingerprint: c.Fingerprint,
	}
}

func (f *fixture) add(t *testing.T) ControllerInfo {
	t.Helper()
	info, err := f.m.Add(t.Context(), webActor, f.request())
	if err != nil {
		t.Fatal(err)
	}
	f.waitState(t, info.ID, StateConnected)
	return info
}

func (f *fixture) waitState(t *testing.T, id, state string) Snapshot {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		s, err := f.m.Snapshot(id)
		if err == nil && s.Controller.State == state {
			return s
		}
		if time.Now().After(deadline) {
			t.Fatalf("controller state = %+v, %v; want %s", s.Controller, err, state)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func (f *fixture) audit(t *testing.T, action policy.Action) []store.AuditEntry {
	t.Helper()
	entries, err := f.st.Audit().Query(t.Context(), store.AuditFilter{Actions: []string{string(action)}}, 50)
	if err != nil {
		t.Fatal(err)
	}
	return entries
}

// TestAdoptReadsTheEmulatedController is the issue's done-when: a
// controller adopted through the manager is read from the emulated
// instance, in each mode.
func TestAdoptReadsTheEmulatedController(t *testing.T) {
	for name, m := range modes {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, m, policy.Config{})
			info := f.add(t)
			wantAuth := AuthPassword
			if m.key {
				wantAuth = AuthAPIKey
			}
			if info.TLS != TLSFingerprint || info.Auth != wantAuth || info.Kind != m.kind || info.Site != DefaultSite {
				t.Errorf("info = %+v", info)
			}
			s, err := f.m.Snapshot(info.ID)
			if err != nil {
				t.Fatal(err)
			}
			if s.Controller.Devices != 4 || s.Controller.Clients != 5 || len(s.Devices) != 4 || len(s.Clients) != 5 ||
				len(s.Health) != 5 || s.RestartClass != "dangerous" {
				t.Errorf("snapshot = %+v", s)
			}
			if got := f.audit(t, policy.UniFiControllerAdd); len(got) != 1 || got[0].Decision != policy.Allow {
				t.Errorf("add audit = %+v", got)
			}
			if _, err := f.m.Add(t.Context(), webActor, f.request()); !errors.Is(err, ErrNameTaken) {
				t.Errorf("second add = %v, want ErrNameTaken", err)
			}
		})
	}
}

// TestSecretsStaySealed: no credential, session cookie or CSRF token is in
// the API's answers, the audit log, the logs or the stored row.
func TestSecretsStaySealed(t *testing.T) {
	for name, m := range modes {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, m, policy.Config{})
			info := f.add(t)
			if _, err := f.m.RestartAP(t.Context(), policy.ActorWeb, webActor, info.ID, apMAC, nil); err != nil {
				t.Fatal(err)
			}
			s, err := f.m.Snapshot(info.ID)
			if err != nil {
				t.Fatal(err)
			}
			served, err := json.Marshal(struct {
				C []ControllerInfo
				S Snapshot
			}{f.m.Controllers(), s})
			if err != nil {
				t.Fatal(err)
			}
			stored, err := f.st.UniFiControllers().List(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			entries, err := f.st.Audit().List(t.Context(), 50)
			if err != nil {
				t.Fatal(err)
			}
			audited, err := json.Marshal(entries)
			if err != nil {
				t.Fatal(err)
			}
			secrets := append([]string{unifimock.Password, unifimock.APIKey}, f.mock.Secrets()...)
			if !m.key && len(secrets) < 4 {
				t.Fatalf("the mock issued no session: %v", secrets)
			}
			for _, secret := range secrets {
				for what, text := range map[string]string{
					"API": string(served), "audit": string(audited), "logs": f.logs.String(), "store": string(stored[0].Sealed),
				} {
					if strings.Contains(text, secret) {
						t.Errorf("the %s holds a secret", what)
					}
				}
			}
		})
	}
}

func TestBadLoginShowsUnavailable(t *testing.T) {
	for name, m := range modes {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, m, policy.Config{})
			f.mock.SetPassword("changed on the controller")
			f.mock.SetAPIKey("revoked")
			info, err := f.m.Add(t.Context(), webActor, f.request())
			if err != nil {
				t.Fatal(err)
			}
			s := f.waitState(t, info.ID, StateUnavailable)
			if s.Controller.Error != ErrBadLogin.Error() || len(s.Clients) != 0 || len(s.Devices) != 0 {
				t.Errorf("snapshot = %+v", s)
			}
			if _, err := f.m.RestartAP(t.Context(), policy.ActorWeb, webActor, info.ID, apMAC, nil); !errors.Is(err, ErrUnavailable) {
				t.Errorf("restart on an unavailable controller = %v, want ErrUnavailable", err)
			}
		})
	}
}

func TestSessionExpiryKeepsReading(t *testing.T) {
	f := newFixture(t, modes["unifi os, password"], policy.Config{})
	info := f.add(t)
	logins := f.mock.Logins()
	f.mock.Expire()
	deadline := time.Now().Add(5 * time.Second)
	for f.mock.Logins() == logins {
		if time.Now().After(deadline) {
			t.Fatal("no new login after the session expired")
		}
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(60 * time.Millisecond)
	if s := f.waitState(t, info.ID, StateConnected); s.Controller.Error != "" || len(s.Clients) == 0 {
		t.Errorf("after re-login: %+v", s)
	}
}

func TestForbiddenHealthShowsNotRead(t *testing.T) {
	f := newFixture(t, modes["unifi os, api key"], policy.Config{})
	f.mock.Deny("stat/health")
	info := f.add(t)
	s, err := f.m.Snapshot(info.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Missing) != 1 || !strings.HasPrefix(s.Missing[0], "health: ") || len(s.Health) != 0 || len(s.Clients) != 5 {
		t.Errorf("snapshot = %+v", s)
	}
}

func TestRestartAP(t *testing.T) {
	for name, m := range modes {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, m, policy.Config{})
			info := f.add(t)
			res, err := f.m.RestartAP(t.Context(), policy.ActorWeb, webActor, info.ID, "74-AC-B9-00-00-03", nil)
			if err != nil {
				t.Fatal(err)
			}
			if res.Class != "dangerous" || res.Target != "console/Living room AP" {
				t.Errorf("result = %+v", res)
			}
			if got := f.mock.Restarts(); len(got) != 1 || got[0] != apMAC {
				t.Errorf("restarts = %v", got)
			}
			got := f.audit(t, policy.UniFiAPRestart)
			if len(got) != 1 || got[0].Decision != policy.Allow || !strings.Contains(string(got[0].Detail), apMAC) {
				t.Errorf("audit = %+v", got)
			}
		})
	}
}

func TestRestartOnlyAnAccessPoint(t *testing.T) {
	f := newFixture(t, modes["classic, password"], policy.Config{})
	info := f.add(t)
	for name, mac := range map[string]string{
		"the gateway": "74:ac:b9:00:00:01", "a switch": "74:ac:b9:00:00:02", "a client": "a4:5e:60:00:00:11",
		"unknown": "02:00:00:00:00:99", "not a mac": "../stat/sta",
	} {
		if _, err := f.m.RestartAP(t.Context(), policy.ActorWeb, webActor, info.ID, mac, nil); !errors.Is(err, ErrNoSuchAP) {
			t.Errorf("restart %s = %v, want ErrNoSuchAP", name, err)
		}
	}
	if len(f.mock.Restarts()) != 0 || len(f.audit(t, policy.UniFiAPRestart)) != 0 {
		t.Error("a restart of no access point reached policy or the controller")
	}
}

func TestRestartAPRefused(t *testing.T) {
	errNoReauth := fmt.Errorf("no reauth: %w", policy.ErrDenied)
	denyDangerous := policy.Config{Classes: map[policy.Class]policy.Mode{policy.Dangerous: policy.ModeDeny}}
	for name, tc := range map[string]struct {
		cfg      policy.Config
		kind     string
		precheck func(context.Context) error
		want     error
	}{
		"dangerous denied":       {denyDangerous, policy.ActorWeb, nil, policy.ErrDenied},
		"no re-authentication":   {policy.Config{}, policy.ActorWeb, func(context.Context) error { return errNoReauth }, errNoReauth},
		"an automation may not":  {policy.Config{}, policy.ActorAutomation, nil, policy.ErrDenied},
		"an MCP client may not":  {policy.Config{}, policy.ActorMCP, nil, policy.ErrDenied},
		"an agent token may not": {policy.Config{}, policy.ActorToken, nil, policy.ErrDenied},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, modes["unifi os, password"], tc.cfg)
			info := f.add(t)
			_, err := f.m.RestartAP(t.Context(), tc.kind, "someone", info.ID, apMAC, tc.precheck)
			if !errors.Is(err, tc.want) {
				t.Errorf("restart = %v, want %v", err, tc.want)
			}
			if got := f.audit(t, policy.UniFiAPRestart); len(got) != 1 || got[0].Decision != policy.Deny {
				t.Errorf("audit = %+v, want one denial", got)
			}
			for _, r := range f.mock.Requests() {
				if strings.HasSuffix(r.Path, "/cmd/devmgr") {
					t.Errorf("a refused restart reached the controller: %+v", r)
				}
			}
		})
	}
}

func TestUnknownController(t *testing.T) {
	f := newFixture(t, modes["classic, password"], policy.Config{})
	if _, err := f.m.Snapshot("nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Snapshot = %v", err)
	}
	if _, err := f.m.RestartAP(t.Context(), policy.ActorWeb, webActor, "nope", apMAC, nil); !errors.Is(err, ErrNotFound) {
		t.Errorf("RestartAP = %v", err)
	}
	if err := f.m.Remove(t.Context(), webActor, "nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Remove = %v", err)
	}
}

func TestRemoveStopsReading(t *testing.T) {
	f := newFixture(t, modes["classic, password"], policy.Config{})
	info := f.add(t)
	if err := f.m.Remove(t.Context(), webActor, info.ID); err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(5 * time.Second); len(f.m.Controllers()) != 0; time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("controllers = %+v", f.m.Controllers())
		}
	}
	if got := f.audit(t, policy.UniFiControllerRemove); len(got) != 1 {
		t.Errorf("remove audit = %+v", got)
	}
}

func TestAddValidates(t *testing.T) {
	f := newFixture(t, modes["classic, password"], policy.Config{})
	for _, req := range []AddRequest{
		{Name: "", URL: f.url, Kind: KindClassic, Username: "root", Password: "pw"},
		{Name: "c", URL: "http://192.168.1.1", Kind: KindClassic, Username: "root", Password: "pw"},
		{Name: "c", URL: f.url, Kind: KindClassic, Username: "root", Password: ""},
		{Name: "c", URL: f.url, Kind: KindClassic, APIKey: "key"},
	} {
		if _, err := f.m.Add(t.Context(), webActor, req); !errors.Is(err, ErrBadName) && !errors.Is(err, ErrBadConnection) {
			t.Errorf("Add(%+v) = %v", req, err)
		}
	}
	if got := f.audit(t, policy.UniFiControllerAdd); len(got) != 0 {
		t.Errorf("an invalid add was audited as an action: %+v", got)
	}
}

func TestFeedsDiscovery(t *testing.T) {
	f := newFixture(t, modes["unifi os, api key"], policy.Config{})
	if !f.m.Idle() {
		t.Error("a manager with no controller is not idle")
	}
	f.add(t)
	if f.m.Idle() {
		t.Error("a manager reading a controller is idle")
	}
	recs, err := f.m.Records(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 4 {
		t.Fatalf("records = %+v, want the 4 clients with an address", recs)
	}
	var phone discovery.Record
	for _, r := range recs {
		if r.MAC == "a4:5e:60:00:00:11" {
			phone = r
		}
		if r.Lease {
			t.Errorf("record %+v is a lease", r)
		}
	}
	if phone.Hostname != "Ana's phone" || phone.IP != "192.168.1.23" || !phone.Seen.Equal(time.Unix(1764200010, 0)) {
		t.Errorf("phone = %+v, want its alias and when the controller last heard of it", phone)
	}
	im := discovery.NewImporter(discovery.ImportConfig{
		Sources: []discovery.Source{f.m}, Hosts: f.st.NetworkHosts(),
		Policy: policy.NewWithConfig(f.st.Audit(), f.st.Approvals(), policy.Config{}),
	})
	if err := im.Import(t.Context()); err != nil {
		t.Fatal(err)
	}
	hosts, err := f.st.NetworkHosts().List(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, h := range hosts {
		if h.MAC == "a4:5e:60:00:00:11" {
			found = h.Hostname == "Ana's phone" && h.HostnameSource == store.SourceUniFi
		}
	}
	if !found || len(hosts) != 4 {
		t.Errorf("network hosts = %+v, want the controller's clients", hosts)
	}
}

// lockedWriter serializes the log lines of the manager's goroutines.
type lockedWriter struct {
	mu sync.Mutex
	w  *bytes.Buffer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

func (l *lockedWriter) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.String()
}
