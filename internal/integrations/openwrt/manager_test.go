// SPDX-License-Identifier: AGPL-3.0-only

package openwrt

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/discovery"
	"github.com/gvart/hearth/internal/integrations/kubernetes"
	"github.com/gvart/hearth/internal/integrations/openwrt/openwrtmock"
	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

const webActor = "192.0.2.1"

type fixture struct {
	m    *Manager
	st   *store.Store
	mock *openwrtmock.Server
	srv  *httptest.Server
	logs *lockedWriter
}

func newFixture(t *testing.T, cfg policy.Config) *fixture {
	t.Helper()
	mock := openwrtmock.New(openwrtmock.Username, openwrtmock.Password)
	srv := httptest.NewServer(mock)
	t.Cleanup(srv.Close)
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
	m := NewManager(Config{
		Store: st, Sealer: sealer, Policy: pol, Log: slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		PollInterval: 20 * time.Millisecond, SyncInterval: 20 * time.Millisecond,
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- m.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Run: %v", err)
		}
	})
	return &fixture{m: m, st: st, mock: mock, srv: srv, logs: logs}
}

func (f *fixture) add(t *testing.T) RouterInfo {
	t.Helper()
	info, err := f.m.Add(t.Context(), webActor, AddRequest{
		Name: "gateway", URL: f.srv.URL, Username: openwrtmock.Username, Password: openwrtmock.Password,
	})
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
		if err == nil && s.Router.State == state {
			return s
		}
		if time.Now().After(deadline) {
			t.Fatalf("router state = %+v, %v; want %s", s.Router, err, state)
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

// TestAdoptReadsTheEmulatedRouter is the issue's done-when: a router adopted
// through the manager is read from the emulated instance.
func TestAdoptReadsTheEmulatedRouter(t *testing.T) {
	f := newFixture(t, policy.Config{})
	info := f.add(t)
	if info.TLS != TLSNone || info.Username != openwrtmock.Username {
		t.Errorf("info = %+v", info)
	}
	s, err := f.m.Snapshot(info.ID)
	if err != nil {
		t.Fatal(err)
	}
	if s.Router.Hostname != "gateway" || s.Router.Clients != 5 || s.System.Model != "GL.iNet GL-MT6000" ||
		len(s.Interfaces) != 4 || len(s.Clients) != 5 || s.RestartClass != "dangerous" {
		t.Errorf("snapshot = %+v", s)
	}
	if got := f.audit(t, policy.OpenWrtRouterAdd); len(got) != 1 || got[0].Decision != policy.Allow {
		t.Errorf("add audit = %+v", got)
	}
	// Two hubs adding the same name make one router; a second add is refused.
	if _, err := f.m.Add(t.Context(), webActor, AddRequest{
		Name: "gateway", URL: f.srv.URL, Username: "x", Password: "y",
	}); !errors.Is(err, ErrNameTaken) {
		t.Errorf("second add = %v, want ErrNameTaken", err)
	}
}

func TestSecretsStaySealed(t *testing.T) {
	f := newFixture(t, policy.Config{})
	info := f.add(t)
	s, err := f.m.Snapshot(info.ID)
	if err != nil {
		t.Fatal(err)
	}
	served, err := json.Marshal(struct {
		R []RouterInfo
		S Snapshot
	}{f.m.Routers(), s})
	if err != nil {
		t.Fatal(err)
	}
	var sessions []string
	for _, c := range f.mock.Calls() {
		if c.Session != "" && c.Session != nullSession {
			sessions = append(sessions, c.Session)
		}
	}
	if len(sessions) == 0 {
		t.Fatal("no call carried a session")
	}
	stored, err := f.st.OpenWrtRouters().List(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	entries := f.audit(t, policy.OpenWrtRouterAdd)
	audited, err := json.Marshal(entries)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range append([]string{openwrtmock.Password}, sessions[0]) {
		for what, text := range map[string]string{
			"API": string(served), "audit": string(audited), "logs": f.logs.String(),
			"store": string(stored[0].Sealed),
		} {
			if strings.Contains(text, secret) {
				t.Errorf("the %s holds a secret", what)
			}
		}
	}
}

func TestBadLoginShowsUnavailable(t *testing.T) {
	f := newFixture(t, policy.Config{})
	f.mock.SetPassword("changed on the router")
	info, err := f.m.Add(t.Context(), webActor, AddRequest{
		Name: "gateway", URL: f.srv.URL, Username: openwrtmock.Username, Password: openwrtmock.Password,
	})
	if err != nil {
		t.Fatal(err)
	}
	s := f.waitState(t, info.ID, StateUnavailable)
	if s.Router.Error != ErrBadLogin.Error() || len(s.Clients) != 0 {
		t.Errorf("snapshot = %+v", s)
	}
	if _, err := f.m.RestartDNS(t.Context(), policy.ActorWeb, webActor, info.ID, nil); !errors.Is(err, ErrUnavailable) {
		t.Errorf("restart on an unavailable router = %v, want ErrUnavailable", err)
	}
}

func TestSessionExpiryKeepsReading(t *testing.T) {
	f := newFixture(t, policy.Config{})
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
	if s := f.waitState(t, info.ID, StateConnected); s.Router.Error != "" || len(s.Clients) == 0 {
		t.Errorf("after re-login: %+v", s)
	}
}

func TestRestartDNS(t *testing.T) {
	f := newFixture(t, policy.Config{})
	info := f.add(t)
	res, err := f.m.RestartDNS(t.Context(), policy.ActorWeb, webActor, info.ID, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Class != "dangerous" || res.Target != "gateway/dnsmasq" || f.mock.Restarts() != 1 {
		t.Errorf("result = %+v, restarts = %d", res, f.mock.Restarts())
	}
	got := f.audit(t, policy.OpenWrtDNSRestart)
	if len(got) != 1 || got[0].Decision != policy.Allow {
		t.Errorf("audit = %+v", got)
	}
}

func TestRestartDNSRefused(t *testing.T) {
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
			f := newFixture(t, tc.cfg)
			info := f.add(t)
			_, err := f.m.RestartDNS(t.Context(), tc.kind, "someone", info.ID, tc.precheck)
			if !errors.Is(err, tc.want) {
				t.Errorf("restart = %v, want %v", err, tc.want)
			}
			if got := f.audit(t, policy.OpenWrtDNSRestart); len(got) != 1 || got[0].Decision != policy.Deny {
				t.Errorf("audit = %+v, want one denial", got)
			}
			if f.mock.Restarts() != 0 {
				t.Error("a refused restart reached the router")
			}
			for _, c := range f.mock.Calls() {
				if c.Object == "rc" {
					t.Errorf("a refused restart called %+v", c)
				}
			}
		})
	}
}

func TestUnknownRouter(t *testing.T) {
	f := newFixture(t, policy.Config{})
	if _, err := f.m.Snapshot("nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Snapshot = %v", err)
	}
	if _, err := f.m.RestartDNS(t.Context(), policy.ActorWeb, webActor, "nope", nil); !errors.Is(err, ErrNotFound) {
		t.Errorf("RestartDNS = %v", err)
	}
	if err := f.m.Remove(t.Context(), webActor, "nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Remove = %v", err)
	}
}

func TestRemoveStopsReading(t *testing.T) {
	f := newFixture(t, policy.Config{})
	info := f.add(t)
	if err := f.m.Remove(t.Context(), webActor, info.ID); err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(5 * time.Second); len(f.m.Routers()) != 0; time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("routers = %+v", f.m.Routers())
		}
	}
	if got := f.audit(t, policy.OpenWrtRouterRemove); len(got) != 1 {
		t.Errorf("remove audit = %+v", got)
	}
}

func TestAddValidates(t *testing.T) {
	f := newFixture(t, policy.Config{})
	for _, req := range []AddRequest{
		{Name: "", URL: f.srv.URL, Username: "root", Password: "pw"},
		{Name: "gw", URL: "ftp://192.168.1.1", Username: "root", Password: "pw"},
		{Name: "gw", URL: f.srv.URL, Username: "root", Password: ""},
	} {
		if _, err := f.m.Add(t.Context(), webActor, req); !errors.Is(err, ErrBadName) && !errors.Is(err, ErrBadConnection) {
			t.Errorf("Add(%+v) = %v", req, err)
		}
	}
	if got := f.audit(t, policy.OpenWrtRouterAdd); len(got) != 0 {
		t.Errorf("an invalid add was audited as an action: %+v", got)
	}
}

func TestFeedsDiscovery(t *testing.T) {
	f := newFixture(t, policy.Config{})
	if !f.m.Idle() {
		t.Error("a manager with no router is not idle")
	}
	f.add(t)
	if f.m.Idle() {
		t.Error("a manager reading a router is idle")
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
		if r.MAC == "a4:5e:60:00:00:02" {
			phone = r
		}
		if !r.Lease {
			t.Errorf("record %+v is no lease", r)
		}
	}
	if phone.Hostname != "pixel-8" || phone.IP != "192.168.1.23" || phone.Seen.IsZero() {
		t.Errorf("phone = %+v, want its lease name and when the radio heard it", phone)
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
		if h.MAC == "a4:5e:60:00:00:02" {
			found = h.Hostname == "pixel-8" && h.HostnameSource == store.SourceOpenWrt
		}
	}
	if !found || len(hosts) != 4 {
		t.Errorf("network hosts = %+v, want the router's clients", hosts)
	}
}

func TestIdleSourceIsNotImported(t *testing.T) {
	f := newFixture(t, policy.Config{})
	im := discovery.NewImporter(discovery.ImportConfig{
		Sources: []discovery.Source{f.m}, Hosts: f.st.NetworkHosts(),
		Policy: policy.NewWithConfig(f.st.Audit(), f.st.Approvals(), policy.Config{}),
	})
	if err := im.Import(t.Context()); err != nil {
		t.Fatal(err)
	}
	if got := f.audit(t, policy.NetworkImport); len(got) != 0 {
		t.Errorf("an import of no router was audited: %+v", got)
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
