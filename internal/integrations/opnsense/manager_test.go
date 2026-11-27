// SPDX-License-Identifier: AGPL-3.0-only

package opnsense

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
	"github.com/gvart/hearth/internal/integrations/opnsense/opnsensemock"
	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

const webActor = "192.0.2.1"

type fixture struct {
	m    *Manager
	st   *store.Store
	mock *opnsensemock.Server
	srv  *httptest.Server
	fp   string
	logs *lockedWriter
}

func newFixture(t *testing.T, cfg policy.Config) *fixture {
	t.Helper()
	mock, srv, fp := newMockServer(t)
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
	return &fixture{m: m, st: st, mock: mock, srv: srv, fp: fp, logs: logs}
}

func (f *fixture) request() AddRequest {
	return AddRequest{Name: "edge", URL: f.srv.URL, Key: opnsensemock.Key, Secret: opnsensemock.Secret, Fingerprint: f.fp}
}

func (f *fixture) add(t *testing.T) FirewallInfo {
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
		if err == nil && s.Firewall.State == state {
			return s
		}
		if time.Now().After(deadline) {
			t.Fatalf("firewall state = %+v, %v; want %s", s.Firewall, err, state)
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

// TestAdoptReadsTheEmulatedFirewall is the issue's done-when: a firewall
// adopted through the manager is read from the emulated instance.
func TestAdoptReadsTheEmulatedFirewall(t *testing.T) {
	f := newFixture(t, policy.Config{})
	info := f.add(t)
	if info.TLS != TLSFingerprint || info.URL != f.srv.URL {
		t.Errorf("info = %+v", info)
	}
	s, err := f.m.Snapshot(info.ID)
	if err != nil {
		t.Fatal(err)
	}
	if s.Firewall.Hostname != "edge.home.arpa" || s.Firewall.Version != "OPNsense 25.7.4-amd64" || s.Firewall.Clients != 6 ||
		s.Firmware.Latest != "25.7.5" || len(s.Interfaces) != 3 || len(s.Clients) != 6 || s.RestartClass != "dangerous" {
		t.Errorf("snapshot = %+v", s)
	}
	if got := f.audit(t, policy.OPNsenseFirewallAdd); len(got) != 1 || got[0].Decision != policy.Allow {
		t.Errorf("add audit = %+v", got)
	}
	// Two hubs adding the same name make one firewall; a second add is refused.
	req := f.request()
	req.Key, req.Secret = "x", "y"
	if _, err := f.m.Add(t.Context(), webActor, req); !errors.Is(err, ErrNameTaken) {
		t.Errorf("second add = %v, want ErrNameTaken", err)
	}
}

func TestSecretsStaySealed(t *testing.T) {
	f := newFixture(t, policy.Config{})
	info := f.add(t)
	// A refused restart and a bad key are logged and audited too.
	if _, err := f.m.RestartDNS(t.Context(), policy.ActorMCP, "someone", info.ID, nil); err == nil {
		t.Fatal("an MCP client restarted Unbound")
	}
	f.mock.SetSecret("rotated")
	f.waitState(t, info.ID, StateUnavailable)
	s, err := f.m.Snapshot(info.ID)
	if err != nil {
		t.Fatal(err)
	}
	served, err := json.Marshal(struct {
		F []FirewallInfo
		S Snapshot
	}{f.m.Firewalls(), s})
	if err != nil {
		t.Fatal(err)
	}
	stored, err := f.st.OPNsenseFirewalls().List(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	entries, err := f.st.Audit().List(t.Context(), 100)
	if err != nil {
		t.Fatal(err)
	}
	audited, err := json.Marshal(entries)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) < 2 {
		t.Fatalf("audit = %s, want the add and the refused restart", audited)
	}
	for _, secret := range []string{opnsensemock.Key, opnsensemock.Secret} {
		for what, text := range map[string]string{
			"API": string(served), "audit": string(audited), "logs": f.logs.String(),
			"store": string(stored[0].Sealed), "store name": stored[0].Name,
		} {
			if strings.Contains(text, secret) || strings.Contains(text, secret[:16]) {
				t.Errorf("the %s holds a credential", what)
			}
		}
	}
}

func TestBadKeyShowsUnavailable(t *testing.T) {
	f := newFixture(t, policy.Config{})
	f.mock.SetSecret("changed on the firewall")
	info, err := f.m.Add(t.Context(), webActor, f.request())
	if err != nil {
		t.Fatal(err)
	}
	s := f.waitState(t, info.ID, StateUnavailable)
	if s.Firewall.Error != ErrBadLogin.Error() || len(s.Clients) != 0 {
		t.Errorf("snapshot = %+v", s)
	}
	if _, err := f.m.RestartDNS(t.Context(), policy.ActorWeb, webActor, info.ID, nil); !errors.Is(err, ErrUnavailable) {
		t.Errorf("restart on an unavailable firewall = %v, want ErrUnavailable", err)
	}
}

func TestDeniedEndpointShowsNotRead(t *testing.T) {
	f := newFixture(t, policy.Config{})
	f.mock.Deny(pathTraffic)
	info := f.add(t)
	s, err := f.m.Snapshot(info.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Missing) != 1 || !strings.HasPrefix(s.Missing[0], "interfaces: ") || len(s.Interfaces) != 0 || len(s.Clients) != 6 {
		t.Errorf("snapshot = %+v, want the interfaces only not read", s)
	}
}

func TestRestartDNS(t *testing.T) {
	f := newFixture(t, policy.Config{})
	info := f.add(t)
	res, err := f.m.RestartDNS(t.Context(), policy.ActorWeb, webActor, info.ID, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Class != "dangerous" || res.Target != "edge/unbound" || res.Action != ActionRestartDNS || f.mock.Restarts() != 1 {
		t.Errorf("result = %+v, restarts = %d", res, f.mock.Restarts())
	}
	got := f.audit(t, policy.OPNsenseUnboundRestart)
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
			if got := f.audit(t, policy.OPNsenseUnboundRestart); len(got) != 1 || got[0].Decision != policy.Deny {
				t.Errorf("audit = %+v, want one denial", got)
			}
			if f.mock.Restarts() != 0 {
				t.Error("a refused restart reached the firewall")
			}
			for _, r := range f.mock.Requests() {
				if r.Path == pathRestartDNS {
					t.Errorf("a refused restart called %+v", r)
				}
			}
		})
	}
}

func TestRestartDeniedByTheFirewall(t *testing.T) {
	f := newFixture(t, policy.Config{})
	f.mock.Deny(pathRestartDNS)
	info := f.add(t)
	if _, err := f.m.RestartDNS(t.Context(), policy.ActorWeb, webActor, info.ID, nil); !errors.Is(err, errDenied) {
		t.Errorf("restart = %v, want the key's privileges to refuse it", err)
	}
	if f.mock.Restarts() != 0 {
		t.Error("the firewall restarted Unbound for a key without the privilege")
	}
}

func TestUnknownFirewall(t *testing.T) {
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
	if got := f.audit(t, policy.OPNsenseUnboundRestart); len(got) != 0 {
		t.Errorf("a restart of no firewall was audited: %+v", got)
	}
}

func TestRemoveStopsReading(t *testing.T) {
	f := newFixture(t, policy.Config{})
	info := f.add(t)
	if err := f.m.Remove(t.Context(), webActor, info.ID); err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(5 * time.Second); len(f.m.Firewalls()) != 0; time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("firewalls = %+v", f.m.Firewalls())
		}
	}
	if got := f.audit(t, policy.OPNsenseFirewallRemove); len(got) != 1 {
		t.Errorf("remove audit = %+v", got)
	}
}

func TestAddValidates(t *testing.T) {
	f := newFixture(t, policy.Config{})
	for _, req := range []AddRequest{
		{Name: "", URL: f.srv.URL, Key: "k", Secret: "s"},
		{Name: "fw", URL: "http://192.168.1.1", Key: "k", Secret: "s"},
		{Name: "fw", URL: f.srv.URL, Key: "k", Secret: ""},
		{Name: "fw", URL: f.srv.URL, Key: "", Secret: "s"},
	} {
		if _, err := f.m.Add(t.Context(), webActor, req); !errors.Is(err, ErrBadName) && !errors.Is(err, ErrBadConnection) {
			t.Errorf("Add(%+v) = %v", req, err)
		}
	}
	if got := f.audit(t, policy.OPNsenseFirewallAdd); len(got) != 0 {
		t.Errorf("an invalid add was audited as an action: %+v", got)
	}
}

func TestFeedsDiscovery(t *testing.T) {
	f := newFixture(t, policy.Config{})
	if !f.m.Idle() {
		t.Error("a manager with no firewall is not idle")
	}
	f.add(t)
	if f.m.Idle() {
		t.Error("a manager reading a firewall is idle")
	}
	recs, err := f.m.Records(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 6 {
		t.Fatalf("records = %+v, want the 6 clients with an IPv4 address", recs)
	}
	byMAC := map[string]discovery.Record{}
	for _, r := range recs {
		byMAC[r.MAC] = r
	}
	if phone := byMAC["a4:5e:60:00:00:02"]; phone.Hostname != "pixel-8" || phone.IP != "192.168.1.23" || !phone.Lease ||
		phone.Seen.IsZero() || phone.Vendor != "Google, Inc." {
		t.Errorf("phone = %+v, want its lease name and seen in the ARP table", phone)
	}
	if s := byMAC["f0:99:b6:00:00:05"]; s.Lease || s.Seen.IsZero() {
		t.Errorf("ARP-only host = %+v, want no lease, seen now", s)
	}
	if p := byMAC["00:1b:a9:00:00:03"]; !p.Lease || !p.Seen.IsZero() {
		t.Errorf("printer = %+v, want a lease not in the ARP table", p)
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
			found = h.Hostname == "pixel-8" && h.HostnameSource == store.SourceOPNsense
		}
	}
	if !found || len(hosts) != 6 {
		t.Errorf("network hosts = %+v, want the firewall's clients", hosts)
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
		t.Errorf("an import of no firewall was audited: %+v", got)
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
