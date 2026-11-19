// SPDX-License-Identifier: AGPL-3.0-only

package proxmox

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/integrations/kubernetes"
	"github.com/gvart/hearth/internal/integrations/proxmox/pvemock"
	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

const webActor = "192.0.2.1"

// genCA is a CA certificate that signed nothing the tests serve.
func genCA(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "other CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

type fixture struct {
	m      *Manager
	st     *store.Store
	pol    *policy.Engine
	sealer *kubernetes.Sealer
	mock   *pvemock.Server
	srv    *httptest.Server
}

// newFixture runs a manager with the policy configuration cfg on a fresh
// store, with a mock Proxmox API over TLS.
func newFixture(t *testing.T, cfg policy.Config) *fixture {
	t.Helper()
	return newPolledFixture(t, cfg, 20*time.Millisecond)
}

// newPolledFixture is newFixture reading the server every poll.
func newPolledFixture(t *testing.T, cfg policy.Config, poll time.Duration) *fixture {
	t.Helper()
	mock := pvemock.New(pvemock.Token)
	srv := httptest.NewTLSServer(mock)
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
	pol := policy.NewWithConfig(st.Audit(), st.Approvals(), cfg)
	m := NewManager(Config{
		Store: st, Sealer: sealer, Policy: pol,
		PollInterval: poll, SyncInterval: 20 * time.Millisecond,
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
	return &fixture{m: m, st: st, pol: pol, sealer: sealer, mock: mock, srv: srv}
}

func (f *fixture) add(t *testing.T) ServerInfo {
	t.Helper()
	info, err := f.m.Add(t.Context(), webActor, AddRequest{
		Name: "lab", URL: f.srv.URL, Token: pvemock.Token, Fingerprint: fingerprintOf(f.srv),
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
		if err == nil && s.Server.State == state {
			return s
		}
		if time.Now().After(deadline) {
			t.Fatalf("server state = %+v, %v; want %s", s.Server, err, state)
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

func TestReadsNodesGuestsAndStorage(t *testing.T) {
	f := newFixture(t, policy.Config{})
	info := f.add(t)
	s, err := f.m.Snapshot(info.ID)
	if err != nil {
		t.Fatal(err)
	}

	var nodes []string
	for _, n := range s.Nodes {
		nodes = append(nodes, n.Name+":"+n.Status)
	}
	if want := []string{"pve1:online", "pve2:online", "pve3:offline"}; !slices.Equal(nodes, want) {
		t.Errorf("nodes = %v, want %v", nodes, want)
	}
	if n := s.Nodes[0]; n.MaxCPU != 8 || n.MaxMem != 32<<30 || n.Mem != 9<<30 || n.Uptime != 604800 || n.CPU != 0.12 {
		t.Errorf("node = %+v", n)
	}

	var guests []string
	for _, g := range s.Guests {
		guests = append(guests, g.Kind+"/"+g.Name+"/"+g.Node+"/"+g.Status)
	}
	want := []string{
		"qemu/home-assistant/pve1/running", "qemu/backup-vm/pve1/stopped", "qemu/k3s-worker/pve2/running",
		"lxc/pihole/pve1/running", "lxc/nginx/pve2/stopped", "lxc/gitea/pve3/unknown",
	}
	if !slices.Equal(guests, want) {
		t.Errorf("guests (no template) = %v, want %v", guests, want)
	}

	var storage []string
	for _, st := range s.Storage {
		storage = append(storage, st.Name+"@"+st.Node+"/"+st.Type+"/"+st.Status)
	}
	wantStorage := []string{
		"local@pve1/dir/available", "local-lvm@pve1/lvmthin/available",
		"nas@pve1/nfs/available", "nas@pve2/nfs/available", "nas@pve3/nfs/unknown",
	}
	if !slices.Equal(storage, wantStorage) {
		t.Errorf("storage = %v, want %v", storage, wantStorage)
	}
	if i := slices.IndexFunc(s.Storage, func(st Storage) bool { return st.Name == "nas" }); i < 0 || !s.Storage[i].Shared || s.Storage[i].Total != 500<<30 {
		t.Errorf("nas = %+v", s.Storage[i])
	}
	if i := slices.IndexFunc(s.Storage, func(st Storage) bool { return st.Name == "local" }); s.Storage[i].Shared {
		t.Errorf("local counted as shared: %+v", s.Storage[i])
	}
	if s.ActionClasses[ActionStart] != "safe" || s.ActionClasses[ActionStop] != "dangerous" || s.ActionClasses[ActionReboot] != "dangerous" {
		t.Errorf("action classes = %v", s.ActionClasses)
	}
	if s.Server.Nodes != 3 || s.Server.Guests != 6 || s.Server.TLS != TLSFingerprint || s.Server.URL != f.srv.URL {
		t.Errorf("server = %+v", s.Server)
	}
	for _, r := range f.mock.Requests() {
		if !r.Authorized {
			t.Errorf("request without the token: %+v", r)
		}
	}
	if a := f.audit(t, policy.ProxmoxServerAdd); len(a) != 1 || a[0].Decision != policy.Allow || a[0].Target != "lab" {
		t.Errorf("add audit = %+v", a)
	}
}

func TestActionsReachTheAPI(t *testing.T) {
	for _, tc := range []struct {
		action string
		vmid   int
		path   string
		pol    policy.Action
		class  policy.Class
		status string
	}{
		{ActionStart, 101, "/api2/json/nodes/pve1/qemu/101/status/start", policy.ProxmoxGuestStart, policy.Safe, "running"},
		{ActionStop, 100, "/api2/json/nodes/pve1/qemu/100/status/stop", policy.ProxmoxGuestStop, policy.Dangerous, "stopped"},
		{ActionReboot, 102, "/api2/json/nodes/pve2/qemu/102/status/reboot", policy.ProxmoxGuestReboot, policy.Dangerous, "running"},
		{ActionStart, 201, "/api2/json/nodes/pve2/lxc/201/status/start", policy.ProxmoxGuestStart, policy.Safe, "running"},
		{ActionStop, 200, "/api2/json/nodes/pve1/lxc/200/status/stop", policy.ProxmoxGuestStop, policy.Dangerous, "stopped"},
		{ActionReboot, 200, "/api2/json/nodes/pve1/lxc/200/status/reboot", policy.ProxmoxGuestReboot, policy.Dangerous, "running"},
	} {
		t.Run(tc.action+"/"+tc.path, func(t *testing.T) {
			f := newFixture(t, policy.Config{})
			info := f.add(t)
			res, err := f.m.Act(t.Context(), policy.ActorWeb, webActor, info.ID, ActionRequest{Action: tc.action, VMID: tc.vmid})
			if err != nil {
				t.Fatal(err)
			}
			if got := f.mock.Posts(); !slices.Equal(got, []string{tc.path}) {
				t.Errorf("POSTs = %v, want %s", got, tc.path)
			}
			if got := f.mock.GuestStatus(tc.vmid); got != tc.status {
				t.Errorf("guest status = %q, want %q", got, tc.status)
			}
			if res.Class != string(tc.class) || !strings.HasPrefix(res.Task, "UPID:") || !strings.Contains(res.Result, "accepted") {
				t.Errorf("result = %+v", res)
			}
			if class, _ := policy.ClassOf(tc.pol); class != tc.class {
				t.Errorf("class of %s = %s, want %s", tc.pol, class, tc.class)
			}
			a := f.audit(t, tc.pol)
			if len(a) != 1 || a[0].Decision != policy.Allow || a[0].Result != "ok" || a[0].ActorKind != policy.ActorWeb {
				t.Fatalf("audit = %+v", a)
			}
			if !strings.HasPrefix(a[0].Target, "lab/") {
				t.Errorf("audit target = %q", a[0].Target)
			}
		})
	}
}

func TestDeniedActionNeverReachesTheAPI(t *testing.T) {
	denyAll := policy.Config{Classes: map[policy.Class]policy.Mode{policy.Safe: policy.ModeDeny, policy.Dangerous: policy.ModeDeny}}
	denyWeb := policy.Config{Actors: map[string]map[policy.Class]policy.Mode{
		policy.ActorWeb: {policy.Safe: policy.ModeDeny, policy.Dangerous: policy.ModeDeny},
	}}
	allowAll := policy.Config{Classes: map[policy.Class]policy.Mode{policy.Safe: policy.ModeAllow, policy.Dangerous: policy.ModeAllow}}
	actions := []struct {
		action string
		vmid   int
		pol    policy.Action
	}{
		{ActionStart, 101, policy.ProxmoxGuestStart},
		{ActionStop, 100, policy.ProxmoxGuestStop},
		{ActionReboot, 100, policy.ProxmoxGuestReboot},
	}
	for name, tc := range map[string]struct {
		cfg     policy.Config
		kind    string
		actorID string
	}{
		"class denied":           {denyAll, policy.ActorWeb, webActor},
		"actor kind denied":      {denyWeb, policy.ActorWeb, webActor},
		"anonymous":              {allowAll, policy.ActorWeb, ""},
		"an automation may not":  {allowAll, policy.ActorAutomation, "nightly"},
		"an MCP client may not":  {allowAll, policy.ActorMCP, "claude"},
		"an agent token may not": {allowAll, policy.ActorToken, "t1"},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, tc.cfg)
			var info ServerInfo
			if name == "class denied" || name == "actor kind denied" {
				// Adding is denied by these configurations too: seed the store.
				info = f.seed(t)
			} else {
				info = f.add(t)
			}
			for _, a := range actions {
				_, err := f.m.Act(t.Context(), tc.kind, tc.actorID, info.ID, ActionRequest{Action: a.action, VMID: a.vmid})
				if !errors.Is(err, policy.ErrDenied) {
					t.Errorf("%s = %v, want a denial", a.action, err)
				}
				audited := f.audit(t, a.pol)
				if len(audited) != 1 || audited[0].Decision != policy.Deny {
					t.Errorf("%s audit = %+v, want one denial", a.action, audited)
				}
			}
			if got := f.mock.Posts(); len(got) != 0 {
				t.Errorf("a denied action reached the API: %v", got)
			}
		})
	}
}

// seed stores a server without going through policy.
func (f *fixture) seed(t *testing.T) ServerInfo {
	t.Helper()
	raw, err := json.Marshal(Connection{URL: f.srv.URL, Token: pvemock.Token, Fingerprint: fingerprintOf(f.srv)})
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := f.sealer.Seal("seeded", raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.st.ProxmoxServers().Add(t.Context(), store.ProxmoxServer{ID: "seeded", Name: "lab", Sealed: sealed, CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	return f.waitState(t, "seeded", StateConnected).Server
}

// waitHeld returns the one pending approval.
func (f *fixture) waitHeld(t *testing.T) store.Approval {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		held, err := f.st.Approvals().List(t.Context(), store.ApprovalPending, 10)
		if err != nil {
			t.Fatal(err)
		}
		if len(held) == 1 {
			return held[0]
		}
		if time.Now().After(deadline) {
			t.Fatalf("pending approvals = %+v, want one", held)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestConfirmModeHoldsTheAction(t *testing.T) {
	confirm := policy.Config{Classes: map[policy.Class]policy.Mode{policy.Dangerous: policy.ModeConfirm}}
	stop := ActionRequest{Action: ActionStop, VMID: 100}
	const stopPath = "/api2/json/nodes/pve1/qemu/100/status/stop"

	act := func(ctx context.Context, f *fixture, id string) <-chan error {
		done := make(chan error, 1)
		go func() {
			_, err := f.m.Act(ctx, policy.ActorWeb, webActor, id, stop)
			done <- err
		}()
		return done
	}
	waitResult := func(t *testing.T, done <-chan error) error {
		t.Helper()
		select {
		case err := <-done:
			return err
		case <-time.After(10 * time.Second):
			t.Fatal("the held action did not end")
			return nil
		}
	}

	t.Run("approved: sent exactly once, after the approval", func(t *testing.T) {
		f := newFixture(t, confirm)
		info := f.add(t)
		done := act(t.Context(), f, info.ID)
		held := f.waitHeld(t)
		if held.Action != string(policy.ProxmoxGuestStop) || held.Class != string(policy.Dangerous) || held.Target != "lab/qemu/100" {
			t.Errorf("held = %+v", held)
		}
		time.Sleep(100 * time.Millisecond)
		if got := f.mock.Posts(); len(got) != 0 {
			t.Fatalf("a held action reached the API: %v", got)
		}
		if err := f.pol.Decide(t.Context(), policy.ActorAdmin, "admin", held.ID, true); err != nil {
			t.Fatal(err)
		}
		if err := waitResult(t, done); err != nil {
			t.Fatal(err)
		}
		if got := f.mock.Posts(); !slices.Equal(got, []string{stopPath}) {
			t.Errorf("POSTs = %v", got)
		}
		var decisions []string
		for _, e := range f.audit(t, policy.ProxmoxGuestStop) {
			decisions = append(decisions, e.Decision)
		}
		slices.Sort(decisions)
		if !slices.Equal(decisions, []string{policy.Allow, policy.Confirm}) {
			t.Errorf("audit decisions = %v, want the hold and its release", decisions)
		}
	})

	t.Run("denied: never sent", func(t *testing.T) {
		f := newFixture(t, confirm)
		info := f.add(t)
		done := act(t.Context(), f, info.ID)
		held := f.waitHeld(t)
		if err := f.pol.Decide(t.Context(), policy.ActorAdmin, "admin", held.ID, false); err != nil {
			t.Fatal(err)
		}
		if err := waitResult(t, done); !errors.Is(err, policy.ErrDenied) {
			t.Errorf("Act = %v, want a denial", err)
		}
		if got := f.mock.Posts(); len(got) != 0 {
			t.Errorf("a refused action reached the API: %v", got)
		}
	})

	t.Run("requester gone: never sent", func(t *testing.T) {
		f := newFixture(t, confirm)
		info := f.add(t)
		ctx, cancel := context.WithCancel(t.Context())
		done := act(ctx, f, info.ID)
		f.waitHeld(t)
		// The hold is stored before it is audited: cancel once it is both.
		for deadline := time.Now().Add(5 * time.Second); len(f.audit(t, policy.ProxmoxGuestStop)) == 0; {
			if time.Now().After(deadline) {
				t.Fatal("the hold was not audited")
			}
			time.Sleep(5 * time.Millisecond)
		}
		cancel()
		if err := waitResult(t, done); !errors.Is(err, policy.ErrDenied) {
			t.Errorf("Act = %v, want a denial", err)
		}
		if got := f.mock.Posts(); len(got) != 0 {
			t.Errorf("an abandoned action reached the API: %v", got)
		}
	})

	t.Run("guest gone while held: never sent", func(t *testing.T) {
		f := newFixture(t, confirm)
		info := f.add(t)
		done := act(t.Context(), f, info.ID)
		held := f.waitHeld(t)
		f.mock.RemoveGuest(100)
		deadline := time.Now().Add(5 * time.Second)
		for {
			s, _ := f.m.Snapshot(info.ID)
			if !slices.ContainsFunc(s.Guests, func(g Guest) bool { return g.VMID == 100 }) {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("the guest did not disappear")
			}
			time.Sleep(5 * time.Millisecond)
		}
		if err := f.pol.Decide(t.Context(), policy.ActorAdmin, "admin", held.ID, true); err != nil {
			t.Fatal(err)
		}
		if err := waitResult(t, done); !errors.Is(err, ErrGuestNotFound) {
			t.Errorf("Act = %v, want ErrGuestNotFound", err)
		}
		if got := f.mock.Posts(); len(got) != 0 {
			t.Errorf("POSTs = %v", got)
		}
	})

	t.Run("a safe action is not held", func(t *testing.T) {
		f := newFixture(t, confirm)
		info := f.add(t)
		if _, err := f.m.Act(t.Context(), policy.ActorWeb, webActor, info.ID, ActionRequest{Action: ActionStart, VMID: 101}); err != nil {
			t.Fatal(err)
		}
		if got := f.mock.Posts(); len(got) != 1 {
			t.Errorf("POSTs = %v", got)
		}
	})
}

func TestActionRefusedBeforePolicy(t *testing.T) {
	f := newFixture(t, policy.Config{})
	info := f.add(t)
	for name, tc := range map[string]struct {
		id   string
		req  ActionRequest
		want error
	}{
		"unknown action":    {info.ID, ActionRequest{Action: "destroy", VMID: 100}, ErrBadAction},
		"unknown guest":     {info.ID, ActionRequest{Action: ActionStart, VMID: 4242}, ErrGuestNotFound},
		"a template":        {info.ID, ActionRequest{Action: ActionStart, VMID: 9000}, ErrGuestNotFound},
		"unknown server":    {"nope", ActionRequest{Action: ActionStart, VMID: 100}, ErrNotFound},
		"no guest selected": {info.ID, ActionRequest{Action: ActionStart}, ErrGuestNotFound},
	} {
		if _, err := f.m.Act(t.Context(), policy.ActorWeb, webActor, tc.id, tc.req); !errors.Is(err, tc.want) {
			t.Errorf("%s: Act = %v, want %v", name, err, tc.want)
		}
	}
	if got := f.mock.Posts(); len(got) != 0 {
		t.Errorf("POSTs = %v", got)
	}
}

func TestProxmoxErrorIsReported(t *testing.T) {
	f := newFixture(t, policy.Config{})
	info := f.add(t)
	// The mock refuses to stop a guest that is not running.
	_, err := f.m.Act(t.Context(), policy.ActorWeb, webActor, info.ID, ActionRequest{Action: ActionStop, VMID: 101})
	if err == nil || !strings.Contains(err.Error(), "not running") {
		t.Fatalf("Act = %v", err)
	}
	a := f.audit(t, policy.ProxmoxGuestStop)
	if len(a) != 1 || !strings.HasPrefix(a[0].Result, "error:") {
		t.Errorf("audit = %+v", a)
	}
}

func TestUnreachableServerIsUnavailable(t *testing.T) {
	f := newFixture(t, policy.Config{})
	info := f.add(t)

	f.mock.FailWith(http.StatusUnauthorized, "")
	s := f.waitState(t, info.ID, StateUnavailable)
	if !strings.Contains(s.Server.Error, "token") || len(s.Guests) != 0 || len(s.Nodes) != 0 {
		t.Errorf("snapshot = %+v", s)
	}
	if _, err := f.m.Act(t.Context(), policy.ActorWeb, webActor, info.ID, ActionRequest{Action: ActionStart, VMID: 101}); !errors.Is(err, ErrUnavailable) {
		t.Errorf("Act = %v, want ErrUnavailable", err)
	}
	if got := f.mock.Posts(); len(got) != 0 {
		t.Errorf("POSTs = %v", got)
	}

	f.mock.FailWith(0, "")
	if s := f.waitState(t, info.ID, StateConnected); len(s.Guests) != 6 {
		t.Errorf("guests after recovery = %d", len(s.Guests))
	}

	// A server gone altogether does not end Run: the cleanup checks that.
	f.srv.CloseClientConnections()
	f.srv.Close()
	if s := f.waitState(t, info.ID, StateUnavailable); s.Server.Error == "" {
		t.Error("no reason given")
	}
}

func TestStartupWithUnreachableServer(t *testing.T) {
	f := newFixture(t, policy.Config{})
	// Nothing listens on port 1. Adding never connects, so it succeeds.
	info, err := f.m.Add(t.Context(), webActor, AddRequest{
		Name: "gone", URL: "https://127.0.0.1:1", Token: pvemock.Token, Fingerprint: strings.Repeat("ab", 32),
	})
	if err != nil {
		t.Fatal(err)
	}
	s := f.waitState(t, info.ID, StateUnavailable)
	if s.Server.Error == "" || strings.Contains(s.Server.Error, pvemock.Token) {
		t.Errorf("error = %q", s.Server.Error)
	}
}

func TestTokenIsSealedAndNeverServed(t *testing.T) {
	f := newFixture(t, policy.Config{})
	info := f.add(t)
	_, secret, _ := strings.Cut(pvemock.Token, "=")

	rows, err := f.st.ProxmoxServers().List(t.Context())
	if err != nil || len(rows) != 1 {
		t.Fatalf("rows = %v, %v", rows, err)
	}
	if bytes.Contains(rows[0].Sealed, []byte(secret)) || bytes.Contains(rows[0].Sealed, []byte("hearth@pve")) {
		t.Error("the stored connection holds the token in the clear")
	}
	if _, err := f.sealer.Open("another-row", rows[0].Sealed); err == nil {
		t.Error("the sealed connection opened for another row")
	}
	kube, err := kubernetes.NewSealer([]byte("test CA key"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := kube.Open(info.ID, rows[0].Sealed); err == nil {
		t.Error("the kubeconfig key opened a proxmox connection")
	}

	snap, err := f.m.Snapshot(info.ID)
	if err != nil {
		t.Fatal(err)
	}
	served, err := json.Marshal([]any{snap, f.m.Servers(), info})
	if err != nil {
		t.Fatal(err)
	}
	entries, err := f.st.Audit().List(t.Context(), 50)
	if err != nil {
		t.Fatal(err)
	}
	audit, err := json.Marshal(entries)
	if err != nil {
		t.Fatal(err)
	}
	for name, b := range map[string][]byte{"API": served, "audit log": audit} {
		if bytes.Contains(b, []byte(secret)) {
			t.Errorf("the %s holds the token", name)
		}
	}
}

func TestCorruptRowIsUnavailable(t *testing.T) {
	f := newFixture(t, policy.Config{})
	if err := f.st.ProxmoxServers().Add(t.Context(), store.ProxmoxServer{
		ID: "bad", Name: "bad", Sealed: []byte("not sealed at all, not even close"), CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	if s := f.waitState(t, "bad", StateUnavailable); s.Server.Error != "cannot decrypt the connection" {
		t.Errorf("error = %q", s.Server.Error)
	}
}

func TestAddAndRemove(t *testing.T) {
	f := newFixture(t, policy.Config{})
	info := f.add(t)
	if _, err := f.m.Add(t.Context(), webActor, AddRequest{Name: "lab", URL: f.srv.URL, Token: pvemock.Token}); !errors.Is(err, ErrNameTaken) {
		t.Errorf("Add with a taken name = %v", err)
	}
	if _, err := f.m.Add(t.Context(), webActor, AddRequest{Name: "\x00", URL: f.srv.URL, Token: pvemock.Token}); !errors.Is(err, ErrBadName) {
		t.Errorf("Add with a bad name = %v", err)
	}
	if err := f.m.Remove(t.Context(), webActor, info.ID); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for len(f.m.Servers()) != 0 {
		if time.Now().After(deadline) {
			t.Fatal("the server is still read after Remove")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if err := f.m.Remove(t.Context(), webActor, info.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("second Remove = %v", err)
	}
	if a := f.audit(t, policy.ProxmoxServerRemove); len(a) != 2 || a[0].Decision != policy.Allow {
		t.Errorf("remove audit = %+v", a)
	}
}
