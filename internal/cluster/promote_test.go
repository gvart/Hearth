// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import (
	"cmp"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/gvart/hearth/internal/pki"
	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
	"github.com/gvart/hearth/internal/store/storetest"
)

// apTestNode is a real AP member: gossip and replication over loopback
// mutual TLS, its own data dir, store and CA (with the key only if it is a
// master).
type apTestNode struct {
	id      string
	dir     string
	ca      *pki.CA
	node    *APNode
	st      *store.Store
	addr    string
	allowed RoleSet
	// srv serves its ClusterService over TLS (FetchCAKey), at node.AgentURL.
	srv  *httptest.Server
	stop func()
	// storeOpts and config, set before start, open its store and report
	// its host flags (apschema_test.go).
	storeOpts []store.Option
	config    ConfigSource
	// caEvery, if set, is how often it reconciles its CA (100 ms if not).
	caEvery time.Duration
	// deadAfter, if set, is its --member-dead-after, with the members down
	// looked at every 50 ms (deadmembers_test.go).
	deadAfter time.Duration
	// keepMasters, if set, is its --keep-masters (keepmasters_test.go).
	keepMasters int
	// log, if set, receives its log instead of testLogger.
	log *slog.Logger
}

type apSpec struct {
	id      string
	roles   RoleSet
	allowed RoleSet
}

// newAPTestCluster starts members specs, the first of which the others
// join through, with N replicas.
func newAPTestCluster(t *testing.T, n int, specs ...apSpec) map[string]*apTestNode {
	t.Helper()
	ca, err := pki.LoadOrCreateCA(t.TempDir(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]*apTestNode{}
	var seed string
	for _, s := range specs {
		tn := startAPTestNode(t, ca, s, n, seed)
		if seed == "" {
			seed = tn.addr
		}
		out[s.id] = tn
	}
	for _, tn := range out {
		waitUntil(t, 10*time.Second, tn.id+" to see every member", func() bool {
			alive := 0
			for _, m := range tn.node.Membership().Members() {
				if m.State == MemberAlive {
					alive++
				}
			}
			return alive == len(specs)
		})
	}
	for _, tn := range out {
		if err := tn.node.RecordNodeCert(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	return out
}

func startAPTestNode(t *testing.T, ca *pki.CA, s apSpec, n int, seed string) *apTestNode {
	t.Helper()
	tn := prepareAPTestNode(t, ca, s)
	tn.start(t, n, seed)
	return tn
}

// prepareAPTestNode makes the data dir of member s, not started yet.
func prepareAPTestNode(t *testing.T, ca *pki.CA, s apSpec) *apTestNode {
	t.Helper()
	dir := t.TempDir()
	state := filepath.Join(dir, StateDir)
	if err := os.MkdirAll(state, 0o700); err != nil {
		t.Fatal(err)
	}
	if s.roles.Has(RoleMaster) {
		key, err := ca.KeyDER()
		if err != nil {
			t.Fatal(err)
		}
		if err := pki.InstallCA(dir, ca.Cert().Raw, key, ca.Fingerprint()); err != nil {
			t.Fatal(err)
		}
	} else if err := pki.InstallCACert(dir, ca.Cert().Raw, ca.Fingerprint()); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOrIssueNodeCert(state, ca, s.id, "", time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := saveLocalRoles(dir, LocalRoles{Roles: s.roles}); err != nil {
		t.Fatal(err)
	}
	return &apTestNode{id: s.id, dir: dir, allowed: s.allowed}
}

// start runs the member on its data dir.
func (tn *apTestNode) start(t *testing.T, n int, seed string) {
	t.Helper()
	ca, err := pki.LoadCA(tn.dir, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var seeds []string
	if seed != "" {
		seeds = []string{seed}
	}
	// Its ClusterService, as the hub serves it on its TLS listener.
	srv := httptest.NewUnstartedServer(nil)
	serverCert, err := issueTestServerCert(tn.dir)
	if err != nil {
		t.Fatal(err)
	}
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverCert}, ClientAuth: tls.VerifyClientCertIfGiven, ClientCAs: ca.Pool(),
	}
	node, err := NewAPNode(t.Context(), APConfig{
		DataDir: tn.dir, NodeID: tn.id, CA: ca, Allowed: tn.allowed,
		Listen: ln.Addr().String(), Listener: ln, Advertise: ln.Addr().String(), Seeds: seeds,
		Replicas: n, Log: cmp.Or(tn.log, testLogger(t)), RolesEvery: 50 * time.Millisecond, ConfigSource: tn.config,
		CAReconcileEvery: cmp.Or(tn.caEvery, 100*time.Millisecond),
		MemberDeadAfter:  tn.deadAfter, KeepMasters: tn.keepMasters, deadEvery: 50 * time.Millisecond,
		Gossip: ReplicatorConfig{
			RequestTimeout: 2 * time.Second, AntiEntropyEvery: time.Hour, HintsEvery: time.Hour, GCEvery: time.Hour,
		},
		tuneGossip: func(c *MembershipConfig) {
			c.ProbeInterval, c.ProbeTimeout = 100*time.Millisecond, 80*time.Millisecond
			c.GossipInterval, c.PushPullInterval, c.SuspicionMult = 20*time.Millisecond, time.Second, 2
			c.TCPTimeout, c.RefreshEvery = time.Second, 200*time.Millisecond
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	// The store lives in the data dir, as a hub's does: a restart keeps it.
	dbPath := filepath.Join(tn.dir, "hearth.db")
	if _, err := os.Stat(dbPath); errors.Is(err, os.ErrNotExist) {
		storetest.Migrated(t, dbPath)
	}
	st, err := store.Open(t.Context(), dbPath, append(node.StoreOptions(), tn.storeOpts...)...)
	if err != nil {
		t.Fatal(err)
	}
	if err := node.Bind(t.Context(), st); err != nil {
		t.Fatal(err)
	}
	pol := policy.NewWithConfig(st.Audit(), st.Approvals(), policy.Config{})
	srv.Config.Handler = func() http.Handler {
		m := http.NewServeMux()
		m.Handle(NewAPJoinServer(node, st, ca, pol, testLogger(t)).Handler())
		return m
	}()
	srv.StartTLS()
	node.cfg.AgentURL = srv.URL
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = node.Run(ctx); close(done) }()
	stopped := false
	tn.stop = func() {
		if stopped {
			return
		}
		stopped = true
		cancel()
		<-done
		_ = st.Close()
		srv.Close()
	}
	t.Cleanup(tn.stop)
	tn.ca, tn.node, tn.st, tn.addr, tn.srv = ca, node, st, ln.Addr().String(), srv
}

// issueTestServerCert issues a TLS certificate for 127.0.0.1 from the CA in
// dir; a member without the CA key borrows one issued by a test CA copy.
func issueTestServerCert(dir string) (tls.Certificate, error) {
	ca, err := pki.LoadCA(dir, time.Now())
	if err != nil {
		return tls.Certificate{}, err
	}
	if ca.HasKey() {
		return ca.IssueServerCert([]string{"127.0.0.1"}, time.Now())
	}
	// Only masters serve FetchCAKey; a member without the key serves with
	// a certificate no client trusts.
	other, err := pki.LoadOrCreateCA(filepath.Join(dir, "untrusted-ca"), time.Now())
	if err != nil {
		return tls.Certificate{}, err
	}
	return other.IssueServerCert([]string{"127.0.0.1"}, time.Now())
}

func (tn *apTestNode) memberOn(on *apTestNode) MemberInfo {
	for _, m := range on.node.Membership().Members() {
		if m.ID == tn.id {
			return m
		}
	}
	return MemberInfo{}
}

var (
	storageMaster = RolesOf(RoleStorage, RoleMaster)
	storageOnly   = RolesOf(RoleStorage)
	masterOnly    = RolesOf(RoleMaster)
)

// TestRoleChangeRefusals: each refusal of a promotion, demotion or removal.
func TestRoleChangeRefusals(t *testing.T) {
	ctx := t.Context()
	c := newAPTestCluster(t, 2,
		apSpec{"a", storageMaster, storageMaster},
		apSpec{"b", storageOnly, storageOnly}, // does not allow master
	)
	a, b := c["a"].node, c["b"].node
	if err := c["a"].st.Devices().Upsert(ctx, store.Device{
		ID: "pi", Name: "pi", Hostname: "pi", OS: "linux",
		Arch: "arm64", Facts: []byte(`{}`), FirstSeen: time.Now(), LastSeen: time.Now(), Status: store.StatusOnline,
	}); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		do   func() error
		want error
	}{
		{"promote unknown member", func() error { _, err := a.Promote(ctx, "nope", RoleStorage); return err }, ErrUnknownMember},
		{"promote an agent host", func() error { _, err := a.Promote(ctx, "pi", RoleStorage); return err }, ErrAgentHost},
		{"promote beyond --allow-roles", func() error { _, err := a.Promote(ctx, "b", RoleMaster); return err }, ErrRoleCeiling},
		{"promote to node", func() error { _, err := a.Promote(ctx, "b", RoleNode); return err }, ErrBadRole},
		{"promote to a role held", func() error { _, err := a.Promote(ctx, "b", RoleStorage); return err }, ErrNoChange},
		{"ask a member that is no master", func() error { _, err := b.Promote(ctx, "a", RoleStorage); return err }, ErrNotMasterHere},
		{"demote the last master", func() error { _, err := a.Demote(ctx, "a", RoleMaster); return err }, ErrLastMaster},
		{"demote a member's last role", func() error { _, err := a.Demote(ctx, "b", RoleStorage); return err }, ErrKeepsNoRole},
		{"remove itself", func() error { _, err := a.RemoveMember(ctx, "a"); return err }, ErrRemoveSelf},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.do(); !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if RoleErrorKind(tc.want) == "" {
				t.Fatalf("%v has no kind", tc.want)
			}
		})
	}
	// The ceiling holds on the member too, whoever asks.
	if _, err := b.applyRoleChange(ctx, roleRequest{Promote: true, Role: RoleMaster}); !errors.Is(err, ErrRoleCeiling) {
		t.Fatalf("b took master beyond its --allow-roles: %v", err)
	}
	if b.Roles() != storageOnly {
		t.Fatalf("b roles = %s", b.Roles())
	}
}

// TestDemoteLastStorageRefused: the last storage member is not demoted
// from storage, nor removed.
func TestDemoteLastStorageRefused(t *testing.T) {
	ctx := t.Context()
	c := newAPTestCluster(t, 1,
		apSpec{"a", storageMaster, storageMaster},
		apSpec{"b", masterOnly, storageMaster},
	)
	if _, err := c["b"].node.Demote(ctx, "a", RoleStorage); !errors.Is(err, ErrLastStorage) {
		t.Fatalf("demote the last storage member: %v, want ErrLastStorage", err)
	}
	if _, err := c["b"].node.RemoveMember(ctx, "a"); !errors.Is(err, ErrLastStorage) {
		t.Fatalf("remove the last storage member: %v, want ErrLastStorage", err)
	}
}

// TestPromoteToStorageSyncs: a master promoted to storage shows syncing
// until it holds its rows, then serves them; its roles survive a restart.
func TestPromoteToStorageSyncs(t *testing.T) {
	ctx := t.Context()
	c := newAPTestCluster(t, 2,
		apSpec{"a", storageMaster, storageMaster},
		apSpec{"b", storageMaster, storageMaster},
		apSpec{"c", masterOnly, storageMaster},
	)
	for i := range 30 {
		id := fmt.Sprintf("dev-%02d", i)
		if err := c["a"].st.Devices().Upsert(ctx, device(id, id)); err != nil {
			t.Fatal(err)
		}
	}
	got, err := c["a"].node.Promote(ctx, "c", RoleStorage)
	if err != nil {
		t.Fatal(err)
	}
	if got.State != RoleSyncing {
		t.Fatalf("state = %q, want syncing", got.State)
	}
	waitUntil(t, 10*time.Second, "c to be in sync", func() bool {
		m := c["c"].memberOn(c["a"])
		return m.Roles.Has(RoleStorage) && !m.Syncing
	})
	// Every row c owns is on c.
	ring := c["a"].node.Replicator().view().ring
	held := 0
	for i := range 30 {
		id := fmt.Sprintf("dev-%02d", i)
		owners := ring.Owners(store.BucketOf(store.Token(id)), 2)
		for _, o := range owners {
			if o != "c" {
				continue
			}
			held++
			rows, err := c["c"].st.ReadLocal(ctx, `SELECT 1 FROM devices WHERE id = ?`, store.Values{id})
			if err != nil {
				t.Fatal(err)
			}
			if len(rows.Vals) == 0 {
				t.Fatalf("c owns %s but lacks it after the catch-up", id)
			}
		}
	}
	if held == 0 {
		t.Fatal("c owns no device: the test needs some")
	}
	// The promotion is recorded: a restart keeps it.
	lr, err := LoadLocalRoles(c["c"].dir, storageMaster, testLogger(t))
	if err != nil {
		t.Fatal(err)
	}
	if lr.Roles != storageMaster || lr.Syncing {
		t.Fatalf("recorded roles = %+v, want storage and master, synced", lr)
	}
	c["c"].stop()
	c["c"].start(t, 2, c["a"].addr)
	if c["c"].node.Roles() != storageMaster {
		t.Fatalf("roles after a restart = %s", c["c"].node.Roles())
	}
}

// TestDemoteStorageDrains: a storage member demoted hands its rows off and
// leaves the ring once each has its copies on the others.
func TestDemoteStorageDrains(t *testing.T) {
	ctx := t.Context()
	c := newAPTestCluster(t, 2,
		apSpec{"a", storageMaster, storageMaster},
		apSpec{"b", storageMaster, storageMaster},
		apSpec{"c", storageMaster, storageMaster},
	)
	for i := range 30 {
		id := fmt.Sprintf("dev-%02d", i)
		if err := c["a"].st.Devices().Upsert(ctx, device(id, id)); err != nil {
			t.Fatal(err)
		}
	}
	holds := func(m, id string) bool {
		rows, err := c[m].st.ReadLocal(ctx, `SELECT 1 FROM devices WHERE id = ?`, store.Values{id})
		if err != nil {
			t.Fatal(err)
		}
		return len(rows.Vals) > 0
	}
	// A device write waits for its coordinator alone and reaches its
	// second replica (or a stand-in for one the gossip suspects) in the
	// background. c hands off the rows it holds, not writes still on their
	// way to it, so let every write have its two copies before the
	// demotion: a row c holds then goes to a and b, any other is on both.
	waitUntil(t, 10*time.Second, "every device on two members", func() bool {
		for i := range 30 {
			id, copies := fmt.Sprintf("dev-%02d", i), 0
			for _, m := range []string{"a", "b", "c"} {
				if holds(m, id) {
					copies++
				}
			}
			if copies < 2 {
				return false
			}
		}
		return true
	})
	got, err := c["a"].node.Demote(ctx, "c", RoleStorage)
	if err != nil {
		t.Fatal(err)
	}
	if got.State != RoleDraining {
		t.Fatalf("state = %q, want draining", got.State)
	}
	waitUntil(t, 10*time.Second, "c to leave storage", func() bool {
		return !c["c"].memberOn(c["a"]).Roles.Has(RoleStorage)
	})
	for i := range 30 {
		id := fmt.Sprintf("dev-%02d", i)
		for _, m := range []string{"a", "b"} {
			if !holds(m, id) {
				t.Fatalf("%s lacks %s after c's demotion", m, id)
			}
		}
	}
	if _, err := c["a"].st.Devices().Get(ctx, "dev-07"); err != nil {
		t.Fatalf("read after the demotion: %v", err)
	}
}

// TestDemoteMaster: a demoted master's tokens are spent, its pending
// approvals expired, and its CA key deleted; it serves agents no more.
func TestDemoteMaster(t *testing.T) {
	ctx := t.Context()
	c := newAPTestCluster(t, 2,
		apSpec{"a", storageMaster, storageMaster},
		apSpec{"b", storageMaster, storageMaster},
	)
	b := c["b"]
	if err := b.st.Tokens().Create(ctx, "enroll-secret", nil, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := b.st.JoinTokens().Create(ctx, "join-secret", time.Now().Add(time.Hour), "storage"); err != nil {
		t.Fatal(err)
	}
	if err := b.st.Approvals().Create(ctx, store.Approval{
		ID: "ap1", Action: "device.exec", Class: "dangerous", ActorKind: "mcp", ActorID: "x", Target: "pi",
		CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	changed, stop := b.node.RoleChanges()
	defer stop()
	if _, err := c["a"].node.Demote(ctx, "b", RoleMaster); err != nil {
		t.Fatal(err)
	}
	select {
	case <-changed:
	case <-time.After(5 * time.Second):
		t.Fatal("b's subscribers were not told it lost the master role")
	}
	if b.node.IsMaster() || b.node.IsLeader() {
		t.Fatal("b is still a master")
	}
	if _, err := os.Stat(filepath.Join(b.dir, pki.CAKeyFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("b's CA key file: %v, want gone", err)
	}
	if b.ca.HasKey() {
		t.Fatal("b still holds the CA key")
	}
	if _, err := b.st.Tokens().Consume(ctx, "enroll-secret", time.Now()); !errors.Is(err, store.ErrTokenUsed) {
		t.Fatalf("b's enrollment token: %v, want spent", err)
	}
	if _, err := c["a"].st.JoinTokens().Consume(ctx, "join-secret", time.Now()); err == nil {
		t.Fatal("b's join token is still usable")
	}
	ap, err := c["a"].st.Approvals().Get(ctx, "ap1")
	if err != nil {
		t.Fatal(err)
	}
	if ap.Status != store.ApprovalExpired || ap.DecidedBy != demotedBy {
		t.Fatalf("b's approval = %s by %q, want expired by %q", ap.Status, ap.DecidedBy, demotedBy)
	}
	waitUntil(t, 5*time.Second, "a to see b demoted", func() bool {
		return !c["b"].memberOn(c["a"]).Roles.Has(RoleMaster)
	})
	for _, m := range []*apTestNode{c["a"], b} {
		if err := m.st.Hubs().SetAgentURL(ctx, m.id, m.node.cfg.AgentURL); err != nil {
			t.Fatal(err)
		}
	}
	// a's URL reaches b's copy of the global rows in the background.
	var urls []string
	waitUntil(t, 5*time.Second, "b to send agents to a", func() bool {
		urls = b.node.AgentURLs()
		return len(urls) > 0
	})
	if len(urls) != 1 || urls[0] != c["a"].node.cfg.AgentURL {
		t.Fatalf("b sends agents to %v, want a first", urls)
	}
	// The demotion survives a restart, and b does not fetch the key back.
	b.stop()
	b.start(t, 2, c["a"].addr)
	if b.node.IsMaster() {
		t.Fatal("b is a master again after a restart")
	}
}

// TestPromoteToMasterFetchesTheKey: a storage member promoted to master
// fetches the CA key from the master promoting it, over the pinned TLS
// ClusterService; without a promotion under way the key is refused.
func TestPromoteToMasterFetchesTheKey(t *testing.T) {
	ctx := t.Context()
	c := newAPTestCluster(t, 2,
		apSpec{"a", storageMaster, storageMaster},
		apSpec{"b", storageOnly, storageMaster},
	)
	b := c["b"]
	if b.ca.HasKey() {
		t.Fatal("b holds the CA key before its promotion")
	}
	// No promotion under way: refused, and audited.
	_, err := b.node.fetchCAKey(ctx, c["a"].node.cfg.AgentURL)
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("fetch without a promotion: %v, want permission denied", err)
	}
	if _, err := c["a"].node.Promote(ctx, "b", RoleMaster); err != nil {
		t.Fatal(err)
	}
	if !b.node.IsMaster() || !b.ca.HasKey() {
		t.Fatal("b is not a master holding the key")
	}
	if _, err := os.Stat(filepath.Join(b.dir, pki.CAKeyFile)); err != nil {
		t.Fatalf("b's CA key file: %v", err)
	}
	// The grant was used: a second fetch is refused.
	if _, err := b.node.fetchCAKey(ctx, c["a"].node.cfg.AgentURL); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("second fetch: %v, want permission denied", err)
	}
	entries, err := c["a"].st.Audit().Query(ctx, store.AuditFilter{Actions: []string{string(policy.ClusterCAFetchKey)}}, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) < 3 {
		t.Fatalf("audit of the key fetches: %+v; want each of the three", entries)
	}
}

// TestRemoveMember: a removed member is revoked and leaves every listing at
// once, not at the next restart.
func TestRemoveMember(t *testing.T) {
	ctx := t.Context()
	c := newAPTestCluster(t, 2,
		apSpec{"a", storageMaster, storageMaster},
		apSpec{"b", storageMaster, storageMaster},
		apSpec{"c", storageMaster, storageMaster},
	)
	c["c"].stop()
	waitUntil(t, 10*time.Second, "a to see c down", func() bool {
		s := c["c"].memberOn(c["a"]).State
		return s == MemberDead || s == MemberLeft
	})
	got, err := c["a"].node.RemoveMember(ctx, "c")
	if err != nil {
		t.Fatal(err)
	}
	if got.Revoked == 0 {
		t.Fatal("no certificate revoked")
	}
	certs, err := c["b"].st.Hubs().Certs(ctx, "c")
	if err != nil {
		t.Fatal(err)
	}
	for _, cert := range certs {
		if !cert.Revoked {
			t.Fatalf("c's certificate %s not revoked", cert.Serial)
		}
	}
	for _, on := range []string{"a", "b"} {
		waitUntil(t, 5*time.Second, on+" to forget c", func() bool {
			return c["c"].memberOn(c[on]).ID == ""
		})
	}
}

// TestDemoteLastLiveMaster: a dead master is no reason to let the last live
// one go: its CA key would be the cluster's last.
func TestDemoteLastLiveMaster(t *testing.T) {
	ctx := t.Context()
	c := newAPTestCluster(t, 2,
		apSpec{"a", storageMaster, storageMaster},
		apSpec{"b", storageMaster, storageMaster},
	)
	c["b"].stop()
	waitUntil(t, 10*time.Second, "a to see b dead", func() bool {
		s := c["b"].memberOn(c["a"]).State
		return s == MemberDead || s == MemberLeft
	})
	if _, err := c["a"].node.Demote(ctx, "a", RoleMaster); !errors.Is(err, ErrLastMaster) {
		t.Fatalf("demote the last live master: %v, want ErrLastMaster", err)
	}
	// The member refuses it itself too, whoever asks.
	if _, err := c["a"].node.applyRoleChange(ctx, roleRequest{Role: RoleMaster}); !errors.Is(err, ErrLastMaster) {
		t.Fatalf("the last live master demoted itself: %v", err)
	}
	if !c["a"].ca.HasKey() {
		t.Fatal("a lost the CA key")
	}
}
