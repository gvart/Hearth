// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/memberlist"

	"github.com/gvart/hearth/internal/pki"
)

type memberOpts struct {
	cert  tls.Certificate
	check func(*x509.Certificate) error
	seeds []string
	roles RoleSet
	// claim, if set, is the gossip name, instead of the certificate's ID.
	claim string
}

func (o memberOpts) name(id string) string {
	if o.claim != "" {
		return o.claim
	}
	return id
}

// newTestMember returns a Membership on a loopback port with fast probes.
func newTestMember(t *testing.T, ca *pki.CA, id string, o memberOpts) *Membership {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if o.cert.Certificate == nil {
		o.cert = hubCert(t, ca, id)
	}
	if o.roles == 0 {
		o.roles = HubRoles
	}
	seeds := o.seeds
	m, err := NewMembership(MembershipConfig{
		NodeID: o.name(id), Roles: o.roles, Allowed: RolesOf(RoleNode, RoleStorage, RoleMaster),
		Listen: ln.Addr().String(), Listener: ln,
		Seeds:        func() []string { return seeds },
		Schema:       func(context.Context) (int64, error) { return 42, nil },
		ConfigDigest: func() string { return "digest-" + id },
		CA:           ca, Cert: func() *tls.Certificate { return &o.cert }, Check: o.check,
		ProbeInterval: 100 * time.Millisecond, ProbeTimeout: 80 * time.Millisecond,
		GossipInterval: 20 * time.Millisecond, PushPullInterval: time.Second, SuspicionMult: 2,
		TCPTimeout: time.Second, RefreshEvery: 200 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// runMember runs m until the returned stop is called (or the test ends).
func runMember(t *testing.T, m *Membership) (addr string, stop func()) {
	t.Helper()
	addr = m.cfg.Listener.Addr().String()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- m.Run(ctx) }()
	stopped := false
	stop = func() {
		if stopped {
			return
		}
		stopped = true
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Run: %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Errorf("membership %s did not stop", m.cfg.NodeID)
		}
	}
	t.Cleanup(stop)
	waitUntil(t, 5*time.Second, "membership to start", func() bool { return m.ml.Load() != nil })
	return addr, stop
}

func waitUntil(t *testing.T, d time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// states maps member IDs to their states as m sees them.
func states(m *Membership) map[string]string {
	out := map[string]string{}
	for _, mi := range m.Members() {
		out[mi.ID] = mi.State
	}
	return out
}

func sees(m *Membership, want map[string]string) func() bool {
	return func() bool {
		got := states(m)
		if len(got) != len(want) {
			return false
		}
		for id, s := range want {
			if got[id] != s {
				return false
			}
		}
		return true
	}
}

// TestMembershipJoinLeaveFail runs three members: they find each other with
// their metadata, a member that leaves shows as left and one that crashes as
// dead.
func TestMembershipJoinLeaveFail(t *testing.T) {
	ca := newTestCA(t)
	a := newTestMember(t, ca, "a", memberOpts{})
	aAddr, _ := runMember(t, a)
	// b runs without Run's loop, so it can crash below.
	b := newTestMember(t, ca, "b", memberOpts{seeds: []string{aAddr}})
	bML, err := b.start(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = bML.Shutdown() })
	c := newTestMember(t, ca, "c", memberOpts{seeds: []string{aAddr}, roles: RolesOf(RoleStorage)})
	_, stopC := runMember(t, c)

	all := map[string]string{"a": MemberAlive, "b": MemberAlive, "c": MemberAlive}
	for _, m := range []*Membership{a, b, c} {
		waitUntil(t, 10*time.Second, m.cfg.NodeID+" to see all three alive", sees(m, all))
	}
	for _, mi := range b.Members() {
		wantRoles := HubRoles
		if mi.ID == "c" {
			wantRoles = RolesOf(RoleStorage)
		}
		if mi.Roles != wantRoles || mi.AllowedRoles != RolesOf(RoleNode, RoleStorage, RoleMaster) ||
			mi.Schema != 42 || mi.ConfigDigest != "digest-"+mi.ID || mi.ClockMS == 0 || mi.Address == "" {
			t.Errorf("b sees member %+v", mi)
		}
	}

	stopC()
	left := map[string]string{"a": MemberAlive, "b": MemberAlive, "c": MemberLeft}
	waitUntil(t, 10*time.Second, "a to see c left", sees(a, left))
	waitUntil(t, 10*time.Second, "b to see c left", sees(b, left))

	// b crashes: no leave, its connections just stop.
	if err := bML.Shutdown(); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, 15*time.Second, "a to see b dead",
		sees(a, map[string]string{"a": MemberAlive, "b": MemberDead, "c": MemberLeft}))
}

// TestMembershipRefusesNonHubPeers checks that a peer cannot join the gossip
// with a device certificate, a hub certificate of another CA, or a revoked
// hub certificate, and that none of them can make a member join it.
func TestMembershipRefusesNonHubPeers(t *testing.T) {
	ca := newTestCA(t)
	revoked := hubCert(t, ca, "revoked")
	errRevoked := errors.New("revoked")
	check := func(c *x509.Certificate) error {
		if c.SerialNumber.Cmp(revoked.Leaf.SerialNumber) == 0 {
			return errRevoked
		}
		return nil
	}
	a := newTestMember(t, ca, "a", memberOpts{check: check})
	aAddr, _ := runMember(t, a)

	for _, tc := range []struct {
		name string
		ca   *pki.CA
		cert tls.Certificate
	}{
		{name: "device", ca: ca, cert: deviceCert(t, ca)},
		{name: "other-ca", ca: newTestCA(t), cert: tls.Certificate{}},
		{name: "revoked", ca: ca, cert: revoked},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cert := tc.cert
			if cert.Certificate == nil {
				cert = hubCert(t, tc.ca, tc.name)
			}
			x := newTestMember(t, tc.ca, tc.name, memberOpts{cert: cert, seeds: []string{aAddr}})
			xAddr, _ := runMember(t, x)
			// a dials x too, so both directions are refused.
			if _, err := a.ml.Load().Join([]string{xAddr}); err == nil {
				t.Errorf("a joined %s", tc.name)
			}
			time.Sleep(time.Second) // several refresh rounds of x joining a
			if got := states(a); len(got) != 1 {
				t.Errorf("a sees %v, want only itself", got)
			}
			if got := states(x); len(got) != 1 {
				t.Errorf("%s sees %v, want only itself", tc.name, got)
			}
		})
	}
}

// TestMembershipBindsNamesToCertificates: a hub with a valid certificate
// cannot join, or be added by others, under another hub's name.
func TestMembershipBindsNamesToCertificates(t *testing.T) {
	ca := newTestCA(t)
	a := newTestMember(t, ca, "a", memberOpts{})
	aAddr, _ := runMember(t, a)
	b := newTestMember(t, ca, "b", memberOpts{seeds: []string{aAddr}})
	bAddr, _ := runMember(t, b)
	both := map[string]string{"a": MemberAlive, "b": MemberAlive}
	waitUntil(t, 10*time.Second, "a and b to see each other", sees(a, both))
	waitUntil(t, 10*time.Second, "b to see a", sees(b, both))

	for _, claim := range []string{"b", "c"} { // an existing member's name, and a new one
		t.Run(claim, func(t *testing.T) {
			// The certificate says "evil".
			x := newTestMember(t, ca, "evil", memberOpts{claim: claim, seeds: []string{aAddr}})
			xAddr, _ := runMember(t, x)
			if _, err := a.ml.Load().Join([]string{xAddr}); err == nil {
				t.Errorf("a joined the hub claiming %s", claim)
			}
			time.Sleep(time.Second) // several refresh rounds of x joining a
			for _, m := range []*Membership{a, b} {
				for _, mi := range m.Members() {
					if mi.Address == xAddr || mi.ID == "c" || mi.ID == "evil" {
						t.Errorf("%s lists %+v", m.cfg.NodeID, mi)
					}
					if mi.ID == "b" && (mi.Address != bAddr || mi.State != MemberAlive) {
						t.Errorf("%s lists b as %+v, want alive at %s", m.cfg.NodeID, mi, bAddr)
					}
				}
			}
		})
	}
}

func TestNewMembershipRefuses(t *testing.T) {
	ca := newTestCA(t)
	cert := hubCert(t, ca, "a")
	base := MembershipConfig{
		NodeID: "a", Roles: HubRoles, Allowed: HubRoles, Listen: "127.0.0.1:0",
		CA: ca, Cert: func() *tls.Certificate { return &cert },
	}
	for _, tc := range []struct {
		name    string
		mod     func(*MembershipConfig)
		wantErr string
	}{
		{name: "role not allowed", mod: func(c *MembershipConfig) { c.Allowed = RolesOf(RoleStorage) }, wantErr: "role master not allowed"},
		{name: "nothing allowed", mod: func(c *MembershipConfig) { c.Allowed = 0 }, wantErr: "not allowed"},
		{name: "node only", mod: func(c *MembershipConfig) { c.Roles, c.Allowed = AgentRoles, AgentRoles }, wantErr: "only storage and master"},
		{name: "bad node id", mod: func(c *MembershipConfig) { c.NodeID = "A B" }, wantErr: "invalid node ID"},
		{name: "no listen", mod: func(c *MembershipConfig) { c.Listen = "" }, wantErr: "no listen"},
		{name: "no cert", mod: func(c *MembershipConfig) { c.Cert = nil }, wantErr: "no CA or certificate"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base
			tc.mod(&cfg)
			if _, err := NewMembership(cfg); err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("NewMembership = %v, want %q", err, tc.wantErr)
			}
		})
	}
	if _, err := NewMembership(base); err != nil {
		t.Fatalf("NewMembership(valid) = %v", err)
	}
}

func TestNotifyAliveRefusesBadMetadata(t *testing.T) {
	m := &Membership{cfg: MembershipConfig{NodeID: "a"}}
	// The owners as dials would have recorded them: b answers at .2, the
	// hub x at .3; .4 has not been dialed. closed keeps verifyLater from
	// dialing.
	m.trans.Store(&gossipTransport{
		ip: net.ParseIP("10.0.0.1"), port: 7445, closed: true,
		owners:    map[string]string{"10.0.0.2:7445": "b", "10.0.0.3:7445": "x"},
		verifying: map[string]bool{}, verifyTried: map[string]time.Time{},
	})
	at := func(n memberlist.Node, ip string) memberlist.Node {
		n.Addr, n.Port = net.ParseIP(ip), 7445
		return n
	}
	hub := memberlist.Node{Name: "b", Meta: nil}
	meta := func(mm memberMeta) []byte {
		b, err := json.Marshal(mm)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	for _, tc := range []struct {
		name string
		node memberlist.Node
		ok   bool
	}{
		{name: "self", node: at(memberlist.Node{Name: "a"}, "10.0.0.1"), ok: true},
		{name: "self elsewhere", node: at(memberlist.Node{Name: "a"}, "10.0.0.3")},
		{name: "hub", node: at(withMeta(hub, meta(memberMeta{Roles: HubRoles, Allowed: HubRoles})), "10.0.0.2"), ok: true},
		{name: "storage only", node: at(memberlist.Node{Name: "b", Meta: meta(memberMeta{Roles: RolesOf(RoleStorage), Allowed: HubRoles})}, "10.0.0.2"), ok: true},
		{name: "another hub's name", node: at(withMeta(hub, meta(memberMeta{Roles: HubRoles, Allowed: HubRoles})), "10.0.0.3")},
		{name: "address not verified", node: at(withMeta(hub, meta(memberMeta{Roles: HubRoles, Allowed: HubRoles})), "10.0.0.4")},
		{name: "role outside allowed", node: memberlist.Node{Name: "b", Meta: meta(memberMeta{Roles: HubRoles, Allowed: RolesOf(RoleStorage)})}},
		{name: "node only", node: memberlist.Node{Name: "b", Meta: meta(memberMeta{Roles: AgentRoles, Allowed: AgentRoles})}},
		{name: "unknown role", node: memberlist.Node{Name: "b", Meta: []byte(`{"r":["root"],"a":["root"]}`)}},
		{name: "no metadata", node: memberlist.Node{Name: "b"}},
		{name: "bad name", node: memberlist.Node{Name: "../b", Meta: meta(memberMeta{Roles: HubRoles, Allowed: HubRoles})}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := m.NotifyAlive(&tc.node)
			if (err == nil) != tc.ok {
				t.Fatalf("NotifyAlive = %v, want ok %v", err, tc.ok)
			}
		})
	}
}

func withMeta(n memberlist.Node, meta []byte) memberlist.Node {
	n.Meta = meta
	return n
}

// TestMemberMetaFits checks the largest metadata fits memberlist's limit.
func TestMemberMetaFits(t *testing.T) {
	all := RolesOf(RoleNode, RoleStorage, RoleMaster)
	m := &Membership{cfg: MembershipConfig{
		Roles: all, Allowed: all,
		Schema:       func(context.Context) (int64, error) { return 1<<63 - 1, nil },
		ConfigDigest: func() string { return digestOf(map[string]string{ConfigPolicy: strings.Repeat("f", 64)}) },
	}}
	if err := m.setMeta(t.Context(), true); err != nil {
		t.Fatal(err)
	}
	if n := len(*m.meta.Load()); n > memberlist.MetaMaxSize/2 {
		t.Fatalf("metadata is %d bytes; keep it well under %d", n, memberlist.MetaMaxSize)
	}
}

func TestResolveAdvertise(t *testing.T) {
	for _, tc := range []struct {
		in, want, wantErr string
	}{
		{in: "127.0.0.1:7445", want: "127.0.0.1"},
		{in: "10.0.0.5:7445", want: "10.0.0.5"},
		{in: "localhost:7445", wantErr: "only to loopback"},
		{in: "0.0.0.0:7445", wantErr: "other members can dial"},
		{in: "no-port", wantErr: "missing port"},
	} {
		ip, port, err := resolveAdvertise(t.Context(), tc.in)
		if tc.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("resolveAdvertise(%q) = %v, %d, %v; want %q", tc.in, ip, port, err, tc.wantErr)
			}
			continue
		}
		if err != nil || ip.String() != tc.want || port != 7445 {
			t.Errorf("resolveAdvertise(%q) = %v, %d, %v; want %s", tc.in, ip, port, err, tc.want)
		}
	}
}

func TestDigestOf(t *testing.T) {
	a := digestOf(map[string]string{"policy": "1", "notify": "2"})
	if a == "" || a != digestOf(map[string]string{"notify": "2", "policy": "1"}) {
		t.Fatal("digest depends on map order")
	}
	if a == digestOf(map[string]string{"policy": "1", "notify": "3"}) {
		t.Fatal("digest ignores a value")
	}
	if digestOf(nil) != "" {
		t.Fatal("no digests should digest to empty")
	}
}
