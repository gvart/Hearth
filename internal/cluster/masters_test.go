// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import (
	"cmp"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/gvart/hearth/internal/pki"
	"github.com/gvart/hearth/internal/policy"
	clusterv1 "github.com/gvart/hearth/internal/proto/hearth/cluster/v1"
	"github.com/gvart/hearth/internal/store"
)

// fakeMembers is a gossip view a test changes.
type fakeMembers struct {
	mu sync.Mutex
	m  []MemberInfo
}

func (f *fakeMembers) Members() []MemberInfo {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]MemberInfo(nil), f.m...)
}

func (f *fakeMembers) set(id string, state string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := range f.m {
		if f.m[i].ID == id {
			f.m[i].State = state
		}
	}
}

// TestOwnershipMovesWhenAMasterDies: a key owned by master b moves to a live
// master when b dies, the change is signalled and dated, and a singleton
// keyed on it follows; storage-only members never own anything.
func TestOwnershipMovesWhenAMasterDies(t *testing.T) {
	now := time.Unix(1000, 0)
	clock := func() time.Time { return now }
	fm := &fakeMembers{m: []MemberInfo{
		{ID: "a", Roles: HubRoles, State: MemberAlive},
		{ID: "b", Roles: HubRoles, State: MemberAlive},
		{ID: "c", Roles: HubRoles, State: MemberAlive},
		{ID: "s", Roles: RolesOf(RoleStorage), State: MemberAlive},
	}}
	ring := NewMasterRing("a", fm.Members, clock)
	if got := ring.Masters(); len(got) != 3 {
		t.Fatalf("masters = %v, want a, b, c", got)
	}
	var key string
	for _, k := range []string{"k0", "k1", "k2", "k3", "k4", "k5", "k6", "k7", "k8", "k9", "k10", "k11"} {
		if ring.Owner(k) == "b" {
			key = k
			break
		}
	}
	if key == "" {
		t.Fatal("no key owned by b")
	}
	single := ring.Singleton(key, nil)
	if ring.Owns(key) || single.IsLeader() {
		t.Fatal("a owns b's key")
	}
	changed, unsubscribe := ring.Subscribe()
	defer unsubscribe()

	now = now.Add(time.Minute)
	fm.set("b", MemberDead)
	ring.refresh()
	select {
	case <-changed:
	default:
		t.Error("no change signalled when b died")
	}
	if ring.Live("b") || ring.Owner(key) == "b" || ring.Owner(key) == "s" {
		t.Errorf("after b died: live b = %v, owner = %s", ring.Live("b"), ring.Owner(key))
	}
	if !ring.Since().Equal(now) {
		t.Errorf("since = %v, want %v", ring.Since(), now)
	}
	if ring.Owns(key) != single.IsLeader() {
		t.Error("the singleton does not follow the ring")
	}
	// Suspect still counts as live: no move on a missed probe.
	fm.set("b", MemberSuspect)
	ring.refresh()
	if ring.Owner(key) != "b" {
		t.Errorf("owner with b suspect = %s, want b", ring.Owner(key))
	}
}

// TestIsolation: a master that heard from no other member for 59 s is not
// isolated, for 60 s it is, and it recovers on contact; a member alone in
// its cluster never is.
func TestIsolation(t *testing.T) {
	start := time.Unix(1000, 0)
	now, last, others := start, start, true
	iso := Isolation{
		LastContact: func() time.Time { return last },
		Others:      func() bool { return others },
		Now:         func() time.Time { return now },
		Bound:       IsolationBound,
	}
	now = start.Add(59 * time.Second)
	if iso.Isolated() {
		t.Error("isolated after 59 s")
	}
	now = start.Add(60 * time.Second)
	if !iso.Isolated() {
		t.Error("not isolated after 60 s")
	}
	last = now
	if iso.Isolated() {
		t.Error("still isolated after a contact")
	}
	now, others = now.Add(time.Hour), false
	if iso.Isolated() {
		t.Error("a single-member cluster is isolated")
	}
}

// TestOwnedTokenSingleUseAcrossASplit: a token master a created and
// consumed on its side of a split is refused on the other side, naming a,
// though that side holds a quorum of unused copies; and a's own record
// refuses a second use when no replica answers.
func TestOwnedTokenSingleUseAcrossASplit(t *testing.T) {
	ctx := t.Context()
	an := newAPNet(t, 4, "a", "b", "c", "d")
	exp := time.Now().Add(time.Hour)
	if err := an.m("a").st.Tokens().Create(ctx, "tok", nil, exp); err != nil {
		t.Fatal(err)
	}
	an.split([]string{"a", "b"}, []string{"c", "d"}, true)
	if _, err := an.m("a").st.Tokens().Consume(ctx, "tok", time.Now()); err != nil {
		t.Fatalf("consume on a = %v", err)
	}
	_, err := an.m("c").st.Tokens().Consume(ctx, "tok", time.Now())
	if !errors.Is(err, store.ErrNotOwner) || store.OwnerOf(err) != "a" {
		t.Fatalf("consume on c during the split = %v, want ErrNotOwner naming a", err)
	}
	an.split([]string{"a", "b"}, []string{"c", "d"}, false)

	// A second token, used once by a; then its replicas go away.
	if err := an.m("a").st.Tokens().Create(ctx, "tok2", nil, exp); err != nil {
		t.Fatal(err)
	}
	if _, err := an.m("a").st.Tokens().Consume(ctx, "tok2", time.Now()); err != nil {
		t.Fatalf("consume tok2 on a = %v", err)
	}
	for _, id := range []string{"b", "c", "d"} {
		an.setDown(id, true)
	}
	if _, err := an.m("a").st.Tokens().Consume(ctx, "tok2", time.Now()); !errors.Is(err, store.ErrTokenUsed) {
		t.Fatalf("second consume on a with no replica = %v, want ErrTokenUsed", err)
	}
}

// TestApprovalDecidedOnlyByItsOwner: master b cannot approve master a's
// approval; a can.
func TestApprovalDecidedOnlyByItsOwner(t *testing.T) {
	ctx := t.Context()
	an := newAPNet(t, 2, "a", "b")
	now := time.Now()
	if err := an.m("a").st.Approvals().Create(ctx, store.Approval{
		ID: "ap-1", CreatedAt: now, ExpiresAt: now.Add(time.Hour), ActorKind: "web", ActorID: "x",
		Action: "kube.node.drain", Class: "dangerous", Target: "lab/pi",
	}); err != nil {
		t.Fatal(err)
	}
	err := an.m("b").st.Approvals().Decide(ctx, "ap-1", store.ApprovalApproved, "web:x", now)
	if !errors.Is(err, store.ErrNotOwner) || store.OwnerOf(err) != "a" {
		t.Fatalf("approve on b = %v, want ErrNotOwner naming a", err)
	}
	if err := an.m("a").st.Approvals().Decide(ctx, "ap-1", store.ApprovalApproved, "web:x", now); err != nil {
		t.Fatalf("approve on a = %v", err)
	}
}

// TestRevocationBroadcastSkipsAntiEntropy: a revocation written while one
// of the device's replicas could not take it reaches that replica from the
// gossip broadcast at once, with no hint delivery or anti-entropy run.
func TestRevocationBroadcastSkipsAntiEntropy(t *testing.T) {
	ctx := t.Context()
	ids := []string{"a", "b", "c"}
	an := newAPNet(t, 2, ids...)
	var (
		mu   sync.Mutex
		msgs [][]byte
	)
	an.m("a").rep.cfg.Broadcast = func(b []byte) {
		mu.Lock()
		defer mu.Unlock()
		msgs = append(msgs, b)
	}
	dev := keyOwnedBy(t, ids, 2, "dev", "a", "b")
	if err := an.m("a").st.Devices().Upsert(ctx, device(dev, "pi")); err != nil {
		t.Fatal(err)
	}
	if err := an.m("a").st.Certs().Create(ctx, "serial-1", dev); err != nil {
		t.Fatal(err)
	}
	revoked := func(m *apMember) bool {
		rows, err := m.st.ReadLocal(ctx, `SELECT count(*) FROM certs WHERE serial = 'serial-1' AND revoked_at IS NOT NULL`, nil)
		if err != nil {
			t.Fatal(err)
		}
		n, _ := rows.Vals[0][0].(int64)
		return n == 1
	}
	// a cannot reach b (the write leaves b a hint, delivered hourly); b
	// still reaches a.
	an.mu.Lock()
	an.cut[[2]string{"a", "b"}] = true
	an.mu.Unlock()
	an.dropConns()
	if _, err := an.m("a").st.Certs().RevokeDevice(ctx, dev, time.Now()); err != nil {
		t.Fatal(err)
	}
	if revoked(an.m("b")) {
		t.Fatal("b got the revocation by replication; the test needs it withheld")
	}
	mu.Lock()
	got := append([][]byte(nil), msgs...)
	mu.Unlock()
	if len(got) == 0 {
		t.Fatal("the revocation was not broadcast")
	}
	for _, b := range got {
		an.m("b").rep.HandleMessage(b)
	}
	apEventually(t, "b to apply the broadcast revocation", func() bool { return revoked(an.m("b")) })
}

// TestAgentURLsReachEveryMaster: the agent URL each master records reaches
// the others, which list it to agents after their own.
func TestAgentURLsReachEveryMaster(t *testing.T) {
	ctx := t.Context()
	ids := []string{"a", "b", "c"}
	an := newAPNet(t, 2, ids...)
	for _, id := range ids {
		if err := an.m(id).st.Hubs().SetAgentURL(ctx, id, "https://"+id+":7443"); err != nil {
			t.Fatal(err)
		}
	}
	fm := &fakeMembers{}
	for _, id := range ids {
		fm.m = append(fm.m, MemberInfo{ID: id, Roles: HubRoles, State: MemberAlive})
	}
	node := &APNode{
		cfg: APConfig{NodeID: "b", AgentURL: "https://b:7443"}, st: an.m("b").st, log: testLogger(t),
		masters: NewMasterRing("b", fm.Members, nil),
	}
	node.setRoles(HubRoles)
	apEventually(t, "b to list every master's agent URL", func() bool {
		got := node.AgentURLs()
		return len(got) == 3 && got[0] == "https://b:7443"
	})
	if u := node.AgentURLOf(ctx, "c"); u != "https://c:7443" {
		t.Errorf("AgentURLOf(c) = %q", u)
	}
	fm.set("c", MemberDead)
	node.masters.refresh()
	if got := node.AgentURLs(); len(got) != 2 {
		t.Errorf("agent URLs with c dead = %v", got)
	}
}

// TestCAKeyOnlyToMasters: the AP join service grants a hub the roles both
// its join token and its host allow, and hands the CA key only to one
// granted master: never through a token without master, whatever the hub
// asks for.
func TestCAKeyOnlyToMasters(t *testing.T) {
	ctx := t.Context()
	an := newAPNet(t, 1, "a")
	m := an.m("a")
	ca := newTestCA(t)
	node := &APNode{cfg: APConfig{NodeID: "a"}, rep: m.rep, st: m.st, log: testLogger(t)}
	srv := NewAPJoinServer(node, m.st, ca, policy.New(m.st.Audit()), testLogger(t))
	schema, err := m.st.SchemaVersion(ctx)
	if err != nil {
		t.Fatal(err)
	}
	join := func(id, secret string, roles ...string) (*clusterv1.JoinResponse, error) {
		t.Helper()
		key, err := pki.NewKey()
		if err != nil {
			t.Fatal(err)
		}
		csr, err := pki.NewCSR(key, id)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := srv.Join(ctx, connect.NewRequest(&clusterv1.JoinRequest{
			TokenSecret: secret, NodeId: id, Csr: csr, Address: id + ":7946", SchemaVersion: schema,
			AllowedRoles: roles,
		}))
		if err != nil {
			return nil, err
		}
		return resp.Msg, nil
	}
	for i, tc := range []struct {
		name, token string
		allowed     []string
		want        string // granted roles; "" for a refusal
	}{
		{"storage token, joiner asks for master", "storage", []string{"storage", "master"}, "storage"},
		{"storage token, joiner asks for master only", "storage", []string{"master"}, ""},
		{"master token, storage-only host", "storage,master", []string{"storage"}, "storage"},
		{"master token, joiner names no roles", "storage,master", nil, ""},
		{"master token, master and storage host", "storage,master", []string{"storage", "master"}, "storage,master"},
		{"master-only token", "master", []string{"storage", "master"}, "master"},
		{"token with unparsable roles", "root", []string{"storage", "master"}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			id, secret := fmt.Sprintf("hub-%d", i), fmt.Sprintf("j%d", i)
			if err := m.st.JoinTokens().Create(ctx, secret, time.Now().Add(time.Hour), tc.token); err != nil {
				t.Fatal(err)
			}
			r, err := join(id, secret, tc.allowed...)
			if tc.want == "" {
				if connect.CodeOf(err) != connect.CodeFailedPrecondition || !strings.Contains(err.Error(), "no role") {
					t.Fatalf("join = %v, want refused: no role", err)
				}
			} else if err != nil {
				t.Fatalf("join: %v", err)
			}
			if got := strings.Join(r.GetRoles(), ","); got != tc.want {
				t.Fatalf("granted %q, want %q", got, tc.want)
			}
			master := strings.Contains(tc.want, "master")
			if gotKey := len(r.GetCaKey()) != 0; gotKey != master {
				t.Fatalf("CA key sent = %v, want %v", gotKey, master)
			}
			// Spent either way: the refusal used the token up.
			if _, err := m.st.JoinTokens().Consume(ctx, secret, time.Now()); !errors.Is(err, store.ErrTokenUsed) {
				t.Fatalf("token after join: %v, want spent", err)
			}
			entries, err := m.st.Audit().Query(ctx, store.AuditFilter{Actions: []string{string(policy.ClusterJoin)}, Targets: []string{id}}, 10)
			if err != nil {
				t.Fatal(err)
			}
			wantGranted := cmp.Or(tc.want, "none")
			if len(entries) == 0 || !strings.Contains(string(entries[0].Detail), `"granted_roles":"`+wantGranted+`"`) ||
				!strings.Contains(string(entries[0].Detail), `"token_roles":"`+tc.token+`"`) {
				t.Fatalf("audit = %+v, want token roles %s and granted %s", entries, tc.token, wantGranted)
			}
			if failed := strings.HasPrefix(entries[0].Result, "error"); failed != (tc.want == "") {
				t.Fatalf("audit result %q, refused %v", entries[0].Result, tc.want == "")
			}
		})
	}

	// Spent, expired or unknown tokens are refused before any role is granted.
	if err := m.st.JoinTokens().Create(ctx, "expired", time.Now().Add(-time.Minute), "storage,master"); err != nil {
		t.Fatal(err)
	}
	for secret, want := range map[string]string{"j0": "already used", "expired": "expired", "unknown": "unknown join token"} {
		r, err := join("late-"+secret, secret, "storage", "master")
		if connect.CodeOf(err) != connect.CodeUnauthenticated || !strings.Contains(err.Error(), want) || r != nil {
			t.Errorf("join with %s token = %v, want unauthenticated: %s", secret, err, want)
		}
	}
}
