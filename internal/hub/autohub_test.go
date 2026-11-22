// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"context"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/gvart/hearth/internal/pki"
	"github.com/gvart/hearth/internal/policy"
	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
	"github.com/gvart/hearth/internal/store"
)

// autoHubMasters is the AP cluster an Enroller sees: this master, hub-a, and
// the counts of its members.
type autoHubMasters struct{ masters, storage int }

func (autoHubMasters) Self() string                               { return "hub-a" }
func (autoHubMasters) Live(string) bool                           { return true }
func (autoHubMasters) AgentURLOf(context.Context, string) string  { return "https://192.0.2.10:7443" }
func (autoHubMasters) Client() *http.Client                       { return http.DefaultClient }
func (autoHubMasters) OwnerOf(string) string                      { return "hub-a" }
func (m *autoHubMasters) HubCounts(string) (masters, storage int) { return m.masters, m.storage }

type autoHubFixture struct {
	st  *store.Store
	ca  *pki.CA
	e   *Enroller
	m   *autoHubMasters
	pol *policy.Engine
}

func newAutoHubFixture(t *testing.T, masters, storage int) *autoHubFixture {
	t.Helper()
	st := newTestStore(t)
	ca, err := pki.LoadOrCreateCA(t.TempDir(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	pol := policy.New(st.Audit())
	e := NewEnroller(st, ca, pol, slog.New(slog.DiscardHandler))
	m := &autoHubMasters{masters: masters, storage: storage}
	e.masters, e.hubs = m, m
	return &autoHubFixture{st: st, ca: ca, e: e, m: m, pol: pol}
}

// token is a new enrollment token's secret, hub-eligible when hub.
func (f *autoHubFixture) token(t *testing.T, hub bool) string {
	t.Helper()
	tok, err := pki.NewToken(f.ca.Cert())
	if err != nil {
		t.Fatal(err)
	}
	roles := ""
	if hub {
		roles = allJoinRoles
	}
	if err := f.st.Tokens().CreateHub(t.Context(), tok.Secret, "", roles, nil, time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	return tok.Secret
}

func (f *autoHubFixture) enroll(t *testing.T, secret string, offer *agentv1.HubOffer) *agentv1.EnrollResponse {
	t.Helper()
	key, err := pki.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	csr, err := pki.NewCSR(key, "pi")
	if err != nil {
		t.Fatal(err)
	}
	resp, err := f.e.Enroll(t.Context(), connect.NewRequest(&agentv1.EnrollRequest{
		TokenSecret: secret, Csr: csr, Hostname: "pi", HubOffer: offer,
	}))
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	return resp.Msg
}

// enrollHub is the device.enroll entry's hub outcome for device id.
func (f *autoHubFixture) enrollHub(t *testing.T, id string) string {
	t.Helper()
	entries, err := f.st.Audit().List(t.Context(), 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Action == string(policy.DeviceEnroll) && e.Target == id {
			_, rest, _ := strings.Cut(string(e.Detail), `"hub":"`)
			out, _, _ := strings.Cut(rest, `"`)
			return out
		}
	}
	t.Fatalf("no device.enroll entry for %s", id)
	return ""
}

func capableOffer() *agentv1.HubOffer {
	return &agentv1.HubOffer{Os: "linux", Arch: "arm64", MemTotal: 8 << 30, DiskFree: 20 << 30}
}

// A capable device enrolling with a hub-eligible token gets a join token
// for this master, minted as its own cluster.token.create decision by the
// enrollment token: master and storage while the caps allow.
func TestAutoHubMints(t *testing.T) {
	f := newAutoHubFixture(t, 1, 1)
	secret := f.token(t, true)
	msg := f.enroll(t, secret, capableOffer())
	hj := msg.GetHubJoin()
	if hj.GetToken() == "" || hj.GetRefused() != "" || hj.GetUrl() != "https://192.0.2.10:7443" ||
		!slices.Equal(hj.GetRoles(), []string{"storage", "master"}) {
		t.Fatalf("hub join = %+v, want a storage,master token through hub-a", hj)
	}
	if got := f.enrollHub(t, msg.GetDeviceId()); got != hubOffered {
		t.Fatalf("device.enroll hub = %q, want offered", got)
	}
	jt, err := pki.ParseJoinToken(hj.GetToken())
	if err != nil || jt.CAFingerprint != pki.Fingerprint(f.ca.Cert()) {
		t.Fatalf("join token %v does not pin this CA", err)
	}
	entries := auditEntries(t, f.st, policy.ClusterTokenCreate)
	if len(entries) != 1 || entries[0].ActorKind != policy.ActorToken || entries[0].ActorID != tokenActorID(secret) ||
		entries[0].Target != msg.GetDeviceId() || entries[0].Result != "ok" ||
		!strings.Contains(string(entries[0].Detail), `"roles":"storage,master"`) {
		t.Fatalf("cluster.token.create audit = %+v, want one by the enrollment token for the device", entries)
	}
	all, _ := f.st.Audit().List(t.Context(), 100)
	for _, e := range all {
		if strings.Contains(string(e.Detail)+e.Result+e.ActorID, jt.Secret) {
			t.Fatal("the join token secret is in the audit log")
		}
	}
	got, err := f.st.JoinTokens().Use(t.Context(), jt.Secret, time.Now())
	if err != nil || got.DeviceID != msg.GetDeviceId() || got.Roles != "storage,master" {
		t.Fatalf("minted token = %+v, %v", got, err)
	}
	// Single use.
	if _, err := f.st.JoinTokens().Use(t.Context(), jt.Secret, time.Now()); err == nil {
		t.Fatal("the minted join token was used twice")
	}
}

// The caps: 3 masters, then storage only; 5 storage members, then none.
// Tokens minted and not yet spent count as members to come.
func TestAutoHubCaps(t *testing.T) {
	roles := func(hj *agentv1.HubJoin) string {
		if hj.GetToken() == "" {
			return "refused: " + hj.GetRefused()
		}
		return strings.Join(hj.GetRoles(), ",")
	}
	for _, tc := range []struct {
		name             string
		masters, storage int
		want             []string
	}{
		{"room for both", 1, 1, []string{"storage,master", "storage,master", "storage"}},
		{"3 masters", 3, 3, []string{"storage", "storage", "refused: the cluster has 5 storage members"}},
		{"5 storage members", 1, 5, []string{"refused: the cluster has 5 storage members"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newAutoHubFixture(t, tc.masters, tc.storage)
			for i, want := range tc.want {
				got := roles(f.enroll(t, f.token(t, true), capableOffer()).GetHubJoin())
				if !strings.HasPrefix(got, want) {
					t.Fatalf("enrollment %d: %q, want %q", i+1, got, want)
				}
			}
		})
	}
}

// No hub without a hub-eligible token, an offer and a capable device, which
// the hub checks again whatever the agent decided; nothing is minted then.
func TestAutoHubRefusals(t *testing.T) {
	for _, tc := range []struct {
		name    string
		hub     bool
		offer   *agentv1.HubOffer
		outcome string
		refused string
	}{
		{"token without hub", false, capableOffer(), hubNotEligible, "does not let this device become a hub"},
		{"no offer (manual join, --agent-only)", true, nil, hubNotOffered, ""},
		{"plain token, no offer", false, nil, hubNotEligible, ""},
		{"32-bit", true, &agentv1.HubOffer{Os: "linux", Arch: "arm", MemTotal: 8 << 30, DiskFree: 20 << 30}, hubNotCapable, "64-bit"},
		{"1 GB", true, &agentv1.HubOffer{Os: "linux", Arch: "arm64", MemTotal: 922 << 20, DiskFree: 20 << 30}, hubNotCapable, "memory"},
		{"low disk", true, &agentv1.HubOffer{Os: "linux", Arch: "arm64", MemTotal: 8 << 30, DiskFree: 1 << 30}, hubNotCapable, "free"},
		{"macOS", true, &agentv1.HubOffer{Os: "darwin", Arch: "arm64", MemTotal: 16 << 30, DiskFree: 100 << 30}, hubNotCapable, "not Linux"},
		{"empty offer", true, &agentv1.HubOffer{}, hubNotCapable, "not Linux"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newAutoHubFixture(t, 0, 0)
			msg := f.enroll(t, f.token(t, tc.hub), tc.offer)
			hj := msg.GetHubJoin()
			if hj.GetToken() != "" {
				t.Fatalf("hub join = %+v, want none", hj)
			}
			if (tc.offer == nil) != (hj == nil) || !strings.Contains(hj.GetRefused(), tc.refused) {
				t.Fatalf("hub join = %+v, want refused %q", hj, tc.refused)
			}
			if got := f.enrollHub(t, msg.GetDeviceId()); got != tc.outcome {
				t.Fatalf("device.enroll hub = %q, want %q", got, tc.outcome)
			}
			if n := len(auditEntries(t, f.st, policy.ClusterTokenCreate)); n != 0 {
				t.Fatalf("%d join tokens minted", n)
			}
		})
	}
}

// A master cut off from its cluster refuses the mint, audited, and the
// device is enrolled and stays an agent.
func TestAutoHubMintWhileIsolated(t *testing.T) {
	f := newAutoHubFixture(t, 1, 1)
	var calls atomic.Int32
	// device.enroll is asked first (connected), cluster.token.create next.
	f.pol.FailClosedWhen(func() bool { return calls.Add(1) > 1 })
	msg := f.enroll(t, f.token(t, true), capableOffer())
	if hj := msg.GetHubJoin(); hj.GetToken() != "" || !strings.Contains(hj.GetRefused(), "cut off") {
		t.Fatalf("hub join = %+v, want refused as cut off", hj)
	}
	if msg.GetDeviceId() == "" {
		t.Fatal("the device was not enrolled")
	}
	entries := auditEntries(t, f.st, policy.ClusterTokenCreate)
	if len(entries) != 1 || entries[0].Decision != policy.Deny || !strings.Contains(entries[0].Result, policy.ErrIsolated) {
		t.Fatalf("audit = %+v, want the denial for isolation", entries)
	}
	if all, _, err := f.st.JoinTokens().PendingMinted(t.Context(), time.Now()); err != nil || all != 0 {
		t.Fatalf("pending minted = %d, %v; want none", all, err)
	}
}

// Outside an AP cluster no join token is minted.
func TestAutoHubOutsideAP(t *testing.T) {
	f := newAutoHubFixture(t, 0, 0)
	f.e.masters, f.e.hubs = nil, nil
	if hj := f.enroll(t, f.token(t, true), capableOffer()).GetHubJoin(); hj.GetToken() != "" || hj.GetRefused() == "" {
		t.Fatalf("hub join = %+v, want refused", hj)
	}
}

func auditEntries(t *testing.T, st *store.Store, action policy.Action) []store.AuditEntry {
	t.Helper()
	all, err := st.Audit().List(t.Context(), 500)
	if err != nil {
		t.Fatal(err)
	}
	var out []store.AuditEntry
	for _, e := range all {
		if e.Action == string(action) {
			out = append(out, e)
		}
	}
	return out
}
