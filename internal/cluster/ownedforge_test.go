// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import (
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/hlc"
	"github.com/gvart/hearth/internal/store"
)

// plant writes cmd on storage member s's own database, stamped now as if
// master m wrote it, and merges its rows into every member: what a
// compromised storage member, a replica of the sharded rows, can do.
func plant(t *testing.T, an *apNet, cmds ...store.Command) {
	t.Helper()
	ctx := t.Context()
	var muts []store.Mutation
	for _, cmd := range cmds {
		_, ms, err := an.m("s").st.ApplyLocalMutations(ctx, cmd)
		if err != nil {
			t.Fatalf("plant %s: %v", cmd.Op(), err)
		}
		muts = append(muts, ms...)
	}
	for _, to := range []string{"m", "s2"} {
		if _, err := an.m("s").rep.call(ctx, to, apRequest{Op: opMerge, Muts: muts}); err != nil {
			t.Fatalf("merge the planted rows into %s: %v", to, err)
		}
	}
}

// rewrite changes, in the row ref names, the columns set, stamped newer,
// and merges it into every member, as a storage member could.
func rewrite(t *testing.T, an *apNet, ref store.RowRef, set map[string]any) {
	t.Helper()
	ctx := t.Context()
	ms, err := an.m("m").st.ReadRows(ctx, []store.RowRef{ref})
	if err != nil || len(ms) != 1 {
		t.Fatalf("read %v: %v, %v", ref, ms, err)
	}
	m := ms[0]
	for k, v := range set {
		m.Row[k] = v
	}
	m.HLC = hlc.New(time.Now().Add(time.Second))
	for _, to := range []string{"m", "s2"} {
		if _, err := an.m("s").rep.call(ctx, to, apRequest{Op: opMerge, Muts: []store.Mutation{m}}); err != nil {
			t.Fatalf("merge the rewritten row into %s: %v", to, err)
		}
	}
}

func forgedStamp() store.Stamp { return store.Stamp{HLC: hlc.New(time.Now()), Origin: "m"} }

func hashOf(secret string) []byte {
	h := sha256.Sum256([]byte(secret))
	return h[:]
}

// TestForgedJoinTokenRefused: a join token a storage member wrote, naming
// master m as its owner and granting master (the CA key), is refused by m;
// one m created and the storage member then rewrote to grant master grants
// what m created it with.
func TestForgedJoinTokenRefused(t *testing.T) {
	an := newGateNet(t)
	ctx := t.Context()
	exp := time.Now().Add(time.Hour)
	plant(t, an, store.CreateJoinToken{
		Stamp: forgedStamp(), Hash: hashOf("forged"), ExpiresAt: exp.UnixMilli(), Roles: "storage,master", Owner: "m",
	})
	if _, err := an.m("m").st.JoinTokens().Use(ctx, "forged", "evil", time.Now()); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("forged join token: %v, want ErrNotFound", err)
	}

	if err := an.m("m").st.JoinTokens().Create(ctx, "real", exp, "storage"); err != nil {
		t.Fatal(err)
	}
	rewrite(t, an, store.RowRef{Table: "join_tokens", Key: store.Values{hashOf("real")}}, map[string]any{"roles": "storage,master"})
	jt, err := an.m("m").st.JoinTokens().Use(ctx, "real", "new", time.Now())
	if err != nil || jt.Roles != "storage" {
		t.Fatalf("rewritten join token grants %q, %v; want storage", jt.Roles, err)
	}
}

// TestForgedHubTokenRefused: an enrollment token a storage member wrote,
// naming master m and letting the device become a master, is refused by m.
func TestForgedHubTokenRefused(t *testing.T) {
	an := newGateNet(t)
	ctx := t.Context()
	plant(t, an, store.CreateToken{
		Stamp: forgedStamp(), Hash: hashOf("forged"), Labels: `{}`, HubRoles: "storage,master",
		ExpiresAt: time.Now().Add(time.Hour).UnixMilli(), Owner: "m",
	})
	if _, err := an.m("m").st.Tokens().Consume(ctx, "forged", time.Now()); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("forged hub-eligible token: %v, want ErrNotFound", err)
	}
	// m's own token works, with what m created it with.
	if err := an.m("m").st.Tokens().CreateHub(ctx, "real", "pi", "storage", nil, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	tok, err := an.m("m").st.Tokens().Consume(ctx, "real", time.Now())
	if err != nil || tok.HubRoles != "storage" || tok.Name != "pi" {
		t.Fatalf("m's token: %+v, %v", tok, err)
	}
}

// TestForgedApprovalRefused: an approval a storage member wrote and approved
// for master m, or one m holds that the storage member marks approved, is no
// decision of m's: m cannot be made to decide one it did not create, and a
// replica's approval counts as none.
func TestForgedApprovalRefused(t *testing.T) {
	an := newGateNet(t)
	ctx := t.Context()
	now := time.Now()
	ap := store.Approval{
		ID: "held", CreatedAt: now, ExpiresAt: now.Add(time.Hour), ActorKind: "automation", ActorID: "a",
		Action: "automation.exec", Class: "dangerous", Target: "pi", Detail: []byte(`{}`),
	}
	if err := an.m("m").st.Approvals().Create(ctx, ap); err != nil {
		t.Fatal(err)
	}
	rewrite(t, an, store.RowRef{Table: "approvals", Key: store.Values{"held"}},
		map[string]any{"status": store.ApprovalApproved, "decided_by": "web/w", "decided_at": now.UnixMilli()})
	got, err := an.m("m").st.Approvals().Get(ctx, "held")
	if err != nil || got.Status != store.ApprovalApproved {
		t.Fatalf("the replicas hold %+v, %v; want the planted approval", got, err)
	}
	if d, checked, err := an.m("m").st.Approvals().OwnerDecision(ctx, "held"); err != nil || !checked || d != "" {
		t.Fatalf("m's own decision = %q (checked %v), %v; want none", d, checked, err)
	}

	plant(t, an, store.CreateApproval{Stamp: forgedStamp(), ID: "forged", CreatedAt: now.UnixMilli(),
		ExpiresAt: now.Add(time.Hour).UnixMilli(), ActorKind: "automation", ActorID: "a", Action: "automation.exec",
		Class: "dangerous", Target: "pi", Detail: `{}`, Owner: "m"})
	err = an.m("m").st.Approvals().Decide(ctx, "forged", store.ApprovalApproved, "web/w", now)
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("m decided an approval it did not create: %v, want ErrNotFound", err)
	}
	// Its own approval, it decides.
	if err := an.m("m").st.Approvals().Create(ctx, store.Approval{ID: "own", CreatedAt: now, ExpiresAt: now.Add(time.Hour),
		ActorKind: "automation", ActorID: "a", Action: "automation.exec", Class: "dangerous", Target: "pi", Detail: []byte(`{}`)}); err != nil {
		t.Fatal(err)
	}
	if err := an.m("m").st.Approvals().Decide(ctx, "own", store.ApprovalApproved, "web/w", now); err != nil {
		t.Fatal(err)
	}
	if d, _, _ := an.m("m").st.Approvals().OwnerDecision(ctx, "own"); d != store.ApprovalApproved {
		t.Fatalf("m's decision on its own approval = %q", d)
	}
}
