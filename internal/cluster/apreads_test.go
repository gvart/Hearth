// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/store"
)

// Reads inside writes (#276): a member that missed a write (it was down,
// the write waits in a hint) and then applies a command reading that row
// decides on the newest copy the other replicas hold, not on its own.
// Hints and anti-entropy run hourly here, so the copy stays stale until the
// command runs.

// secretKeyPreferring returns a secret whose partition key (its SHA-256, in
// hex) has a preference list starting with first.
func secretKeyPreferring(t *testing.T, ids []string, prefix string, first ...string) string {
	t.Helper()
	ring := NewRing(ids)
	for i := range 100000 {
		s := prefix + strconv.Itoa(i)
		h := sha256.Sum256([]byte(s))
		if slices.Equal(ring.Preference(store.BucketOf(store.Token(hex.EncodeToString(h[:]))))[:len(first)], first) {
			return s
		}
	}
	t.Fatalf("no secret preferring %v", first)
	return ""
}

// localRows counts the rows query finds in m's own database.
func localRows(t *testing.T, m *apMember, query string, args ...any) int64 {
	t.Helper()
	rows, err := m.st.ReadLocal(t.Context(), query, store.Values(args))
	if err != nil {
		t.Fatal(err)
	}
	n, _ := rows.Vals[0][0].(int64)
	return n
}

// A certificate pinned while one of its replicas was down is not pinned
// again, to another fingerprint, by that replica: the second fingerprint is
// a mismatch. One created while it was down is found by it.
func TestPinOnAReplicaThatMissedThePin(t *testing.T) {
	ctx := t.Context()
	ids := []string{"a", "b", "c"}
	an := newAPNet(t, 2, ids...)
	id := keyOwnedBy(t, ids, 2, "dev", "b", "c")
	if err := an.m("b").st.Devices().Upsert(ctx, device(id, "d")); err != nil {
		t.Fatal(err)
	}
	if err := an.m("b").st.Certs().Create(ctx, "s1", id); err != nil {
		t.Fatal(err)
	}
	an.setDown("c", true)
	if out, err := an.m("b").st.Certs().Pin(ctx, "s1", id, "fp-real", "", time.Now()); err != nil || out != store.Pinned {
		t.Fatalf("pin on b = %v, %v", out, err)
	}
	if err := an.m("b").st.Certs().Create(ctx, "s2", id); err != nil {
		t.Fatal(err)
	}
	an.setDown("c", false)
	if n := localRows(t, an.m("c"), `SELECT count(*) FROM certs WHERE serial = 's1' AND fingerprint IS NULL`); n != 1 {
		t.Fatalf("c holds %d unpinned copies of s1; the test needs it stale", n)
	}

	out, err := an.m("c").st.Certs().Pin(ctx, "s1", id, "fp-minted", "", time.Now())
	if err != nil || out != store.PinMismatch {
		t.Fatalf("pin of another fingerprint on c = %v, %v; want a mismatch", out, err)
	}
	for _, m := range []string{"b", "c"} {
		if n := localRows(t, an.m(m), `SELECT count(*) FROM certs WHERE serial = 's1' AND fingerprint = 'fp-real' AND pin_mismatch_at IS NOT NULL`); n != 1 {
			t.Errorf("%s: s1 lost its pin or its mismatch", m)
		}
	}
	// A mismatch is recorded once.
	if out, err := an.m("c").st.Certs().Pin(ctx, "s1", id, "fp-minted", "", time.Now()); err != nil || out != store.PinKept {
		t.Errorf("second pin of the other fingerprint = %v, %v; want kept", out, err)
	}

	if out, err := an.m("c").st.Certs().Pin(ctx, "s2", id, "fp-2", "", time.Now()); err != nil || out != store.Pinned {
		t.Fatalf("pin on c of a certificate it missed = %v, %v", out, err)
	}
}

// Revoking a device on a replica that missed one of its certificates
// revokes that certificate too.
func TestRevokeDeviceOnAReplicaThatMissedACert(t *testing.T) {
	ctx := t.Context()
	ids := []string{"a", "b", "c"}
	an := newAPNet(t, 2, ids...)
	id := keyOwnedBy(t, ids, 2, "dev", "b", "c")
	if err := an.m("b").st.Devices().Upsert(ctx, device(id, "d")); err != nil {
		t.Fatal(err)
	}
	if err := an.m("b").st.Certs().Create(ctx, "s1", id); err != nil {
		t.Fatal(err)
	}
	an.setDown("c", true)
	if err := an.m("b").st.Certs().Create(ctx, "s2", id); err != nil {
		t.Fatal(err)
	}
	an.setDown("c", false)
	if n := localRows(t, an.m("c"), `SELECT count(*) FROM certs WHERE serial = 's2'`); n != 0 {
		t.Fatal("c holds s2; the test needs it stale")
	}

	n, err := an.m("c").st.Certs().RevokeDevice(ctx, id, time.Now())
	if err != nil || n != 2 {
		t.Fatalf("revoke on c = %d, %v; want both certificates", n, err)
	}
	for _, m := range ids {
		if err := an.m(m).st.Certs().Check(ctx, "s2", id); !errors.Is(err, store.ErrCertRevoked) {
			t.Errorf("%s: check s2 = %v, want revoked", m, err)
		}
	}
}

// An expiry applied on a replica that missed the owner's approval does not
// replace it: the approval is closed.
func TestExpiryOnAReplicaThatMissedTheDecision(t *testing.T) {
	ctx := t.Context()
	ids := []string{"a", "b", "c"}
	an := newAPNet(t, 2, ids...)
	apID := keyOwnedBy(t, ids, 2, "ap", "b", "c")
	now := time.Now()
	if err := an.m("b").st.Approvals().Create(ctx, store.Approval{
		ID: apID, CreatedAt: now, ExpiresAt: now.Add(time.Minute), ActorKind: "web", ActorID: "x",
		Action: "kube.node.drain", Class: "dangerous", Target: "lab/pi",
	}); err != nil {
		t.Fatal(err)
	}
	an.setDown("c", true)
	if err := an.m("b").st.Approvals().Decide(ctx, apID, store.ApprovalApproved, "web:x", now); err != nil {
		t.Fatalf("approve on b, its owner = %v", err)
	}
	an.setDown("c", false)
	if n := localRows(t, an.m("c"), `SELECT count(*) FROM approvals WHERE id = ? AND status = 'pending'`, apID); n != 1 {
		t.Fatal("c does not hold a pending copy; the test needs it stale")
	}

	err := an.m("c").st.Approvals().Decide(ctx, apID, store.ApprovalExpired, "sweep", now.Add(2*time.Minute))
	if !errors.Is(err, store.ErrApprovalClosed) {
		t.Fatalf("expire on c = %v, want ErrApprovalClosed", err)
	}
	for _, m := range ids {
		a, err := an.m(m).st.Approvals().Get(ctx, apID)
		if err != nil || a.Status != store.ApprovalApproved {
			t.Errorf("%s: approval = %q, %v; want approved", m, a.Status, err)
		}
	}
}

// Single use of a master-owned token holds on a replica whose copy does not
// show the use, without any refresh: the owner refuses its second use from
// its own record, and another master is refused any use as no owner.
func TestOwnedTokenSingleUseOnAStaleReplica(t *testing.T) {
	ctx := t.Context()
	ids := []string{"a", "b", "c", "d"}
	an := newAPNet(t, 2, ids...)
	// c and b hold it, d stands in for c: a's use goes to b, which has it.
	used := secretKeyPreferring(t, ids, "used", "c", "b", "d")
	if err := an.m("a").st.Tokens().Create(ctx, used, nil, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	an.setDown("c", true)
	if _, err := an.m("a").st.Tokens().Consume(ctx, used, time.Now()); err != nil {
		t.Fatalf("consume with c down = %v", err)
	}
	an.setDown("c", false)
	h := sha256.Sum256([]byte(used))
	if n := localRows(t, an.m("c"), `SELECT count(*) FROM tokens WHERE hash = ? AND used_at IS NULL`, h[:]); n != 1 {
		t.Fatal("c's copy shows the use; the test needs it stale")
	}
	if _, err := an.m("a").st.Tokens().Consume(ctx, used, time.Now()); !errors.Is(err, store.ErrTokenUsed) {
		t.Errorf("second use by the owner = %v, want ErrTokenUsed", err)
	}
	for _, m := range []string{"b", "c", "d"} {
		if _, err := an.m(m).st.Tokens().Consume(ctx, used, time.Now()); !errors.Is(err, store.ErrNotOwner) {
			t.Errorf("use on %s = %v, want ErrNotOwner", m, err)
		}
	}
}

// A use forwarded to a replica with another member hung costs that member
// one quick timeout in the refresh, well within the forward's deadline.
func TestRefreshWithAHungMember(t *testing.T) {
	ctx := t.Context()
	ids := []string{"a", "b", "c", "d"}
	an := newAPNet(t, 2, ids...)
	tok := secretKeyPreferring(t, ids, "tok", "c", "b")
	if err := an.m("a").st.Tokens().Create(ctx, tok, nil, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	other := "d" // no replica of the token: the use goes to c, which asks b, a and d
	an.mu.Lock()
	an.hung[other] = true
	an.mu.Unlock()
	an.dropConns()
	start := time.Now()
	if _, err := an.m("a").st.Tokens().Consume(ctx, tok, time.Now()); err != nil {
		t.Fatalf("consume with %s hung = %v", other, err)
	}
	if took := time.Since(start); took > 2*defaultQuickTimeout+time.Second {
		t.Errorf("consume with %s hung took %v", other, took)
	}
}

// A password reset with no storage member reachable fails: it ended no
// session.
func TestPasswordResetNeedsAStorageMember(t *testing.T) {
	ctx := t.Context()
	an := newAPNet(t, 2, "a", "b", "c")
	an.m("a").rep.SetLocal(false, false) // a master that holds no partition
	an.setDown("b", true)
	an.setDown("c", true)
	if err := an.m("a").st.Admin().SetPasswordHash(ctx, "$argon2id$new"); !errors.Is(err, store.ErrUnavailable) {
		t.Fatalf("reset with no storage member = %v, want ErrUnavailable", err)
	}
}

// An enrollment token created while the replica its uses go to first was
// down is consumed there, once; one that expired is refused as expired.
func TestTokenOnAReplicaThatMissedIt(t *testing.T) {
	ctx := t.Context()
	ids := []string{"a", "b", "c"}
	an := newAPNet(t, 2, ids...)
	exp := time.Now().Add(time.Hour)
	tok := secretKeyPreferring(t, ids, "tok", "c", "b")
	an.setDown("c", true)
	if err := an.m("a").st.Tokens().Create(ctx, tok, nil, exp); err != nil {
		t.Fatal(err)
	}
	an.setDown("c", false)
	if n := localRows(t, an.m("c"), `SELECT count(*) FROM tokens`); n != 0 {
		t.Fatal("c holds the token; the test needs it stale")
	}
	if _, err := an.m("a").st.Tokens().Consume(ctx, tok, time.Now()); err != nil {
		t.Fatalf("consume on a, its owner, forwarded to c = %v", err)
	}
	if _, err := an.m("a").st.Tokens().Consume(ctx, tok, time.Now()); !errors.Is(err, store.ErrTokenUsed) {
		t.Fatalf("second consume = %v, want ErrTokenUsed", err)
	}

	// Expired while c was down: refused there as expired.
	old := secretKeyPreferring(t, ids, "old", "c", "b")
	an.setDown("c", true)
	if err := an.m("a").st.Tokens().Create(ctx, old, nil, time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	an.setDown("c", false)
	if _, err := an.m("a").st.Tokens().Consume(ctx, old, time.Now().Add(time.Minute)); !errors.Is(err, store.ErrTokenExpired) {
		t.Errorf("consume of an expired token = %v, want ErrTokenExpired", err)
	}
}

// Signing out on a replica that missed the session ends it.
func TestSignOutOnAReplicaThatMissedTheSession(t *testing.T) {
	ctx := t.Context()
	ids := []string{"a", "b", "c"}
	an := newAPNet(t, 2, ids...)
	sec := secretKeyPreferring(t, ids, "sess", "c", "b")
	now := time.Now()
	an.setDown("c", true)
	if err := an.m("a").st.Admin().CreateSession(ctx, sec, now, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	an.setDown("c", false)
	if n := localRows(t, an.m("c"), `SELECT count(*) FROM sessions`); n != 0 {
		t.Fatal("c holds the session; the test needs it stale")
	}
	if err := an.m("a").st.Admin().DeleteSession(ctx, sec); err != nil {
		t.Fatal(err)
	}
	for _, m := range ids {
		if _, err := an.m(m).st.Admin().CheckSession(ctx, sec, now); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("%s: session after sign-out = %v, want ErrNotFound", m, err)
		}
	}
}

// A password reset ends every session, those on partitions the member
// applying it does not hold too.
func TestPasswordResetEndsEverySession(t *testing.T) {
	ctx := t.Context()
	ids := []string{"a", "b", "c"}
	an := newAPNet(t, 2, ids...)
	now := time.Now()
	var secrets []string
	for i, pair := range [][]string{{"a", "b"}, {"b", "c"}, {"c", "a"}} {
		s := secretKeyPreferring(t, ids, "s"+strconv.Itoa(i)+"-", pair...)
		if err := an.m("a").st.Admin().CreateSession(ctx, s, now, now.Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
		secrets = append(secrets, s)
	}
	if err := an.m("a").st.Admin().SetPasswordHash(ctx, "$argon2id$new"); err != nil {
		t.Fatal(err)
	}
	for _, s := range secrets {
		for _, m := range ids {
			if _, err := an.m(m).st.Admin().CheckSession(ctx, s, now); !errors.Is(err, store.ErrNotFound) {
				t.Errorf("%s: session %s after the reset = %v, want ErrNotFound", m, s, err)
			}
		}
	}
	for _, m := range ids {
		if h, err := an.m(m).st.Admin().PasswordHash(ctx); err != nil || h != "$argon2id$new" {
			t.Errorf("%s: password hash = %q, %v", m, h, err)
		}
	}
}

// The first import of configuration documents, on a member that missed
// documents stored while it was down, is refused: documents are stored.
func TestImportFirstOnAMemberThatMissedADocument(t *testing.T) {
	ctx := t.Context()
	ids := []string{"a", "b", "c"}
	an := newAPNet(t, 2, ids...)
	doc := store.ConfigDoc{Kind: store.ConfigRunbook, Name: "r.yaml", Content: []byte("steps: []")}
	an.setDown("c", true)
	if err := an.m("a").st.ConfigDocs().Put(ctx, "admin/root", []store.ConfigDoc{doc}, time.Now()); err != nil {
		t.Fatal(err)
	}
	an.setDown("c", false)
	if n := localRows(t, an.m("c"), `SELECT count(*) FROM config_docs`); n != 0 {
		t.Fatal("c holds the document; the test needs it stale")
	}
	files := []store.ConfigDoc{{Kind: store.ConfigAutomation, Name: "a.yaml", Content: []byte("id: a")}}
	if err := an.m("c").st.ConfigDocs().ImportFirst(ctx, "admin/root", files, time.Now()); !errors.Is(err, store.ErrExists) {
		t.Fatalf("first import on c = %v, want ErrExists", err)
	}
}
