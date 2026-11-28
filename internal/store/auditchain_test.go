// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"testing"
	"time"
)

// testSealer is an AuditSealer with fixed keys: it seals with kid's.
type testSealer struct {
	kid  string
	keys map[string][]byte
}

func newTestSealer(kid string, earlier ...string) testSealer {
	s := testSealer{kid: kid, keys: map[string][]byte{}}
	for _, k := range append(earlier, kid) {
		if k != "" {
			s.keys[k] = []byte("key of " + k)
		}
	}
	return s
}

func (s testSealer) MAC(msg []byte) (string, []byte, error) {
	if s.kid == "" {
		return "", nil, errors.New("no key")
	}
	m := hmac.New(sha256.New, s.keys[s.kid])
	m.Write(msg)
	return s.kid, m.Sum(nil), nil
}

func (s testSealer) Check(kid string, msg, mac []byte) (bool, bool) {
	key, ok := s.keys[kid]
	if !ok {
		return false, false
	}
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	return true, hmac.Equal(m.Sum(nil), mac)
}

func (s testSealer) CanVerify() bool { return s.kid != "" }

func appendN(ctx context.Context, t *testing.T, s *Store, from, n int) {
	t.Helper()
	for i := range n {
		if _, err := s.Audit().Append(ctx, AuditEntry{
			ActorKind: "admin", ActorID: "root", Action: fmt.Sprintf("act.%d", from+i), Decision: "allow",
		}); err != nil {
			t.Fatal(err)
		}
	}
}

func verifications(ctx context.Context, t *testing.T, s *Store) map[string]string {
	t.Helper()
	es, err := s.Audit().List(ctx, 1000)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, e := range es {
		out[e.Action] = e.Verification
	}
	return out
}

func verify(ctx context.Context, t *testing.T, s *Store) AuditReport {
	t.Helper()
	rep, err := s.Audit().Verify(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

// chainOf returns the report of origin's chain.
func chainOf(t *testing.T, rep AuditReport, origin string) AuditChainReport {
	t.Helper()
	for _, c := range rep.Chains {
		if c.Origin == origin {
			return c
		}
	}
	t.Fatalf("no chain of %s in %+v", origin, rep)
	return AuditChainReport{}
}

// rawExec runs SQL the log's triggers refuse, as a member editing its own
// database would.
func rawExec(ctx context.Context, t *testing.T, s *Store, stmts ...string) {
	t.Helper()
	for _, q := range append([]string{`DROP TRIGGER IF EXISTS audit_log_no_update`, `DROP TRIGGER IF EXISTS audit_log_no_delete`}, stmts...) {
		if _, err := s.db.ExecContext(ctx, q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
}

func TestAuditSealedEntriesVerify(t *testing.T) {
	ctx := t.Context()
	s := openTestWith(t, WithOrigin("hub-a"))
	s.SetAuditSealer(newTestSealer("k1"))
	appendN(ctx, t, s, 0, 3)
	es, err := s.Audit().List(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	for i, e := range es {
		if e.Verification != AuditVerified || e.SealOrigin != "hub-a" || e.SealSeq != int64(3-i) {
			t.Errorf("entry %d: %s %s#%d, want verified hub-a#%d", i, e.Verification, e.SealOrigin, e.SealSeq, 3-i)
		}
	}
	rep := verify(ctx, t, s)
	c := chainOf(t, rep, "hub-a")
	if !rep.OK() || !rep.CanVerify || rep.Entries != 3 || c.Last != 3 || c.Verified != 3 || c.Head != 3 {
		t.Fatalf("report = %+v", rep)
	}
}

// An action's entry and its outcome fold into one row: verified only when
// both are.
func TestAuditFoldedOutcomeVerification(t *testing.T) {
	ctx := t.Context()
	s := openTestWith(t, WithOrigin("hub-a"))
	s.SetAuditSealer(newTestSealer("k1"))
	if _, err := s.Audit().Append(ctx, AuditEntry{ActorKind: "admin", ActorID: "root", Action: "device.exec",
		Decision: "allow", Detail: []byte(`{"audit_op":"op1"}`)}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Audit().Append(ctx, AuditEntry{ActorKind: "admin", ActorID: "root", Action: "device.exec",
		Decision: "allow", Result: "ok", Detail: []byte(`{"audit_outcome_of":"op1"}`)}); err != nil {
		t.Fatal(err)
	}
	if v := verifications(ctx, t, s); v["device.exec"] != AuditVerified {
		t.Fatalf("folded entry = %s, want verified", v["device.exec"])
	}
	// The outcome changed in place.
	rawExec(ctx, t, s, `UPDATE audit_log SET result = 'failed' WHERE audit_outcome_of = 'op1'`)
	es, err := s.Audit().List(ctx, 10)
	if err != nil || len(es) != 1 || es[0].Result != "failed" || es[0].Verification != AuditUnverified {
		t.Fatalf("List = %+v, %v; want one failed, unverified entry", es, err)
	}
}

// A member without the hub CA key cannot make a valid entry: one with no
// seal, one with a made-up seal, or a real seal on changed content.
func TestAuditForgedEntriesUnverified(t *testing.T) {
	ctx := t.Context()
	master := openTestWith(t, WithOrigin("hub-a"))
	master.SetAuditSealer(newTestSealer("k1"))
	appendN(ctx, t, master, 0, 2)

	// A keyless member's entry, merged into the master's log.
	keyless := openTestWith(t, WithOrigin("storage-1"))
	keyless.SetAuditSealer(newTestSealer(""))
	if _, err := keyless.Audit().Append(ctx, AuditEntry{ActorKind: "admin", ActorID: "root", Action: "unsealed", Decision: "allow"}); err != nil {
		t.Fatal(err)
	}
	// A seal it made up, naming the master's chain and its key.
	forged := Mutation{Table: auditTable, HLC: 1 << 50, Origin: "hub-a", Seq: 9, Row: map[string]any{
		"ts": time.Now().UnixMilli(), "actor_kind": "admin", "actor_id": "root", "action": "forged", "target": "",
		"decision": "allow", "result": "", "detail": "{}", "audit_key": nil,
		"chain_origin": "hub-a", "chain_seq": int64(3), "chain_prev": "", "chain_kid": "k1", "chain_mac": "00ff",
	}}
	muts := append(auditMutations(ctx, t, keyless), forged)
	if err := master.Merge(ctx, muts); err != nil {
		t.Fatal(err)
	}
	// And a real entry whose content it changed.
	rawExec(ctx, t, master, `UPDATE audit_log SET decision = 'deny' WHERE action = 'act.1'`)

	want := map[string]string{
		"act.0": AuditVerified, "act.1": AuditUnverified, "unsealed": AuditUnverified, "forged": AuditUnverified,
	}
	if got := verifications(ctx, t, master); !reflect.DeepEqual(got, want) {
		t.Fatalf("verifications = %v, want %v", got, want)
	}
	rep := verify(ctx, t, master)
	c := chainOf(t, rep, "hub-a")
	if rep.OK() || rep.Unsealed != 1 || !reflect.DeepEqual(c.Unverified, []int64{2, 3}) || c.Verified != 1 {
		t.Fatalf("report = %+v", rep)
	}
	// The keyless member checks nothing.
	if v := verifications(ctx, t, keyless); v["unsealed"] != AuditUnverified {
		t.Errorf("keyless member's own unsealed entry = %s", v["unsealed"])
	}
	if rep := verify(ctx, t, keyless); rep.CanVerify {
		t.Errorf("keyless member can verify: %+v", rep)
	}
	if v := verifications(ctx, t, master); v["act.0"] != AuditVerified {
		t.Fatal(v)
	}
	keylessCopy := openTestWith(t, WithOrigin("storage-2"))
	keylessCopy.SetAuditSealer(newTestSealer(""))
	if err := keylessCopy.Merge(ctx, auditMutations(ctx, t, master)); err != nil {
		t.Fatal(err)
	}
	if v := verifications(ctx, t, keylessCopy); v["act.0"] != AuditUnchecked {
		t.Errorf("a sealed entry on a keyless member = %s, want unchecked", v["act.0"])
	}
}

// auditMutations returns every entry of s's log as the mutations
// anti-entropy sends (ReadRows).
func auditMutations(ctx context.Context, t *testing.T, s *Store) []Mutation {
	t.Helper()
	rows, err := s.db.QueryContext(ctx, `SELECT _hlc, _origin, _seq FROM audit_log ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var refs []RowRef
	for rows.Next() {
		var h, seq int64
		var origin string
		if err := rows.Scan(&h, &origin, &seq); err != nil {
			t.Fatal(err)
		}
		refs = append(refs, RowRef{Table: auditTable, Key: Values{h, origin, seq}})
	}
	muts, err := s.ReadRows(ctx, refs)
	if err != nil {
		t.Fatal(err)
	}
	return muts
}

// An entry that reaches another member by anti-entropy keeps its seal.
func TestAuditSealSurvivesReplication(t *testing.T) {
	ctx := t.Context()
	a := openTestWith(t, WithOrigin("hub-a"))
	sealer := newTestSealer("k1")
	a.SetAuditSealer(sealer)
	appendN(ctx, t, a, 0, 3)
	b := openTestWith(t, WithOrigin("hub-b"))
	b.SetAuditSealer(sealer)
	if err := b.Merge(ctx, auditMutations(ctx, t, a)); err != nil {
		t.Fatal(err)
	}
	for action, v := range verifications(ctx, t, b) {
		if v != AuditVerified {
			t.Errorf("%s on the replica: %s", action, v)
		}
	}
	if rep := verify(ctx, t, b); !rep.OK() || chainOf(t, rep, "hub-a").Verified != 3 {
		t.Fatalf("replica's report = %+v", rep)
	}
}

// A deleted entry is a gap of its master's chain; so is a deleted newest
// entry this master appended.
func TestAuditDeletedEntryIsAGap(t *testing.T) {
	ctx := t.Context()
	s := openTestWith(t, WithOrigin("hub-a"))
	s.SetAuditSealer(newTestSealer("k1"))
	appendN(ctx, t, s, 0, 6)
	rawExec(ctx, t, s, `DELETE FROM audit_log WHERE chain_seq IN (3, 4)`, `DELETE FROM audit_log WHERE chain_seq = 6`)
	c := chainOf(t, verify(ctx, t, s), "hub-a")
	want := []AuditRange{{From: 3, To: 4}, {From: 6, To: 6}}
	if !reflect.DeepEqual(c.Missing, want) || c.Last != 5 || c.Head != 6 || c.OK() {
		t.Fatalf("chain = %+v, want missing %v", c, want)
	}
	// Entries before the first are missing too.
	rawExec(ctx, t, s, `DELETE FROM audit_log WHERE chain_seq = 1`)
	if c := chainOf(t, verify(ctx, t, s), "hub-a"); c.Missing[0] != (AuditRange{From: 1, To: 1}) {
		t.Fatalf("missing = %v, want 1 first", c.Missing)
	}
}

// Entries moved in the chain, or swapped, do not verify.
func TestAuditReorderedEntriesDetected(t *testing.T) {
	ctx := t.Context()
	s := openTestWith(t, WithOrigin("hub-a"))
	s.SetAuditSealer(newTestSealer("k1"))
	appendN(ctx, t, s, 0, 4)
	// Seals swapped between entries 2 and 3: each now names the other's
	// place.
	rawExec(ctx, t, s,
		`UPDATE audit_log SET chain_seq = -chain_seq WHERE chain_seq IN (2, 3)`,
		`UPDATE audit_log SET chain_seq = 3 WHERE chain_seq = -2`,
		`UPDATE audit_log SET chain_seq = 2 WHERE chain_seq = -3`)
	c := chainOf(t, verify(ctx, t, s), "hub-a")
	if !reflect.DeepEqual(c.Unverified, []int64{2, 3}) {
		t.Fatalf("chain = %+v, want 2 and 3 unverified", c)
	}
	v := verifications(ctx, t, s)
	if v["act.1"] != AuditUnverified || v["act.2"] != AuditUnverified || v["act.3"] != AuditVerified {
		t.Fatalf("verifications = %v", v)
	}
}

// A verified entry that does not follow the one before (a fork whose other
// branch is gone) breaks the chain; two sealed entries with one sequence
// number (a chain taken up again from an older head) are duplicates.
func TestAuditBrokenAndDuplicateLinks(t *testing.T) {
	ctx := t.Context()
	sealer := newTestSealer("k1")
	s := openTestWith(t, WithOrigin("hub-a"))
	s.SetAuditSealer(sealer)
	appendN(ctx, t, s, 0, 3)
	// The same master from a backup taken after its first entry.
	restored := openTestWith(t, WithOrigin("hub-a"))
	restored.SetAuditSealer(sealer)
	first := auditMutations(ctx, t, s)[:1]
	if err := restored.Merge(ctx, first); err != nil {
		t.Fatal(err)
	}
	appendN(ctx, t, restored, 10, 2) // seq 2 and 3 again
	if err := s.Merge(ctx, auditMutations(ctx, t, restored)); err != nil {
		t.Fatal(err)
	}
	c := chainOf(t, verify(ctx, t, s), "hub-a")
	if !reflect.DeepEqual(c.Duplicates, []int64{2, 3}) || len(c.Broken) != 0 || len(c.Missing) != 0 {
		t.Fatalf("chain = %+v, want 2 and 3 duplicated", c)
	}
	// One branch's entry 2 gone: the other branch's 3 does not follow
	// what is left.
	rawExec(ctx, t, s, `DELETE FROM audit_log WHERE chain_seq = 2 AND action = 'act.10'`)
	c = chainOf(t, verify(ctx, t, s), "hub-a")
	if !reflect.DeepEqual(c.Broken, []int64{3}) {
		t.Fatalf("chain = %+v, want 3 broken", c)
	}
}

// Entries written before sealing started are legacy, not errors.
func TestAuditLegacyEntries(t *testing.T) {
	ctx := t.Context()
	s := openTestWith(t, WithOrigin("hub-a"))
	// Written before the hub sealed.
	if _, err := s.Audit().Append(ctx, AuditEntry{TS: time.UnixMilli(1_700_000_000_000), ActorKind: "admin",
		ActorID: "root", Action: "old", Decision: "allow"}); err != nil {
		t.Fatal(err)
	}
	s.SetAuditSealer(newTestSealer("k1"))
	if v := verifications(ctx, t, s); v["old"] != AuditLegacy {
		t.Fatalf("old entry = %s, want legacy", v["old"])
	}
	rep := verify(ctx, t, s)
	if rep.Legacy != 1 || rep.Unsealed != 0 || !rep.OK() {
		t.Fatalf("report = %+v", rep)
	}
	// Below the seal schema every entry is legacy.
	es, err := s.Audit().query(ctx, AuditFilter{}, 10, auditByVersion)
	if err != nil || es[0].Verification != AuditLegacy {
		t.Fatalf("query at the versioned schema = %+v, %v", es, err)
	}
}

// After a rotation, entries sealed with the earlier CA's key verify with
// it, and the chain goes on across the keys.
func TestAuditRotationKeepsVerification(t *testing.T) {
	ctx := t.Context()
	s := openTestWith(t, WithOrigin("hub-a"))
	s.SetAuditSealer(newTestSealer("k1"))
	appendN(ctx, t, s, 0, 2)
	s.SetAuditSealer(newTestSealer("k2", "k1"))
	appendN(ctx, t, s, 2, 2)
	for action, v := range verifications(ctx, t, s) {
		if v != AuditVerified {
			t.Errorf("%s: %s", action, v)
		}
	}
	if rep := verify(ctx, t, s); !rep.OK() || chainOf(t, rep, "hub-a").Verified != 4 {
		t.Fatalf("report = %+v", rep)
	}
	// Without the earlier key the entries before the rotation do not.
	s.SetAuditSealer(newTestSealer("k2"))
	if v := verifications(ctx, t, s); v["act.0"] != AuditUnverified || v["act.3"] != AuditVerified {
		t.Fatalf("verifications = %v", v)
	}
}

// failOnce fails the first write it is given, after applying it or not.
type failOnce struct {
	s       *Store
	applied bool
	n       int
}

func (f *failOnce) Apply(ctx context.Context, cmd Command) (Result, error) {
	f.n++
	if f.n == 1 {
		if f.applied {
			_, _ = f.s.ApplyLocal(ctx, cmd)
		}
		return Result{}, errors.New("no quorum")
	}
	return f.s.ApplyLocal(ctx, cmd)
}

// A write that failed leaves no gap: the retry takes its place in the chain.
// One that failed after it was applied is found again by its key.
func TestAuditFailedAppendLeavesNoGap(t *testing.T) {
	for _, applied := range []bool{false, true} {
		t.Run(fmt.Sprintf("applied=%v", applied), func(t *testing.T) {
			ctx := t.Context()
			f := &failOnce{applied: applied}
			s := openTestWith(t, WithOrigin("hub-a"), WithApplier(func(s *Store) Applier { f.s = s; return f }))
			s.SetAuditSealer(newTestSealer("k1"))
			e := AuditEntry{TS: time.UnixMilli(1_800_000_000_000), ActorKind: "hub", ActorID: "a", Action: "x",
				Decision: "allow", Key: "once-1"}
			if _, err := s.Audit().Append(ctx, e); err == nil {
				t.Fatal("first append succeeded")
			}
			if _, err := s.Audit().Append(ctx, e); err != nil {
				t.Fatal(err)
			}
			appendN(ctx, t, s, 0, 1)
			rep := verify(ctx, t, s)
			c := chainOf(t, rep, "hub-a")
			if !rep.OK() || c.Last != 2 || c.Verified != 2 {
				t.Fatalf("report = %+v", rep)
			}
		})
	}
}

// Concurrent appends make one chain without a fork.
func TestAuditConcurrentAppends(t *testing.T) {
	ctx := t.Context()
	s := openTestWith(t, WithOrigin("hub-a"))
	s.SetAuditSealer(newTestSealer("k1"))
	var wg sync.WaitGroup
	for g := range 8 {
		wg.Go(func() {
			for i := range 10 {
				if _, err := s.Audit().Append(ctx, AuditEntry{
					ActorKind: "admin", ActorID: "root", Action: fmt.Sprintf("act.%d", g*100+i), Decision: "allow",
				}); err != nil {
					t.Error(err)
				}
			}
		})
	}
	wg.Wait()
	rep := verify(ctx, t, s)
	if c := chainOf(t, rep, "hub-a"); !rep.OK() || c.Last != 80 || c.Verified != 80 {
		t.Fatalf("report = %+v", rep)
	}
}

// A master that restarts takes its chain up from the log.
func TestAuditChainHeadFromTheLog(t *testing.T) {
	ctx := t.Context()
	s := openTestWith(t, WithOrigin("hub-a"))
	sealer := newTestSealer("k1")
	s.SetAuditSealer(sealer)
	appendN(ctx, t, s, 0, 3)
	// A restart: the chain loads again.
	s.chain.mu.Lock()
	s.chain.loaded, s.chain.seq, s.chain.mac = false, 0, ""
	s.chain.mu.Unlock()
	// A forged entry with a later number does not move the head.
	if err := s.Merge(ctx, []Mutation{{Table: auditTable, HLC: 1 << 50, Origin: "x", Seq: 1, Row: map[string]any{
		"ts": int64(1), "actor_kind": "a", "actor_id": "b", "action": "forged", "target": "", "decision": "allow",
		"result": "", "detail": "{}", "audit_key": nil,
		"chain_origin": "hub-a", "chain_seq": int64(1000), "chain_prev": "", "chain_kid": "k1", "chain_mac": "00",
	}}}); err != nil {
		t.Fatal(err)
	}
	appendN(ctx, t, s, 3, 1)
	c := chainOf(t, verify(ctx, t, s), "hub-a")
	if c.Verified != 4 || len(c.Missing) != 1 || c.Missing[0] != (AuditRange{From: 5, To: 999}) || c.Head != 4 {
		t.Fatalf("chain = %+v; want 1-4 verified, the forged 1000 alone", c)
	}
}

// Verify on a sharded member reads every member's part of the log: an entry
// a member does not return is missing.
func TestAuditVerifySharded(t *testing.T) {
	ctx := t.Context()
	sealer := newTestSealer("k1")
	m := openTestWith(t, WithOrigin("hub-a"))
	m.SetAuditSealer(sealer)
	appendN(ctx, t, m, 0, 5)
	all := auditMutations(ctx, t, m)

	sh := &fakeShards{self: "a", members: map[string]*Store{}, key: func(string) string { return "a" }}
	a := openTestWith(t, WithShards(sh), WithOrigin("hub-a"))
	a.SetAuditSealer(sealer)
	b := openTestWith(t, WithDigest(), WithOrigin("storage-b"))
	sh.members["a"], sh.members["b"] = a, b
	// Entries 1, 2 and 5 on a; 3 and 4 on b, which hides 4.
	if err := a.Merge(ctx, []Mutation{all[0], all[1], all[4]}); err != nil {
		t.Fatal(err)
	}
	if err := b.Merge(ctx, []Mutation{all[2]}); err != nil {
		t.Fatal(err)
	}
	rep := verify(ctx, t, a)
	c := chainOf(t, rep, "hub-a")
	if c.Verified != 4 || !reflect.DeepEqual(c.Missing, []AuditRange{{From: 4, To: 4}}) {
		t.Fatalf("chain = %+v, want 4 missing", c)
	}
	es, err := a.Audit().List(ctx, 10)
	if err != nil || len(es) != 4 {
		t.Fatalf("List = %v, %v", es, err)
	}
	for _, e := range es {
		if e.Verification != AuditVerified || e.Cursor == "" {
			t.Errorf("%s: %s, cursor %q", e.Action, e.Verification, e.Cursor)
		}
	}
}

// BenchmarkAuditAppendSealed is BenchmarkAuditAppend with a sealer: an
// HMAC more per append, and the chain read from the log once.
func BenchmarkAuditAppendSealed(b *testing.B) {
	ctx := b.Context()
	s := openBench(b)
	s.SetAuditSealer(newTestSealer("k1"))
	e := AuditEntry{TS: time.Now(), ActorKind: "agent", ActorID: "pi", Action: "agent.heartbeat", Decision: "allow"}
	b.ResetTimer()
	for range b.N {
		if _, err := s.Audit().Append(ctx, e); err != nil {
			b.Fatal(err)
		}
	}
}
