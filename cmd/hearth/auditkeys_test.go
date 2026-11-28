// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/pki"
	"github.com/gvart/hearth/internal/store"
)

// A hub CA rotation run through its finish keeps the audit entries sealed
// before it verifiable: the old CA's audit key is stored sealed, re-sealed
// with the new CA's key with the other secrets, and opened again by a master
// started after the finish, which never held the old CA key.
func TestAuditKeysSurviveARotation(t *testing.T) {
	ctx := t.Context()
	now := time.Now()
	ca, err := pki.LoadOrCreateCA(t.TempDir(), now)
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.DiscardHandler)
	sealers, err := newHubSealers(ctx, ca, log)
	if err != nil {
		t.Fatal(err)
	}
	ring, err := pki.NewAuditKeyring(ca)
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), dbFile), store.WithOrigin("hub-a"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	st.SetAuditSealer(ring)
	if _, err := st.Audit().Append(ctx, store.AuditEntry{ActorKind: "admin", ActorID: "root", Action: "before", Decision: "allow"}); err != nil {
		t.Fatal(err)
	}
	if err := syncAuditKeys(ctx, st, ring, sealers.audit, now); err != nil {
		t.Fatal(err)
	}
	keys, err := st.AuditKeys().List(ctx)
	if err != nil || len(keys) != 1 || keys[0].ID != pki.AuditKeyID(ca.Cert()) {
		t.Fatalf("stored audit keys = %v, %v; want the CA's", keys, err)
	}

	next, err := ca.GenerateNext(now)
	if err != nil {
		t.Fatal(err)
	}
	if err := ca.TrustNext(next); err != nil {
		t.Fatal(err)
	}
	if err := ca.Cutover(); err != nil {
		t.Fatal(err)
	}
	// The secrets the finish re-seals, the audit key among them.
	secrets, err := st.CARotations().Sealed(ctx)
	if err != nil {
		t.Fatal(err)
	}
	resealed, err := sealers.reseal(ctx, secrets)
	if err != nil {
		t.Fatal(err)
	}
	var audit *store.SealedSecret
	for i := range resealed {
		if resealed[i].Table == store.SealedAuditKeys {
			audit = &resealed[i]
		}
	}
	if audit == nil {
		t.Fatalf("the audit key was not re-sealed: %+v", resealed)
	}
	if err := ca.Finish(); err != nil {
		t.Fatal(err)
	}

	// A master started after the finish, with the re-sealed copy.
	st2, err := store.Open(ctx, filepath.Join(t.TempDir(), dbFile), store.WithOrigin("hub-b"))
	if err != nil {
		t.Fatal(err)
	}
	defer st2.Close()
	if err := st2.AuditKeys().Put(ctx, audit.ID, audit.Resealed, now); err != nil {
		t.Fatal(err)
	}
	sealers2, err := newHubSealers(ctx, ca, log)
	if err != nil {
		t.Fatal(err)
	}
	ring2, err := pki.NewAuditKeyring(ca)
	if err != nil {
		t.Fatal(err)
	}
	st2.SetAuditSealer(ring2)
	if err := st2.Merge(ctx, auditRows(ctx, t, st)); err != nil {
		t.Fatal(err)
	}
	if v := entryVerification(ctx, t, st2, "before"); v != store.AuditUnverified {
		t.Fatalf("before the sync: %s, want unverified (key unknown)", v)
	}
	if err := syncAuditKeys(ctx, st2, ring2, sealers2.audit, now); err != nil {
		t.Fatal(err)
	}
	if v := entryVerification(ctx, t, st2, "before"); v != store.AuditVerified {
		t.Fatalf("after the sync: %s, want verified", v)
	}
	// It stored the new CA's key too, and seals with it.
	if keys, err := st2.AuditKeys().List(ctx); err != nil || len(keys) != 2 {
		t.Fatalf("stored audit keys = %v, %v; want the old and the new", keys, err)
	}
	if _, err := st2.Audit().Append(ctx, store.AuditEntry{ActorKind: "admin", ActorID: "root", Action: "after", Decision: "allow"}); err != nil {
		t.Fatal(err)
	}
	if v := entryVerification(ctx, t, st2, "after"); v != store.AuditVerified {
		t.Fatalf("an entry after the rotation: %s", v)
	}
}

func entryVerification(ctx context.Context, t *testing.T, st *store.Store, action string) string {
	t.Helper()
	es, err := st.Audit().Query(ctx, store.AuditFilter{Actions: []string{action}}, 10)
	if err != nil || len(es) != 1 {
		t.Fatalf("Query %s = %v, %v", action, es, err)
	}
	return es[0].Verification
}

// auditRows returns st's audit entries as replication carries them.
func auditRows(ctx context.Context, t *testing.T, st *store.Store) []store.Mutation {
	t.Helper()
	refs, err := st.BucketRows(ctx, store.SpaceShard, func(int) bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	var want []store.RowRef
	for _, r := range refs {
		if r.Table == "audit_log" {
			want = append(want, r.RowRef)
		}
	}
	muts, err := st.ReadRows(ctx, want)
	if err != nil || len(muts) == 0 {
		t.Fatalf("ReadRows = %v, %v", muts, err)
	}
	return muts
}

// An admin command run on a master's host seals its audit entries, in a
// chain of its own: a backup or a token made there does not read as forged.
func TestAdminCommandsSealTheirAudit(t *testing.T) {
	t.Setenv(passphraseEnv, testBackupPassphrase)
	dir, ca := initHub(t)
	for range 2 {
		if _, err := execute(t, "token", "create", "--data-dir", dir); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := execute(t, "backup", filepath.Join(t.TempDir(), "hub.hbk"), "--data-dir", dir); err != nil {
		t.Fatal(err)
	}
	st := openStore(t, dir)
	ring, err := pki.NewAuditKeyring(ca)
	if err != nil {
		t.Fatal(err)
	}
	st.SetAuditSealer(ring)
	rep, err := st.Audit().Verify(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK() || rep.Unsealed != 0 || len(rep.Chains) != 3 {
		t.Errorf("verify = %+v, want three sealed chains, one per command", rep)
	}
}
