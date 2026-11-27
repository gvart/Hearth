// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/store"
)

// Sign-in sessions live on masters only (#384): every master holds every
// session and checks one on its own copy.

// TestSessionsOnEveryMaster: a session created on one master is on every
// master, valid there, and on no storage-only member.
func TestSessionsOnEveryMaster(t *testing.T) {
	ctx := t.Context()
	c := newAPTestCluster(t, 2,
		apSpec{"a", storageMaster, storageMaster},
		apSpec{"b", storageMaster, storageMaster},
		apSpec{"c", storageMaster, storageMaster},
		apSpec{"d", storageOnly, storageOnly},
	)
	secrets := createSessions(t, c["a"], 50)
	for _, id := range []string{"a", "b", "c"} {
		if n := lacking(t, c[id], secrets); n != 0 {
			t.Fatalf("master %s lacks %d sessions", id, n)
		}
		for _, s := range secrets {
			if _, err := c[id].st.Admin().CheckSession(ctx, s, time.Now()); err != nil {
				t.Fatalf("session %s on %s: %v", s, id, err)
			}
		}
	}
	if n := lacking(t, c["d"], secrets); n != len(secrets) {
		t.Fatalf("storage-only d holds %d sessions, want none", len(secrets)-n)
	}
	// A backup on a master that lost its copies pulls them from the other
	// masters; one on storage-only d, which holds none, is refused.
	if _, err := c["a"].st.DropMasterRows(ctx); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(c["a"].dir, "backup.db")
	if err := c["a"].node.Snapshot(ctx, path); err != nil {
		t.Fatal(err)
	}
	copied, err := store.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range secrets {
		if _, err := copied.Admin().CheckSession(ctx, s, time.Now()); err != nil {
			t.Fatalf("session %s in a's backup: %v", s, err)
		}
	}
	if err := copied.Close(); err != nil {
		t.Fatal(err)
	}
	if err := c["d"].node.Snapshot(ctx, filepath.Join(c["d"].dir, "backup.db")); err == nil {
		t.Fatal("a backup on storage-only d was taken")
	}
	// A sign-out on another master ends it on every master.
	for _, s := range secrets {
		if err := c["b"].st.Admin().DeleteSession(ctx, s); err != nil {
			t.Fatal(err)
		}
	}
	for _, id := range []string{"a", "b", "c"} {
		for _, s := range secrets {
			if _, err := c[id].st.Admin().CheckSession(ctx, s, time.Now()); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("signed-out session %s on %s: err = %v, want not found", s, id, err)
			}
		}
	}
}

// TestPasswordResetEndsSessionsAMasterMissed: a password reset on a master
// that missed a session (its write still in a hint) ends it on every master:
// the resetting master reads the other masters' sessions first.
func TestPasswordResetEndsSessionsAMasterMissed(t *testing.T) {
	ctx := t.Context()
	c := newAPTestCluster(t, 2,
		apSpec{"a", storageMaster, storageMaster},
		apSpec{"b", storageMaster, storageMaster},
		apSpec{"c", storageMaster, storageMaster},
	)
	secrets := createSessions(t, c["a"], 20)
	if _, err := c["c"].st.DropMasterRows(ctx, "sessions"); err != nil {
		t.Fatal(err)
	}
	if n := lacking(t, c["c"], secrets); n != len(secrets) {
		t.Fatalf("c still holds %d sessions", len(secrets)-n)
	}
	if err := c["c"].st.Admin().SetPasswordHash(ctx, "new-hash"); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"a", "b", "c"} {
		for _, s := range secrets {
			if _, err := c[id].st.Admin().CheckSession(ctx, s, time.Now()); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("session %s on %s after the reset: err = %v, want not found", s, id, err)
			}
		}
	}
}

// TestSignInSurvivesAMasterKilled: with one of three masters killed, the
// other two still sign in, and still take the sessions created before.
func TestSignInSurvivesAMasterKilled(t *testing.T) {
	ctx := t.Context()
	c := newAPTestCluster(t, 2,
		apSpec{"a", storageMaster, storageMaster},
		apSpec{"b", storageMaster, storageMaster},
		apSpec{"c", storageMaster, storageMaster},
	)
	before := createSessions(t, c["c"], 5)
	c["c"].stop()
	now := time.Now()
	for _, id := range []string{"a", "b"} {
		secret := "after-" + id
		waitUntil(t, 10*time.Second, "a sign-in on "+id, func() bool {
			return c[id].st.Admin().CreateSession(ctx, secret, now, now.Add(time.Hour)) == nil
		})
		for _, on := range []string{"a", "b"} {
			waitUntil(t, 5*time.Second, secret+" valid on "+on, func() bool {
				_, err := c[on].st.Admin().CheckSession(ctx, secret, time.Now())
				return err == nil
			})
		}
		for _, s := range before {
			if _, err := c[id].st.Admin().CheckSession(ctx, s, time.Now()); err != nil {
				t.Fatalf("session %s from before the kill on %s: %v", s, id, err)
			}
		}
	}
}

// TestMasterRowsFollowTheRole: a storage member promoted to master pulls the
// sessions from the masters; a master demoted deletes its copies; a member
// without the hub CA key deletes any it holds when it starts.
func TestMasterRowsFollowTheRole(t *testing.T) {
	ctx := t.Context()
	c := newAPTestCluster(t, 2,
		apSpec{"a", storageMaster, storageMaster},
		apSpec{"b", storageMaster, storageMaster},
		apSpec{"c", storageOnly, storageMaster},
	)
	secrets := createSessions(t, c["a"], 20)
	if n := lacking(t, c["c"], secrets); n != len(secrets) {
		t.Fatalf("storage-only c holds %d sessions", len(secrets)-n)
	}

	if _, err := c["a"].node.Promote(ctx, "c", RoleMaster); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, 10*time.Second, "c, promoted, to hold every session", func() bool {
		return lacking(t, c["c"], secrets) == 0
	})
	for _, s := range secrets {
		if _, err := c["c"].st.Admin().CheckSession(ctx, s, time.Now()); err != nil {
			t.Fatalf("session %s on c: %v", s, err)
		}
	}

	if _, err := c["a"].node.Demote(ctx, "b", RoleMaster); err != nil {
		t.Fatal(err)
	}
	if n := lacking(t, c["b"], secrets); n != len(secrets) {
		t.Fatalf("demoted b holds %d sessions", len(secrets)-n)
	}
	for _, id := range []string{"a", "c"} {
		for _, s := range secrets {
			if _, err := c[id].st.Admin().CheckSession(ctx, s, time.Now()); err != nil {
				t.Fatalf("session %s on %s after b's demotion: %v", s, id, err)
			}
		}
	}

	// b, a storage-only member now, is handed the rows of a session while it
	// is down; it deletes them as it starts.
	rows := sessionRows(t, c["a"], secrets)
	b := c["b"]
	b.stop()
	st, err := store.Open(ctx, b.dir+"/hearth.db", store.WithDigest())
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Merge(ctx, rows); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	b.start(t, 2, c["a"].addr)
	if n := lacking(t, b, secrets); n != len(secrets) {
		t.Fatalf("b holds %d sessions after its start", len(secrets)-n)
	}
}

// createSessions creates n sessions on tn and returns their secrets.
func createSessions(t *testing.T, tn *apTestNode, n int) []string {
	t.Helper()
	now := time.Now()
	secrets := make([]string, n)
	for i := range secrets {
		secrets[i] = fmt.Sprintf("session-%s-%03d", tn.id, i)
		if err := tn.st.Admin().CreateSession(t.Context(), secrets[i], now, now.Add(time.Hour)); err != nil {
			t.Fatalf("session %d: %v", i, err)
		}
	}
	return secrets
}

// sessionRows reads the rows of the sessions of secrets on tn.
func sessionRows(t *testing.T, tn *apTestNode, secrets []string) []store.Mutation {
	t.Helper()
	refs := make([]store.RowRef, len(secrets))
	for i, s := range secrets {
		h := sha256.Sum256([]byte(s))
		refs[i] = store.RowRef{Table: "sessions", Key: store.Values{h[:]}}
	}
	rows, err := tn.st.ReadRows(t.Context(), refs)
	if err != nil || len(rows) != len(secrets) {
		t.Fatalf("read the sessions on %s: %d rows, %v", tn.id, len(rows), err)
	}
	return rows
}

// lacking counts the sessions of secrets tn's own database has no row of.
func lacking(t *testing.T, tn *apTestNode, secrets []string) int {
	t.Helper()
	n := 0
	for _, s := range secrets {
		h := sha256.Sum256([]byte(s))
		rows, err := tn.st.ReadLocal(t.Context(), `SELECT 1 FROM sessions WHERE hash = ?`, store.Values{h[:]})
		if err != nil {
			t.Fatal(err)
		}
		if len(rows.Vals) == 0 {
			n++
		}
	}
	return n
}
