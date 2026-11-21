// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/store"
)

// TestSessionMissedByAReplica: a session a replica missed (its write was
// hinted to it while it was, or seemed, down, and not delivered yet) is
// still valid on every master: the replica asked first has no row of it,
// so the others are asked.
func TestSessionMissedByAReplica(t *testing.T) {
	ctx := t.Context()
	c := newAPTestCluster(t, 2,
		apSpec{"a", storageMaster, storageMaster},
		apSpec{"b", storageMaster, storageMaster},
		apSpec{"c", storageMaster, storageMaster},
	)
	secrets := createSessions(t, c["a"], 200)
	// b missed every write.
	if _, err := c["b"].st.DropShardRows(ctx); err != nil {
		t.Fatal(err)
	}
	if n := lacking(t, c["b"], secrets); n == 0 {
		t.Fatal("b lacks no session: the test needs some")
	}
	for _, id := range []string{"a", "b", "c"} {
		for _, s := range secrets {
			if _, err := c[id].st.Admin().CheckSession(ctx, s, time.Now()); err != nil {
				t.Fatalf("session %s on %s: %v", s, id, err)
			}
		}
	}
}

// TestSessionTombstoneIsAnAnswer: a replica with the tombstone of a session
// (signed out) answers: the session is not brought back from a replica that
// missed the sign-out.
func TestSessionTombstoneIsAnAnswer(t *testing.T) {
	ctx := t.Context()
	c := newAPTestCluster(t, 2,
		apSpec{"a", storageMaster, storageMaster},
		apSpec{"b", storageMaster, storageMaster},
		apSpec{"c", storageMaster, storageMaster},
	)
	secrets := createSessions(t, c["a"], 60)
	refs := make([]store.RowRef, len(secrets))
	for i, s := range secrets {
		h := sha256.Sum256([]byte(s))
		refs[i] = store.RowRef{Table: "sessions", Key: store.Values{h[:]}}
	}
	live, err := c["b"].st.ReadRows(ctx, refs)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range secrets {
		if err := c["a"].st.Admin().DeleteSession(ctx, s); err != nil {
			t.Fatal(err)
		}
	}
	// b missed the sign-outs: it has the sessions live.
	if _, err := c["b"].st.DropShardRows(ctx); err != nil {
		t.Fatal(err)
	}
	if err := c["b"].st.Merge(ctx, live); err != nil {
		t.Fatal(err)
	}
	ring := c["a"].node.Replicator().view().ring
	checked := 0
	for _, id := range []string{"a", "c"} {
		for _, s := range secrets {
			h := sha256.Sum256([]byte(s))
			owners := ring.Owners(store.BucketOf(store.Token(hex.EncodeToString(h[:]))), 2)
			if !slices.Contains(owners, id) || !slices.Contains(owners, "b") {
				continue
			}
			checked++
			if _, err := c[id].st.Admin().CheckSession(ctx, s, time.Now()); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("signed-out session %s on %s: err = %v, want not found", s, id, err)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no session shared by b and another owner: the test needs some")
	}
}

// createSessions creates n sessions on tn and returns their secrets.
func createSessions(t *testing.T, tn *apTestNode, n int) []string {
	t.Helper()
	now := time.Now()
	secrets := make([]string, n)
	for i := range secrets {
		secrets[i] = fmt.Sprintf("session-%03d", i)
		if err := tn.st.Admin().CreateSession(t.Context(), secrets[i], now, now.Add(time.Hour)); err != nil {
			t.Fatalf("session %d: %v", i, err)
		}
	}
	return secrets
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
