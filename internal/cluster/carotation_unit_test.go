// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/store"
)

// A temporary file a crash left, readable by anyone, does not keep its mode:
// the key is written to a new one.
func TestWriteFileSyncReplacesStaleTemp(t *testing.T) {
	path := filepath.Join(t.TempDir(), "node.next.key")
	if err := os.WriteFile(path+".tmp", []byte("stale"), 0o644); err != nil { //nolint:gosec // a test temp dir
		t.Fatal(err)
	}
	if err := writeFileSync(path, []byte("key"), 0o600); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("mode %v, want 0600", fi.Mode().Perm())
	}
	if b, _ := os.ReadFile(path); string(b) != "key" {
		t.Errorf("content %q", b)
	}
}

// Refused CA key fetches get one audit entry per caller a minute, and the
// next one counts those left out.
func TestFetchRefusalsAuditedOncePerMinute(t *testing.T) {
	st, err := store.Open(t.Context(), filepath.Join(t.TempDir(), "hub.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	now := time.Now()
	s := &JoinServer{store: st, log: testLogger(t), now: func() time.Time { return now }}
	refusal := errors.New("not pinned")
	for range 3 {
		s.auditFetchRefused(t.Context(), refusal)
	}
	entries := func() []store.AuditEntry {
		t.Helper()
		es, err := st.Audit().List(t.Context(), 100)
		if err != nil {
			t.Fatal(err)
		}
		return es
	}
	if es := entries(); len(es) != 1 {
		t.Fatalf("3 refusals within a minute made %d audit entries, want 1", len(es))
	}
	now = now.Add(fetchRefusalEvery)
	s.auditFetchRefused(t.Context(), refusal)
	es := entries()
	if len(es) != 2 {
		t.Fatalf("a refusal a minute later made %d audit entries in all, want 2", len(es))
	}
	var detail map[string]any
	for _, e := range es {
		if err := json.Unmarshal(e.Detail, &detail); err != nil {
			t.Fatal(err)
		}
		if n, ok := detail["refusals_not_audited_before"]; ok && n != float64(2) {
			t.Errorf("the entry counts %v refusals left out, want 2", n)
		} else if ok {
			return
		}
	}
	t.Error("no entry counts the refusals left out")
}

// During a rotation the Raft transport refuses an old-CA hub certificate it
// cannot check against its pin, and still accepts a new-CA one.
func TestRefuseRevokedFailsClosedInRotation(t *testing.T) {
	ca := newTestCA(t)
	st, err := store.Open(t.Context(), filepath.Join(t.TempDir(), "hub.db"))
	if err != nil {
		t.Fatal(err)
	}
	oldPeer, err := loadOrIssueNodeCert(t.TempDir(), ca, "peer", epochA, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	n := &Node{store: st, epoch: epochA, cfg: Config{CA: ca}}
	n.log = testLogger(t)
	_ = st.Close() // every read fails from here on
	if err := n.refuseRevoked(oldPeer.Leaf); err != nil {
		t.Fatalf("outside a rotation a read error refused the peer: %v", err)
	}
	if _, err := ca.GenerateNext(time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := n.refuseRevoked(oldPeer.Leaf); err == nil {
		t.Error("in a rotation an old-CA peer was accepted without its pin checked")
	}
	newPeer, err := loadOrIssueNodeCert(t.TempDir(), ca, "peer", epochA, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := n.refuseRevoked(newPeer.Leaf); err != nil {
		t.Errorf("a new-CA peer was refused on a read error: %v", err)
	}
}
