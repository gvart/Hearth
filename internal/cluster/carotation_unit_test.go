// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import (
	"encoding/json"
	"errors"
	"fmt"
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
	s := &APJoinServer{store: st, log: testLogger(t), now: func() time.Time { return now }}
	refusal := errors.New("not pinned")
	for range 3 {
		s.auditFetchRefused(t.Context(), refusal, false)
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
	s.auditFetchRefused(t.Context(), refusal, false)
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

// Callers that pick a new node ID for each refusal still get no more than
// fetchRefusalBurst audit entries a minute in all, and the next entry counts
// what was left out.
func TestFetchRefusalsBoundedOverCallers(t *testing.T) {
	var f fetchRefusals
	now := time.Now()
	admitted := 0
	for i := range 1000 {
		if ok, _ := f.admit(fmt.Sprintf("forged-%d", i), now); ok {
			admitted++
		}
	}
	if admitted != fetchRefusalBurst {
		t.Errorf("%d refusals of distinct callers admitted in a minute, want %d", admitted, fetchRefusalBurst)
	}
	if len(f.last) > fetchRefusalCallers {
		t.Errorf("%d callers remembered, want at most %d", len(f.last), fetchRefusalCallers)
	}
	ok, suppressed := f.admit("forged-again", now.Add(fetchRefusalEvery))
	if !ok || suppressed != 1000-fetchRefusalBurst {
		t.Errorf("the next minute: admitted %v, counting %d left out; want true, %d", ok, suppressed, 1000-fetchRefusalBurst)
	}
}
