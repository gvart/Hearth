// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/hashicorp/raft"

	"github.com/gvart/hearth/internal/store"
)

func entry(t *testing.T, idx uint64, cmd store.Command) *raft.Log {
	t.Helper()
	b, err := store.EncodeCommand(cmd)
	if err != nil {
		t.Fatal(err)
	}
	return &raft.Log{Index: idx, Type: raft.LogCommand, Data: b}
}

func TestFSMDomainErrorsGoToTheProposer(t *testing.T) {
	st, err := store.Open(t.Context(), filepath.Join(t.TempDir(), "hearth.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	var fatal []error
	f := newFSM(st, t.TempDir(), testLogger(t), func(err error) { fatal = append(fatal, err) }, nil)

	resp := f.Apply(entry(t, 1, store.MarkSeen{ID: "ghost", Now: 1})).(applyResponse)
	if !errors.Is(resp.err, store.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", resp.err)
	}
	resp = f.Apply(entry(t, 2, store.ConsumeJoinToken{Hash: []byte{1}, Now: 1})).(applyResponse)
	if !errors.Is(resp.err, store.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", resp.err)
	}
	if len(fatal) != 0 {
		t.Fatalf("domain errors halted the state machine: %v", fatal)
	}
	if _, err := f.Snapshot(); err != nil {
		t.Fatalf("snapshot after domain errors: %v", err)
	}
}

func TestFSMHaltsOnNodeFailure(t *testing.T) {
	cases := map[string]func(t *testing.T, st *store.Store) *raft.Log{
		"database gone": func(t *testing.T, st *store.Store) *raft.Log {
			_ = st.Close()
			return entry(t, 1, store.MarkSeen{ID: "pi", Now: 1})
		},
		// A hub whose binary is older than the schema the cluster migrates
		// to (the leader checks first; this is the backstop).
		"migrate past the binary": func(t *testing.T, _ *store.Store) *raft.Log {
			return entry(t, 1, store.MigrateSchema{To: store.SchemaVersion() + 1})
		},
		"undecodable entry": func(*testing.T, *store.Store) *raft.Log {
			return &raft.Log{Index: 1, Type: raft.LogCommand, Data: []byte(`{"v":9,"op":"from_the_future","cmd":{}}`)}
		},
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			st, err := store.Open(t.Context(), filepath.Join(t.TempDir(), "hearth.db"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = st.Close() })
			var fatal []error
			f := newFSM(st, t.TempDir(), testLogger(t), func(err error) { fatal = append(fatal, err) }, nil)

			resp := f.Apply(setup(t, st)).(applyResponse)
			if !errors.Is(resp.err, ErrHalted) {
				t.Fatalf("err = %v, want ErrHalted", resp.err)
			}
			if len(fatal) != 1 || !errors.Is(fatal[0], ErrHalted) {
				t.Fatalf("OnFatal calls = %v, want one ErrHalted", fatal)
			}
			// Halted for good: later entries are refused, OnFatal is not
			// called again, and no snapshot claims a state it does not have.
			resp = f.Apply(entry(t, 2, store.MarkOffline{Cutoff: 1})).(applyResponse)
			if !errors.Is(resp.err, ErrHalted) {
				t.Fatalf("next apply err = %v, want ErrHalted", resp.err)
			}
			if len(fatal) != 1 {
				t.Fatalf("OnFatal called %d times", len(fatal))
			}
			if _, err := f.Snapshot(); !errors.Is(err, ErrHalted) {
				t.Fatalf("snapshot err = %v, want ErrHalted", err)
			}
		})
	}
}

func TestFollowerFailureHaltsOnlyThatNode(t *testing.T) {
	nodes := threeNodes(t, newTestCA(t))
	leader := leaderOf(t, nodes...)
	var broken *testNode
	for _, n := range nodes {
		if n != leader {
			broken = n
			break
		}
	}
	_ = broken.st.Close() // the follower's disk "fails"
	upsert(t, leader, "pi")
	select {
	case err := <-broken.fatal:
		if !errors.Is(err, ErrHalted) {
			t.Fatalf("OnFatal(%v), want ErrHalted", err)
		}
	case <-time.After(waitFor):
		t.Fatal("follower never reported its failure")
	}
	for _, n := range nodes {
		if n != broken {
			eventually(t, "pi on "+n.ID(), func() bool { return hasDevice(n, "pi") })
		}
	}
}
