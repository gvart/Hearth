// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import (
	"context"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"runtime/pprof"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/raft"

	"github.com/gvart/hearth/internal/pki"
	"github.com/gvart/hearth/internal/store"
)

const waitFor = 15 * time.Second

func testLogger(t *testing.T) *slog.Logger {
	t.Helper()
	if os.Getenv("HEARTH_TEST_RAFT_LOG") != "" {
		return slog.New(slog.NewTextHandler(os.Stderr, nil)).With("test", t.Name())
	}
	return slog.New(slog.DiscardHandler)
}

func newTestCA(t *testing.T) *pki.CA {
	t.Helper()
	ca, err := pki.LoadOrCreateCA(filepath.Join(t.TempDir(), "ca"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return ca
}

type testNode struct {
	*Node
	st    *store.Store
	dir   string
	fatal chan error
	down  bool
	t     *testing.T
}

// fastTimeouts keeps elections in tests well under a second or two.
func fastTimeouts(c *Config) {
	c.HeartbeatTimeout = 400 * time.Millisecond
	c.ElectionTimeout = 400 * time.Millisecond
	c.LeaderLeaseTimeout = 200 * time.Millisecond
}

// freeAddr returns a loopback address with a port that was free a moment ago.
func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

// startNode starts a node with its own data dir. dir may be empty for a new one.
func startNode(t *testing.T, ca *pki.CA, id, dir, addr string, bootstrap bool, tune ...func(*Config)) *testNode {
	t.Helper()
	return startNodeBound(t, ca, id, dir, addr, bootstrap, (*Node).Bind, tune...)
}

// startNodeBound is startNode with the store bound by bind, e.g.
// (*Node).BindForwarding for a hub whose follower writes are forwarded.
func startNodeBound(t *testing.T, ca *pki.CA, id, dir, addr string, bootstrap bool,
	bind func(*Node, *store.Store) store.Applier, tune ...func(*Config),
) *testNode {
	t.Helper()
	if dir == "" {
		dir = t.TempDir()
	}
	if addr == "" {
		addr = "127.0.0.1:0"
	}
	tn := &testNode{dir: dir, fatal: make(chan error, 1), t: t}
	cfg := Config{
		DataDir: dir, NodeID: id, Listen: addr, CA: ca, Bootstrap: bootstrap,
		Log: testLogger(t), OnFatal: func(err error) { tn.fatal <- err },
	}
	fastTimeouts(&cfg)
	for _, f := range tune {
		f(&cfg)
	}
	n, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(t.Context(), filepath.Join(dir, "hearth.db"), store.WithoutUpgrade(),
		store.WithApplier(func(s *store.Store) store.Applier { return bind(n, s) }))
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Start(t.Context()); err != nil {
		_ = st.Close()
		t.Fatalf("Start %s: %v", id, err)
	}
	tn.Node, tn.st = n, st
	t.Cleanup(tn.stop)
	return tn
}

// stop shuts the node down as a crash would look to its peers.
func (tn *testNode) stop() {
	if tn.down {
		return
	}
	tn.down = true
	within(tn.t, "shutdown of "+tn.ID(), func() { _ = tn.Shutdown() })
	_ = tn.st.Close()
}

// within runs fn, and fails the test with every goroutine's stack if fn
// has not returned after waitFor: a hang in teardown then fails fast with
// the culprit instead of eating the package's whole test timeout. fn keeps
// running in the background.
func within(t *testing.T, what string, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn()
	}()
	select {
	case <-done:
	case <-time.After(waitFor):
		var stacks strings.Builder
		_ = pprof.Lookup("goroutine").WriteTo(&stacks, 2)
		t.Errorf("%s did not finish within %v; goroutines:\n%s", what, waitFor, stacks.String())
	}
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(waitFor)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// leaderOf waits until exactly one live node is leader and returns it.
func leaderOf(t *testing.T, nodes ...*testNode) *testNode {
	t.Helper()
	var leader *testNode
	eventually(t, "a leader", func() bool {
		leader = nil
		for _, n := range nodes {
			if n.down || !n.IsLeader() {
				continue
			}
			if leader != nil {
				return false
			}
			leader = n
		}
		return leader != nil
	})
	return leader
}

// addVoter adds n as a voter through leader, as Promote does.
func addVoter(t *testing.T, leader, n *testNode) {
	t.Helper()
	if err := leader.raft.AddVoter(raft.ServerID(n.ID()), raft.ServerAddress(n.Addr()), 0, waitFor).Error(); err != nil {
		t.Fatalf("AddVoter %s: %v", n.ID(), err)
	}
}

// threeNodes forms a 3-voter cluster: n1 bootstraps, n2 and n3 are added.
func threeNodes(t *testing.T, ca *pki.CA, tune ...func(*Config)) []*testNode {
	t.Helper()
	n1 := startNode(t, ca, "n1", "", "", true, tune...)
	leaderOf(t, n1)
	n2 := startNode(t, ca, "n2", "", "", false, tune...)
	n3 := startNode(t, ca, "n3", "", "", false, tune...)
	addVoter(t, n1, n2)
	addVoter(t, n1, n3)
	return []*testNode{n1, n2, n3}
}

func hasDevice(n *testNode, id string) bool {
	_, err := n.st.Devices().Get(context.Background(), id)
	return err == nil
}

func upsert(t *testing.T, n *testNode, id string) {
	t.Helper()
	now := time.Now()
	if err := n.st.Devices().Upsert(t.Context(), store.Device{ID: id, Name: id, FirstSeen: now, LastSeen: now}); err != nil {
		t.Fatalf("upsert %s on %s: %v", id, n.ID(), err)
	}
}
