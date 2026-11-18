// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/store"
)

// serveControl serves n's control socket for its data dir and returns a
// client for it.
func serveControl(t *testing.T, n *testNode) *ControlClient {
	t.Helper()
	dir := n.dir
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- ServeControl(ctx, dir, n.Node, testLogger(t)) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("ServeControl: %v", err)
		}
	})
	eventually(t, "control socket", func() bool {
		_, err := os.Stat(ControlSocketPath(dir))
		return err == nil
	})
	if runtime.GOOS != "windows" {
		info, err := os.Stat(ControlSocketPath(dir))
		if err != nil {
			t.Fatal(err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("control socket mode = %o, want 600", perm)
		}
	}
	c, err := DialControl(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return c
}

func TestControlSocket(t *testing.T) {
	nodes := threeNodes(t, newTestCA(t), func(c *Config) { c.ForwardWait = 300 * time.Millisecond })
	leader := leaderOf(t, nodes...)
	var follower *testNode
	for _, n := range nodes {
		if n != leader {
			follower = n
		}
	}
	eventually(t, "follower to know the leader", func() bool { return follower.Leader().ID != "" })
	ctx := t.Context()

	// A CLI-side store whose writes go through the leader's control socket.
	lc := serveControl(t, leader)
	cli, err := store.Open(ctx, filepath.Join(t.TempDir(), "cli.db"), store.WithApplier(func(*store.Store) store.Applier { return lc }))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cli.Close() })
	if err := cli.JoinTokens().Create(ctx, "j", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("create through the socket: %v", err)
	}
	if err := cli.JoinTokens().Consume(ctx, "j", time.Now()); err != nil {
		t.Fatalf("consume through the socket: %v", err)
	}
	if err := cli.JoinTokens().Consume(ctx, "j", time.Now()); !errors.Is(err, store.ErrTokenUsed) {
		t.Fatalf("second consume: err = %v, want ErrTokenUsed", err)
	}
	if err := leader.st.JoinTokens().Consume(ctx, "j", time.Now()); !errors.Is(err, store.ErrTokenUsed) {
		t.Fatalf("the socket write did not reach the replicated store: %v", err)
	}

	st, err := lc.Status(ctx)
	if err != nil || st.State != "Leader" || st.NodeID != leader.ID() || len(st.Peers) != 3 {
		t.Fatalf("Status = %+v, %v", st, err)
	}

	// On a follower the socket forwards to the leader. These nodes serve no
	// ClusterService (see TestFollowerWritesAreForwarded), so the leader is
	// unreachable and the write fails as unavailable, in bounded time.
	fc := serveControl(t, follower)
	_, err = fc.Apply(ctx, store.MarkOffline{Cutoff: 1})
	if !errors.Is(err, store.ErrUnavailable) {
		t.Fatalf("follower apply without a reachable leader: err = %v, want ErrUnavailable", err)
	}
}

func TestControlSocketPath(t *testing.T) {
	short := "/var/lib/hearth/hub"
	if got := ControlSocketPath(short); got != filepath.Join(short, ControlSocket) {
		t.Errorf("short data dir: %s", got)
	}
	long := "/" + strings.Repeat("d", 120)
	got := ControlSocketPath(long)
	if !strings.HasPrefix(got, os.TempDir()) || got != ControlSocketPath(long) {
		t.Errorf("long data dir: %s", got)
	}
	if ControlSocketPath(long+"x") == got {
		t.Error("two data dirs share a socket")
	}
}

func TestDialControlWithoutHub(t *testing.T) {
	if _, err := DialControl(t.TempDir()); err == nil {
		t.Fatal("DialControl succeeded with no hub running")
	}
}

// TestControlSocketNeverLoose watches the socket path while ServeControl
// starts: no observer may ever see it with a mode other than 0600 (#103).
func TestControlSocketNeverLoose(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix permissions")
	}
	for range 30 {
		dir := t.TempDir()
		path := ControlSocketPath(dir)
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan error, 1)
		go func() { done <- ServeControl(ctx, dir, nil, testLogger(t)) }()
		for {
			info, err := os.Lstat(path)
			if err != nil {
				continue
			}
			if perm := info.Mode().Perm(); perm != 0o600 {
				t.Errorf("control socket seen with mode %o, want 600", perm)
			}
			break
		}
		cancel()
		if err := <-done; err != nil {
			t.Fatalf("ServeControl: %v", err)
		}
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("socket left behind after shutdown: %v", err)
		}
		if t.Failed() {
			return
		}
	}
}
