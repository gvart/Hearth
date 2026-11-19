// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/backup"
	"github.com/gvart/hearth/internal/cluster"
	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

func clusterStatusOf(t *testing.T, dir string) (cluster.Status, bool) {
	t.Helper()
	out, err := execute(t, "cluster", "status", "--json", "--data-dir", dir)
	if err != nil {
		return cluster.Status{}, false
	}
	var s cluster.Status
	return s, json.Unmarshal([]byte(out), &s) == nil
}

func voters(s cluster.Status) int {
	n := 0
	for _, p := range s.Peers {
		if p.Suffrage == "Voter" {
			n++
		}
	}
	return n
}

// clusterHub is one hub of a test cluster.
type clusterHub struct {
	dir, listen, raft string
	opts              hubOptions
	stop              func()
}

func newClusterHub(t *testing.T, nodeID string) *clusterHub {
	t.Helper()
	h := &clusterHub{dir: t.TempDir(), listen: freeAddr(t), raft: freeAddr(t)}
	h.opts = hubOptions{
		dataDir: h.dir, listen: h.listen, httpListen: freeAddr(t), hosts: []string{"127.0.0.1"},
		cluster: clusterOptions{nodeID: nodeID, raftListen: h.raft, advertise: h.raft},
	}
	return h
}

// joinVia joins h to the cluster of leader and waits until wantVoters hubs vote.
func (h *clusterHub) joinVia(t *testing.T, leader *clusterHub, wantVoters int) {
	t.Helper()
	out, err := execute(t, "cluster", "token", "create", "--data-dir", leader.dir, "--hub-url", "https://"+leader.listen)
	if err != nil {
		t.Fatal(err)
	}
	token := regexp.MustCompile(`hearthj1\.\S+`).FindString(out)
	if token == "" {
		t.Fatalf("no join token in %q", out)
	}
	h.opts.cluster.join, h.opts.cluster.joinToken = "https://"+leader.listen, token
	h.stop = runBackupTestHub(t, h.opts)
	waitFor(t, h.opts.cluster.nodeID+" to become a voter", 60*time.Second, func() bool {
		s, ok := clusterStatusOf(t, leader.dir)
		return ok && voters(s) == wantVoters
	})
}

func auditCount(t *testing.T, dir string, action policy.Action) int {
	t.Helper()
	st, err := store.Open(t.Context(), filepath.Join(dir, dbFile), store.WithoutUpgrade())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	entries, err := st.Audit().Query(t.Context(), store.AuditFilter{Actions: []string{string(action)}}, 100)
	if err != nil {
		t.Fatal(err)
	}
	return len(entries)
}

// TestRestoredHubIsNotAbsorbedByHubsThatJoinedAfterTheBackup: hub-b and hub-c
// are unknown to the backup and still running. The restored hub-a, back at its
// old Raft address, must not follow them or take their log.
func TestRestoredHubIsNotAbsorbedByHubsThatJoinedAfterTheBackup(t *testing.T) {
	t.Setenv(passphraseEnv, testBackupPassphrase)
	a := newClusterHub(t, "hub-a")
	a.opts.cluster.form = true
	a.stop = runBackupTestHub(t, a.opts)
	waitFor(t, "hub-a to lead", 30*time.Second, func() bool {
		s, ok := clusterStatusOf(t, a.dir)
		return ok && s.LeaderID == "hub-a"
	})
	file := filepath.Join(t.TempDir(), "hub-a.hbk")
	if _, err := execute(t, "backup", file, "--data-dir", a.dir); err != nil {
		t.Fatal(err)
	}

	b, c := newClusterHub(t, "hub-b"), newClusterHub(t, "hub-c")
	b.joinVia(t, a, 2)
	c.joinVia(t, a, 3)
	// A write the backup does not hold: it must not reach the restored hub.
	if _, err := execute(t, "token", "create", "--data-dir", a.dir, "--hub-url", "https://"+a.listen); err != nil {
		t.Fatal(err)
	}

	a.stop()
	restored := filepath.Join(t.TempDir(), "restored")
	if _, err := execute(t, "restore", file, "--data-dir", restored); err != nil {
		t.Fatal(err)
	}
	a.opts.dataDir = restored
	a.stop = runBackupTestHub(t, a.opts)
	waitFor(t, "the restored hub to lead its own cluster", 30*time.Second, func() bool {
		s, ok := clusterStatusOf(t, restored)
		return ok && s.LeaderID == "hub-a"
	})
	// Long enough for hub-b and hub-c to elect a leader and reach hub-a.
	for deadline := time.Now().Add(12 * time.Second); time.Now().Before(deadline); time.Sleep(500 * time.Millisecond) {
		if s, ok := clusterStatusOf(t, restored); ok && (s.LeaderID != "hub-a" || len(s.Peers) != 1) {
			t.Fatalf("the restored hub was absorbed: leader %q, peers %+v", s.LeaderID, s.Peers)
		}
	}
	if n := auditCount(t, restored, policy.TokenCreate); n != 0 {
		t.Fatalf("the old cluster's log reached the restored database: %d token.create entries", n)
	}

	// The old hubs go away, and a new hub joins the restored one.
	c.stop()
	b.stop()
	d := newClusterHub(t, "hub-d")
	restoredHub := &clusterHub{dir: restored, listen: a.listen}
	d.joinVia(t, restoredHub, 2)
	// A write on the follower proves the hub-to-hub calls work both ways.
	if _, err := execute(t, "token", "create", "--data-dir", d.dir, "--hub-url", "https://"+a.listen); err != nil {
		t.Fatalf("forwarded write from the rejoined hub: %v", err)
	}
	// It comes back after a restart, with the certificate it was given.
	d.stop()
	d.opts.cluster.join, d.opts.cluster.joinToken = "", ""
	d.stop = runBackupTestHub(t, d.opts)
	waitFor(t, "hub-d to catch up after a restart", 30*time.Second, func() bool {
		s, ok := clusterStatusOf(t, d.dir)
		return ok && s.LeaderID == "hub-a" && voters(s) == 2
	})
}

func TestHubStartRemovesAbandonedTempDirs(t *testing.T) {
	dir := t.TempDir()
	cmd := exec.Command(os.Args[0], "-test.run=^$") //nolint:gosec // this test binary
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	stale := filepath.Join(dir, fmt.Sprintf(".snapshot-%d-abc", cmd.Process.Pid))
	if err := os.MkdirAll(stale, 0o700); err != nil { //nolint:gosec // a path under t.TempDir
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stale, "snapshot.db"), []byte("plaintext"), 0o600); err != nil { //nolint:gosec // a path under t.TempDir
		t.Fatal(err)
	}
	listen := freeAddr(t)
	runBackupTestHub(t, hubOptions{dataDir: dir, listen: listen, httpListen: freeAddr(t), hosts: []string{"127.0.0.1"}})
	waitFor(t, "the hub to listen", 10*time.Second, func() bool {
		var d net.Dialer
		c, err := d.DialContext(t.Context(), "tcp", listen)
		if err == nil {
			_ = c.Close()
		}
		return err == nil
	})
	if _, err := os.Stat(stale); !os.IsNotExist(err) { //nolint:gosec // a path under t.TempDir
		t.Errorf("the abandoned snapshot is still there: %v", err)
	}
}

func TestHubRefusesARestoreStoppedMidCommit(t *testing.T) {
	dir := t.TempDir()
	cmd := exec.Command(os.Args[0], "-test.run=^$") //nolint:gosec // this test binary
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, fmt.Sprintf(".restore-%d-abc", cmd.Process.Pid)), 0o700); err != nil { //nolint:gosec // a path under t.TempDir
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ca.crt"), []byte("moved already"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := runHub(t.Context(), hubOptions{dataDir: dir, listen: "127.0.0.1:0", httpListen: "127.0.0.1:0"}, slog.New(slog.DiscardHandler))
	if !errors.Is(err, backup.ErrIncompleteRestore) {
		t.Fatalf("runHub = %v, want ErrIncompleteRestore", err)
	}
}
