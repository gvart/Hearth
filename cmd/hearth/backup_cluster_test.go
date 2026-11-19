// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"encoding/json"
	"errors"
	"log/slog"
	"os"
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
	dir, listen string
	opts        hubOptions
	stop        func()
}

func newClusterHub(t *testing.T, nodeID string) *clusterHub {
	t.Helper()
	h := &clusterHub{dir: t.TempDir()}
	h.opts = testHubOptions(t, h.dir)
	h.opts.cluster = testClusterOptions(t, nodeID)
	h.listen = h.opts.listen
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

// TestRestoredAuditShowsTheBackupAsStarted: the copy is taken after the audit
// log records the action and before it records the outcome.
func TestRestoredAuditShowsTheBackupAsStarted(t *testing.T) {
	t.Setenv(passphraseEnv, testBackupPassphrase)
	dir, _ := initHub(t)
	file := filepath.Join(t.TempDir(), "hub.hbk")
	if _, err := execute(t, "backup", file, "--data-dir", dir); err != nil {
		t.Fatal(err)
	}
	restored := filepath.Join(t.TempDir(), "restored")
	if _, err := execute(t, "restore", file, "--data-dir", restored); err != nil {
		t.Fatal(err)
	}
	for want, from := range map[string]string{"ok": dir, policy.Started: restored} {
		st, err := store.Open(t.Context(), filepath.Join(from, dbFile), store.WithoutUpgrade())
		if err != nil {
			t.Fatal(err)
		}
		defer st.Close()
		entries, err := st.Audit().Query(t.Context(), store.AuditFilter{Actions: []string{string(policy.HubBackup)}}, 10)
		if err != nil || len(entries) != 1 || entries[0].Result != want {
			t.Errorf("hub.backup in %s = %+v, %v; want one entry with result %q", from, entries, err, want)
		}
	}
}

// TestRestoredHubExpiresApprovalsLeftPending: the process that waited for an
// approval in the backup is gone, so the restored hub expires it, and audits it.
func TestRestoredHubExpiresApprovalsLeftPending(t *testing.T) {
	t.Setenv(passphraseEnv, testBackupPassphrase)
	dir, _ := initHub(t)
	st := openStore(t, dir)
	now := time.Now()
	if err := st.Approvals().Create(t.Context(), store.Approval{
		ID: "held-before-backup", CreatedAt: now.Add(-time.Hour), ExpiresAt: now.Add(-2 * policy.SweepGrace),
		ActorKind: policy.ActorAdmin, ActorID: "root", Action: string(policy.DeviceRevoke), Class: "dangerous", Target: "pi",
	}); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "hub.hbk")
	if _, err := execute(t, "backup", file, "--data-dir", dir); err != nil {
		t.Fatal(err)
	}
	restored := filepath.Join(t.TempDir(), "restored")
	if _, err := execute(t, "restore", file, "--data-dir", restored); err != nil {
		t.Fatal(err)
	}
	runBackupTestHub(t, testHubOptions(t, restored))
	rs, err := store.Open(t.Context(), filepath.Join(restored, dbFile), store.WithoutUpgrade())
	if err != nil {
		t.Fatal(err)
	}
	defer rs.Close()
	waitFor(t, "the restored hub to expire the approval", 20*time.Second, func() bool {
		ap, err := rs.Approvals().Get(t.Context(), "held-before-backup")
		return err == nil && ap.Status == store.ApprovalExpired
	})
}

// TestBackupTakesRunbooksFromTheHubsDir: a hub started with --runbooks-dir
// is backed up with the same flag, and its runbooks restore into the data dir.
func TestBackupTakesRunbooksFromTheHubsDir(t *testing.T) {
	t.Setenv(passphraseEnv, testBackupPassphrase)
	dir, _ := initHub(t)
	runbooks := t.TempDir()
	if err := os.WriteFile(filepath.Join(runbooks, "restart-web.yaml"), []byte("id: restart-web\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "hub.hbk")
	if _, err := execute(t, "backup", file, "--data-dir", dir, "--runbooks-dir", runbooks); err != nil {
		t.Fatal(err)
	}
	restored := filepath.Join(t.TempDir(), "restored")
	if _, err := execute(t, "restore", file, "--data-dir", restored); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(filepath.Join(restored, "runbooks", "restart-web.yaml")); err != nil || string(b) != "id: restart-web\n" {
		t.Errorf("restored runbook = %q, %v", b, err)
	}
}

// abandonTempDir makes a temporary directory whose owner is long gone.
func abandonTempDir(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "snapshot.db"), []byte("plaintext"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-24 * time.Hour)
	if err := os.Chtimes(dir, old, old); err != nil {
		t.Fatal(err)
	}
}

func TestHubStartRemovesAbandonedTempDirs(t *testing.T) {
	dir := t.TempDir()
	stale := filepath.Join(dir, ".snapshot-abc")
	abandonTempDir(t, stale)
	opts := testHubOptions(t, dir)
	runBackupTestHub(t, opts)
	waitFor(t, "the hub to listen", 10*time.Second, serving(t, opts.httpListen))
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Errorf("the abandoned snapshot is still there: %v", err)
	}
}

func TestHubRefusesARestoreStoppedMidCommit(t *testing.T) {
	dir := t.TempDir()
	abandonTempDir(t, filepath.Join(dir, ".restore-abc"))
	if err := os.WriteFile(filepath.Join(dir, "ca.crt"), []byte("moved already"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := runHub(t.Context(), hubOptions{dataDir: dir, listen: "127.0.0.1:0", httpListen: "127.0.0.1:0"}, slog.New(slog.DiscardHandler))
	if !errors.Is(err, backup.ErrIncompleteRestore) {
		t.Fatalf("runHub = %v, want ErrIncompleteRestore", err)
	}
}
