// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/backup"
	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

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
	err := runHub(t.Context(), hubOptions{dataDir: dir, listen: "127.0.0.1:0", httpListen: "127.0.0.1:0", cluster: clusterOptions{listen: "127.0.0.1:0"}}, slog.New(slog.DiscardHandler))
	if !errors.Is(err, backup.ErrIncompleteRestore) {
		t.Fatalf("runHub = %v, want ErrIncompleteRestore", err)
	}
}
