// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/agent"
	"github.com/gvart/hearth/internal/backup"
	"github.com/gvart/hearth/internal/cluster"
	"github.com/gvart/hearth/internal/pki"
	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

const testBackupPassphrase = "correct horse battery staple"

// freeAddr returns a loopback address nothing listens on right now.
func freeAddr(t *testing.T) string {
	t.Helper()
	var lc net.ListenConfig
	l, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	return l.Addr().String()
}

// runBackupTestHub runs a hub until the returned function stops it.
func runBackupTestHub(t *testing.T, opts hubOptions) (stop func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runHub(ctx, opts, slog.New(slog.DiscardHandler)) }()
	stopped := false
	stop = func() {
		if stopped {
			return
		}
		stopped = true
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("hub %s: %v", opts.dataDir, err)
			}
		case <-time.After(20 * time.Second):
			t.Errorf("hub %s did not stop", opts.dataDir)
		}
	}
	t.Cleanup(stop)
	return stop
}

func waitFor(t *testing.T, what string, within time.Duration, ok func() bool) {
	t.Helper()
	for deadline := time.Now().Add(within); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		if ok() {
			return
		}
	}
	t.Fatalf("timed out after %s waiting for %s", within, what)
}

var enrollTokenRe = regexp.MustCompile(`HEARTH_TOKEN=(\S+)`)

// TestRestoredHubTakesBackItsAgent is the promise of a backup: an agent that
// enrolled before it reconnects to the restored hub with the identity it has,
// without enrolling again. A scheduled backup without the CA key keeps that
// promise once the key is copied back from a `hearth backup` file; without
// any key, the hub starts over with a new CA and agents enroll again.
func TestRestoredHubTakesBackItsAgent(t *testing.T) {
	for _, mode := range []string{"backup", "no CA key, key copied back", "no CA key, new CA"} {
		t.Run(mode, func(t *testing.T) { testRestoredHub(t, mode) })
	}
}

func testRestoredHub(t *testing.T, mode string) {
	t.Setenv(passphraseEnv, testBackupPassphrase)
	dataDir := t.TempDir()
	listen, httpListen := freeAddr(t), freeAddr(t)
	hubURL := "https://" + listen
	hubOpts := hubOptions{dataDir: dataDir, listen: listen, httpListen: httpListen, hosts: []string{"127.0.0.1"}}
	stopHub := runBackupTestHub(t, hubOpts)
	listening := func() bool {
		var d net.Dialer
		c, err := d.DialContext(t.Context(), "tcp", listen)
		if err == nil {
			_ = c.Close()
		}
		return err == nil
	}
	waitFor(t, "the hub to listen", 10*time.Second, listening)

	enroll := func(dir, name string) string {
		t.Helper()
		out, err := execute(t, "token", "create", "--data-dir", dir, "--hub-url", hubURL)
		if err != nil {
			t.Fatal(err)
		}
		m := enrollTokenRe.FindStringSubmatch(out)
		if m == nil {
			t.Fatalf("no token in %q", out)
		}
		id, err := agent.Join(t.Context(), hubURL, m[1], t.TempDir(), name)
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	out, err := execute(t, "token", "create", "--data-dir", dataDir, "--hub-url", hubURL)
	if err != nil {
		t.Fatal(err)
	}
	m := enrollTokenRe.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("no token in %q", out)
	}
	agentDir := t.TempDir()
	deviceID, err := agent.Join(t.Context(), hubURL, m[1], agentDir, "restored-pi")
	if err != nil {
		t.Fatal(err)
	}
	certBefore, err := os.ReadFile(filepath.Join(agentDir, agent.CertFile))
	if err != nil {
		t.Fatal(err)
	}
	// The agent runs through the whole test, as it would on a real device.
	agentCtx, stopAgent := context.WithCancel(context.Background())
	agentDone := make(chan error, 1)
	go func() {
		agentDone <- agent.Run(agentCtx, agent.Config{DataDir: agentDir, Version: "test", Log: slog.New(slog.DiscardHandler)})
	}()
	t.Cleanup(func() {
		stopAgent()
		t.Logf("agent stopped: %v", <-agentDone)
	})
	deviceOnline := func(dir string, after time.Time) func() bool {
		return func() bool {
			st, err := store.Open(t.Context(), filepath.Join(dir, dbFile), store.WithoutUpgrade())
			if err != nil {
				return false
			}
			defer st.Close()
			d, err := st.Devices().Get(t.Context(), deviceID)
			return err == nil && d.Status == store.StatusOnline && d.LastSeen.After(after)
		}
	}
	waitFor(t, "the agent to come online", 15*time.Second, deviceOnline(dataDir, time.Time{}))

	// The backups are taken from the running hub: the admin's, and for the
	// other modes the scheduled one without the CA key.
	adminFile := filepath.Join(t.TempDir(), "hub.hbk")
	if _, err := execute(t, "backup", adminFile, "--data-dir", dataDir); err != nil {
		t.Fatal(err)
	}
	file := adminFile
	if mode != "backup" {
		file = filepath.Join(t.TempDir(), "scheduled.hbk")
		st, err := openBackupStore(t.Context(), dataDir)
		if err != nil {
			t.Fatal(err)
		}
		_, err = backup.Create(t.Context(), backup.CreateOptions{
			DataDir: dataDir, Store: st, Output: file, Passphrase: testBackupPassphrase, WithoutCAKey: true,
		})
		_ = st.Close()
		if err != nil {
			t.Fatal(err)
		}
	}
	stopHub()

	restored := filepath.Join(t.TempDir(), "restored")
	if out, err := execute(t, "restore", file, "--data-dir", restored); err != nil {
		t.Fatal(err)
	} else if !strings.Contains(out, "Restored the backup") {
		t.Errorf("restore output: %q", out)
	}
	switch mode {
	case "no CA key, key copied back":
		// As docs/backup.md says: restore the admin's backup elsewhere, copy its key.
		keyDir := filepath.Join(t.TempDir(), "ca")
		if _, err := execute(t, "restore", adminFile, "--data-dir", keyDir); err != nil {
			t.Fatal(err)
		}
		if err := os.Link(filepath.Join(keyDir, pki.CAKeyFile), filepath.Join(restored, pki.CAKeyFile)); err != nil {
			t.Fatal(err)
		}
	case "no CA key, new CA":
		if err := os.Remove(filepath.Join(restored, pki.CACertFile)); err != nil {
			t.Fatal(err)
		}
	}
	restoredAt := time.Now()
	hubOpts.dataDir = restored
	runBackupTestHub(t, hubOpts)

	expectEnrolls := 1
	if mode == "no CA key, new CA" {
		waitFor(t, "the hub with a new CA to listen", 10*time.Second, listening)
		// The agent's old certificate is from the old CA: it has to enroll again.
		time.Sleep(3 * time.Second)
		if deviceOnline(restored, restoredAt)() {
			t.Fatal("an agent of the old CA got back in")
		}
		enroll(restored, "re-enrolled-pi")
		expectEnrolls = 2
	} else {
		waitFor(t, "the agent to reconnect to the restored hub", 60*time.Second, deviceOnline(restored, restoredAt))
		certAfter, err := os.ReadFile(filepath.Join(agentDir, agent.CertFile))
		if err != nil {
			t.Fatal(err)
		}
		if string(certBefore) != string(certAfter) {
			t.Error("the agent's certificate changed: it enrolled again")
		}
	}
	st, err := store.Open(t.Context(), filepath.Join(restored, dbFile), store.WithoutUpgrade())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	devices, err := st.Devices().List(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(devices) != expectEnrolls || devices[0].ID != deviceID && devices[len(devices)-1].ID != deviceID {
		t.Errorf("devices after the restore = %+v, want %d, %s among them", devices, expectEnrolls, deviceID)
	}
	entries, err := st.Audit().Query(t.Context(), store.AuditFilter{
		Actions: []string{string(policy.HubBackup), string(policy.HubRestore), string(policy.DeviceEnroll)},
	}, 10)
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	for _, e := range entries {
		counts[e.Action]++
	}
	if counts[string(policy.HubRestore)] != 1 || counts[string(policy.DeviceEnroll)] != expectEnrolls {
		t.Errorf("audit after the restore = %v, want one hub.restore and %d device.enroll", counts, expectEnrolls)
	}
}

// TestRestoredClusterMemberFormsANewCluster backs up a member of a two-hub
// cluster: the restored hub is alone in its new cluster, with no trace of the
// old peer, and the old peer's certificate no longer works against it.
func TestRestoredClusterMemberFormsANewCluster(t *testing.T) {
	t.Setenv(passphraseEnv, testBackupPassphrase)
	dirA, dirB := t.TempDir(), t.TempDir()
	listenA, raftA := freeAddr(t), freeAddr(t)
	optsA := hubOptions{
		dataDir: dirA, listen: listenA, httpListen: freeAddr(t), hosts: []string{"127.0.0.1"},
		cluster: clusterOptions{form: true, nodeID: "hub-a", raftListen: raftA, advertise: raftA},
	}
	stopA := runBackupTestHub(t, optsA)
	clusterStatus := func(dir string) (cluster.Status, bool) {
		out, err := execute(t, "cluster", "status", "--json", "--data-dir", dir)
		if err != nil {
			return cluster.Status{}, false
		}
		var s cluster.Status
		return s, json.Unmarshal([]byte(out), &s) == nil
	}
	waitFor(t, "hub-a to lead", 30*time.Second, func() bool {
		s, ok := clusterStatus(dirA)
		return ok && s.LeaderID == "hub-a"
	})

	out, err := execute(t, "cluster", "token", "create", "--data-dir", dirA, "--hub-url", "https://"+listenA)
	if err != nil {
		t.Fatal(err)
	}
	token := regexp.MustCompile(`hearthj1\.\S+`).FindString(out)
	if token == "" {
		t.Fatalf("no join token in %q", out)
	}
	raftB := freeAddr(t)
	stopB := runBackupTestHub(t, hubOptions{
		dataDir: dirB, listen: freeAddr(t), httpListen: freeAddr(t), hosts: []string{"127.0.0.1"},
		cluster: clusterOptions{join: "https://" + listenA, joinToken: token, nodeID: "hub-b", raftListen: raftB, advertise: raftB},
	})
	waitFor(t, "hub-b to become a voter with a recorded certificate", 60*time.Second, func() bool {
		s, ok := clusterStatus(dirA)
		if !ok || len(s.Peers) != 2 {
			return false
		}
		for _, p := range s.Peers {
			if p.Suffrage != "Voter" {
				return false
			}
		}
		st, err := store.Open(t.Context(), filepath.Join(dirA, dbFile), store.WithoutUpgrade())
		if err != nil {
			return false
		}
		defer st.Close()
		certs, err := st.Hubs().Certs(t.Context(), "hub-b")
		return err == nil && len(certs) > 0
	})

	file := filepath.Join(t.TempDir(), "cluster.hbk")
	if _, err := execute(t, "backup", file, "--data-dir", dirA); err != nil {
		t.Fatal(err)
	}
	stopB()
	stopA()

	restored := filepath.Join(t.TempDir(), "restored")
	out, err = execute(t, "restore", file, "--data-dir", restored)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "--cluster") {
		t.Errorf("restore output does not explain the cluster: %q", out)
	}
	if cluster.IsMember(restored) {
		t.Fatal("the restored data dir holds Raft state")
	}

	optsA.dataDir = restored
	optsA.cluster.nodeID = "hub-r"
	runBackupTestHub(t, optsA)
	waitFor(t, "the restored hub to lead a new cluster", 30*time.Second, func() bool {
		s, ok := clusterStatus(restored)
		return ok && s.LeaderID == "hub-r"
	})
	s, ok := clusterStatus(restored)
	if !ok || len(s.Peers) != 1 || s.Peers[0].ID != "hub-r" {
		t.Errorf("peers after the restore = %+v, want only hub-r", s.Peers)
	}
	st, err := store.Open(t.Context(), filepath.Join(restored, dbFile), store.WithoutUpgrade())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	certs, err := st.Hubs().Certs(t.Context(), "hub-b")
	if err != nil || len(certs) == 0 {
		t.Fatalf("hub-b's certificates = %v, %v", certs, err)
	}
	for _, c := range certs {
		if !c.Revoked {
			t.Errorf("hub-b's certificate %s still works against the restored hub", c.Serial)
		}
	}
}

func TestBackupCommandRefusals(t *testing.T) {
	dir, _ := initHub(t)
	file := filepath.Join(t.TempDir(), "hub.hbk")

	t.Run("no passphrase", func(t *testing.T) {
		t.Setenv(passphraseEnv, "")
		_, err := execute(t, "backup", file, "--data-dir", dir)
		if err == nil || !strings.Contains(err.Error(), passphraseEnv) {
			t.Fatalf("backup = %v, want an error naming %s", err, passphraseEnv)
		}
	})
	t.Run("short passphrase", func(t *testing.T) {
		t.Setenv(passphraseEnv, "too short")
		_, err := execute(t, "backup", file, "--data-dir", dir)
		if err == nil || !strings.Contains(err.Error(), "at least") {
			t.Fatalf("backup = %v, want the minimum length", err)
		}
		st := openStore(t, dir)
		entries, err := st.Audit().Query(t.Context(), store.AuditFilter{Actions: []string{string(policy.HubBackup)}}, 5)
		if err != nil || len(entries) != 0 {
			t.Errorf("audit = %+v, %v: refused before the policy decision", entries, err)
		}
	})
	t.Run("no passphrase flag exists", func(t *testing.T) {
		for _, cmd := range []string{"backup", "restore"} {
			if _, err := execute(t, cmd, "x", "--passphrase", "secret"); err == nil || !strings.Contains(err.Error(), "unknown flag") {
				t.Errorf("%s --passphrase = %v, want unknown flag", cmd, err)
			}
		}
	})
	t.Run("not a hub", func(t *testing.T) {
		t.Setenv(passphraseEnv, testBackupPassphrase)
		empty := t.TempDir()
		if _, err := execute(t, "backup", file, "--data-dir", empty); err == nil {
			t.Fatal("backup of an empty dir succeeded")
		}
		if entries, _ := os.ReadDir(empty); len(entries) != 0 {
			t.Errorf("backup created %d files in the wrong data dir", len(entries))
		}
	})
	t.Run("denied by policy", func(t *testing.T) {
		t.Setenv(passphraseEnv, testBackupPassphrase)
		denyDir, _ := initHub(t)
		if err := os.WriteFile(filepath.Join(denyDir, policy.ConfigFile), []byte("classes: {dangerous: deny}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		out := filepath.Join(t.TempDir(), "denied.hbk")
		_, err := execute(t, "backup", out, "--data-dir", denyDir)
		if !errors.Is(err, policy.ErrDenied) {
			t.Fatalf("backup = %v, want ErrDenied", err)
		}
		if _, err := os.Stat(out); !os.IsNotExist(err) {
			t.Errorf("a denied backup left a file: %v", err)
		}
		st := openStore(t, denyDir)
		entries, err := st.Audit().Query(t.Context(), store.AuditFilter{Actions: []string{string(policy.HubBackup)}}, 5)
		if err != nil || len(entries) != 1 || entries[0].Decision != policy.Deny {
			t.Errorf("audit = %+v, %v, want one denial", entries, err)
		}
	})
	t.Run("restore over data", func(t *testing.T) {
		t.Setenv(passphraseEnv, testBackupPassphrase)
		_, err := execute(t, "restore", file, "--data-dir", dir)
		if !errors.Is(err, backup.ErrDataDirNotEmpty) {
			t.Fatalf("restore = %v, want ErrDataDirNotEmpty", err)
		}
	})
}

// TestBackupLeavesTheSchemaAlone: a newer binary must not migrate the database
// of a running older hub, and refuses one newer than it supports.
func TestBackupLeavesTheSchemaAlone(t *testing.T) {
	t.Setenv(passphraseEnv, testBackupPassphrase)

	t.Run("older database stays older", func(t *testing.T) {
		dir, _ := initHub(t)
		older := store.SchemaVersion() - 1
		db, err := sql.Open("sqlite", "file:"+filepath.Join(dir, dbFile))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(t.Context(), `DELETE FROM goose_db_version WHERE version_id > ?`, older); err != nil {
			t.Fatal(err)
		}
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := execute(t, "backup", filepath.Join(t.TempDir(), "hub.hbk"), "--data-dir", dir); err != nil {
			t.Fatal(err)
		}
		st, err := store.Open(t.Context(), filepath.Join(dir, dbFile), store.WithoutUpgrade())
		if err != nil {
			t.Fatal(err)
		}
		defer st.Close()
		if v, err := st.SchemaVersion(t.Context()); err != nil || v != older {
			t.Errorf("schema after the backup = %d, %v, want %d", v, err, older)
		}
	})

	t.Run("newer database is refused", func(t *testing.T) {
		dir, _ := initHub(t)
		st, err := store.Open(t.Context(), filepath.Join(dir, dbFile),
			store.WithExtraMigration(store.SchemaVersion()+1, `CREATE TABLE future (id INTEGER)`))
		if err != nil {
			t.Fatal(err)
		}
		if err := st.Close(); err != nil {
			t.Fatal(err)
		}
		_, err = execute(t, "backup", filepath.Join(t.TempDir(), "hub.hbk"), "--data-dir", dir)
		if !errors.Is(err, store.ErrSchemaMismatch) {
			t.Fatalf("backup = %v, want ErrSchemaMismatch", err)
		}
		if strings.Contains(err.Error(), testBackupPassphrase) {
			t.Errorf("the error shows the passphrase: %v", err)
		}
	})
}
