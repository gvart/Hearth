// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
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

// holdAddr binds a loopback port for the whole test. runBackupTestHub hands
// each hub run a copy of the listener, so the port stays bound across hub
// restarts: no other process can take it before or between hub runs.
func holdAddr(t *testing.T) *net.TCPListener {
	t.Helper()
	var lc net.ListenConfig
	l, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l.(*net.TCPListener)
}

// testHubOptions are the options of a hub on dataDir that listens on
// loopback ports held for the whole test, its cluster port included.
func testHubOptions(t *testing.T, dataDir string) hubOptions {
	t.Helper()
	agentLn, webLn := holdAddr(t), holdAddr(t)
	return hubOptions{
		dataDir: dataDir, hosts: []string{"127.0.0.1"},
		listen: agentLn.Addr().String(), agentLn: agentLn, httpListen: webLn.Addr().String(), webLn: webLn,
		cluster: testClusterOptions(t, ""),
	}
}

// testClusterOptions are the cluster options of member nodeID on a loopback
// cluster port held for the whole test.
func testClusterOptions(t *testing.T, nodeID string) clusterOptions {
	t.Helper()
	ln := holdAddr(t)
	addr := ln.Addr().String()
	return clusterOptions{nodeID: nodeID, listen: addr, advertise: addr, ln: ln}
}

// copyListener returns a listener on a duplicate of l's socket: closing it
// leaves l, and with it the port, bound. nil stays nil.
func copyListener(t *testing.T, l net.Listener) net.Listener {
	t.Helper()
	if l == nil {
		return nil
	}
	f, err := l.(*net.TCPListener).File()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	c, err := net.FileListener(f)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// serving reports whether a hub serves HTTP on httpAddr. A TCP connect does
// not tell: a held port accepts connections while no hub runs on it.
func serving(t *testing.T, httpAddr string) func() bool {
	return func() bool {
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+httpAddr+"/ca.crt", nil)
		if err != nil {
			return false
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return false
		}
		_ = resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	}
}

// runBackupTestHub runs a hub until the returned function stops it. The hub
// serves on copies of the held listeners in opts (see holdAddr).
func runBackupTestHub(t *testing.T, opts hubOptions) (stop func()) {
	t.Helper()
	opts.agentLn, opts.webLn = copyListener(t, opts.agentLn), copyListener(t, opts.webLn)
	opts.cluster.ln = copyListener(t, opts.cluster.ln)
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
	hubOpts := testHubOptions(t, dataDir)
	hubURL := "https://" + hubOpts.listen
	stopHub := runBackupTestHub(t, hubOpts)
	listening := serving(t, hubOpts.httpListen)
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
// cluster: the backup says it comes from a cluster, and the restored hub is
// alone in a new cluster of one, with no trace of the old peer. That the old
// peer's certificate no longer works against it is the cluster epoch's
// (internal/cluster TestAPClusterEpoch).
func TestRestoredClusterMemberFormsANewCluster(t *testing.T) {
	t.Setenv(passphraseEnv, testBackupPassphrase)
	dirA, dirB := t.TempDir(), t.TempDir()
	optsA := testHubOptions(t, dirA)
	optsA.cluster.nodeID = "hub-a"
	listenA := optsA.listen
	stopA := runBackupTestHub(t, optsA)
	clusterStatus := func(dir string) (cluster.Status, bool) {
		out, err := execute(t, "cluster", "status", "--json", "--data-dir", dir)
		if err != nil {
			return cluster.Status{}, false
		}
		var s cluster.Status
		return s, json.Unmarshal([]byte(out), &s) == nil
	}
	alive := func(s cluster.Status) []string {
		var ids []string
		for _, m := range s.Members {
			if m.State == cluster.MemberAlive {
				ids = append(ids, m.ID)
			}
		}
		return ids
	}
	waitFor(t, "hub-a to serve", 30*time.Second, func() bool {
		s, ok := clusterStatus(dirA)
		return ok && slices.Equal(alive(s), []string{"hub-a"})
	})

	out, err := execute(t, "cluster", "token", "create", "--data-dir", dirA, "--hub-url", "https://"+listenA)
	if err != nil {
		t.Fatal(err)
	}
	token := regexp.MustCompile(`hearthj1\.\S+`).FindString(out)
	if token == "" {
		t.Fatalf("no join token in %q", out)
	}
	optsB := testHubOptions(t, dirB)
	optsB.cluster.nodeID = "hub-b"
	optsB.cluster.join, optsB.cluster.joinToken = "https://"+listenA, token
	optsB.cluster.seeds = []string{optsA.cluster.listen}
	stopB := runBackupTestHub(t, optsB)
	waitFor(t, "hub-b to join", 60*time.Second, func() bool {
		s, ok := clusterStatus(dirA)
		return ok && slices.Equal(alive(s), []string{"hub-a", "hub-b"})
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
	if !strings.Contains(out, "comes from a cluster") || !strings.Contains(out, "--cluster-seeds") {
		t.Errorf("restore output does not explain the cluster: %q", out)
	}
	if cluster.IsMember(restored) {
		t.Fatal("the restored data dir holds cluster state")
	}

	optsA.dataDir = restored
	optsA.cluster.nodeID = "hub-r"
	runBackupTestHub(t, optsA)
	waitFor(t, "the restored hub to serve", 30*time.Second, func() bool {
		s, ok := clusterStatus(restored)
		return ok && slices.Equal(alive(s), []string{"hub-r"})
	})
	if s, _ := clusterStatus(restored); !s.Alone() {
		t.Errorf("members after the restore = %+v, want only hub-r", s.Members)
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
