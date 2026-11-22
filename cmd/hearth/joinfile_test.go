// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/cluster"
	"github.com/gvart/hearth/internal/pki"
)

// A --join-file hub with no join file and no CA creates no cluster of its
// own: it says it is not a hub, and leaves no CA behind.
func TestJoinFileNothingToJoin(t *testing.T) {
	dir := t.TempDir()
	opts := hubOptions{dataDir: dir, cluster: clusterOptions{joinFile: filepath.Join(dir, "join"), listen: "127.0.0.1:0"}}
	_, _, _, err := startClusterNode(t.Context(), opts, cluster.HubRoles, "", slog.New(slog.DiscardHandler))
	if !errors.Is(err, errNothingToJoin) {
		t.Fatalf("err = %v, want errNothingToJoin", err)
	}
	for _, f := range []string{pki.CACertFile, pki.CAKeyFile} {
		if _, err := os.Stat(filepath.Join(dir, f)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s: %v, want none", f, err)
		}
	}
}

// A join that stopped half way (a node certificate, no CA certificate) is
// cleared with the join file, and the hub says to install again; a join
// file that is no join is dropped too.
func TestJoinFilePartialAndBroken(t *testing.T) {
	t.Run("partial", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, cluster.JoinFileName)
		if err := cluster.WriteJoinFile(path, cluster.JoinFile{URL: "https://127.0.0.1:1", Token: "hearthj1.x.y"}); err != nil { //nolint:gosec // G101: a fake join token
			t.Fatal(err)
		}
		node := filepath.Join(dir, cluster.StateDir, "node.crt")
		if err := os.MkdirAll(filepath.Dir(node), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(node, []byte("half"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, pki.CAKeyFile), []byte("half"), 0o600); err != nil {
			t.Fatal(err)
		}
		opts := hubOptions{dataDir: dir, cluster: clusterOptions{joinFile: path, listen: "127.0.0.1:0"}}
		_, _, _, err := startClusterNode(t.Context(), opts, cluster.HubRoles, "", slog.New(slog.DiscardHandler))
		if err == nil || !strings.Contains(err.Error(), "half way") {
			t.Fatalf("err = %v, want the half-way join named", err)
		}
		for _, f := range []string{path, node, filepath.Join(dir, pki.CAKeyFile)} {
			if _, err := os.Stat(f); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("%s left: %v", f, err)
			}
		}
		// Next start: nothing to join, no CA created.
		if _, _, _, err := startClusterNode(t.Context(), opts, cluster.HubRoles, "", slog.New(slog.DiscardHandler)); !errors.Is(err, errNothingToJoin) {
			t.Fatalf("restart: %v, want errNothingToJoin", err)
		}
	})
	t.Run("not a join", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, cluster.JoinFileName)
		if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
		opts := hubOptions{dataDir: dir, cluster: clusterOptions{joinFile: path, listen: "127.0.0.1:0"}}
		if _, _, _, err := startClusterNode(t.Context(), opts, cluster.HubRoles, "", slog.New(slog.DiscardHandler)); err == nil {
			t.Fatal("joined with a broken join file")
		}
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("broken join file kept: %v", err)
		}
	})
	t.Run("unreachable master keeps the file", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, cluster.JoinFileName)
		ca, err := pki.LoadOrCreateCA(t.TempDir(), time.Now())
		if err != nil {
			t.Fatal(err)
		}
		tok, err := pki.NewToken(ca.Cert())
		if err != nil {
			t.Fatal(err)
		}
		if err := cluster.WriteJoinFile(path, cluster.JoinFile{URL: "https://127.0.0.1:1", Token: tok.EncodeJoin()}); err != nil {
			t.Fatal(err)
		}
		opts := hubOptions{dataDir: dir, cluster: clusterOptions{joinFile: path, listen: "127.0.0.1:0"}}
		if _, _, _, err := startClusterNode(t.Context(), opts, cluster.HubRoles, "", slog.New(slog.DiscardHandler)); err == nil ||
			!strings.Contains(err.Error(), "trying again") {
			t.Fatalf("err = %v, want a failure that may pass", err)
		}
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("join file dropped on a transient failure: %v", err)
		}
	})
}

// A hub joined with only a join file, no seeds, through a URL whose host is
// not the master's gossip address, finds the cluster: the join response
// names the master's address (#334). The file is gone once joined, and a
// spent token makes a second hub with a copy give up for good.
func TestJoinFileFindsTheCluster(t *testing.T) {
	dirA, dirB, dirC := t.TempDir(), t.TempDir(), t.TempDir()
	optsA := testHubOptions(t, dirA)
	optsA.cluster.nodeID = "hub-a"
	runBackupTestHub(t, optsA)
	members := func(dir string) map[string]bool {
		out, err := execute(t, "cluster", "status", "--json", "--data-dir", dir)
		if err != nil {
			return nil
		}
		var s cluster.Status
		if json.Unmarshal([]byte(out), &s) != nil {
			return nil
		}
		ms := map[string]bool{}
		for _, m := range s.Members {
			if m.State == cluster.MemberAlive {
				ms[m.ID] = true
			}
		}
		return ms
	}
	waitFor(t, "hub-a to serve", 30*time.Second, func() bool { return len(members(dirA)) == 1 })
	out, err := execute(t, "cluster", "token", "create", "--data-dir", dirA, "--hub-url", "https://"+optsA.listen)
	if err != nil {
		t.Fatal(err)
	}
	token := regexp.MustCompile(`hearthj1\.\S+`).FindString(out)
	join := cluster.JoinFile{URL: "https://" + optsA.listen, Token: token}
	pathB := filepath.Join(dirB, cluster.JoinFileName)
	if err := cluster.WriteJoinFile(pathB, join); err != nil {
		t.Fatal(err)
	}
	optsB := testHubOptions(t, dirB)
	optsB.cluster.nodeID = "hub-b"
	optsB.cluster.joinFile = pathB
	runBackupTestHub(t, optsB)
	waitFor(t, "hub-a and hub-b to list each other", 60*time.Second, func() bool {
		return len(members(dirA)) == 2 && len(members(dirB)) == 2
	})
	if _, err := os.Stat(pathB); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("join file kept after the join: %v", err)
	}

	// The token is spent: a copy is refused for good, the file dropped and
	// no CA created.
	pathC := filepath.Join(dirC, cluster.JoinFileName)
	if err := cluster.WriteJoinFile(pathC, join); err != nil {
		t.Fatal(err)
	}
	optsC := testHubOptions(t, dirC)
	optsC.cluster.nodeID, optsC.cluster.joinFile = "hub-c", pathC
	_, _, _, err = startClusterNode(t.Context(), optsC, cluster.HubRoles, "", slog.New(slog.DiscardHandler))
	if err == nil || !strings.Contains(err.Error(), "already used") {
		t.Fatalf("join with a spent token = %v", err)
	}
	if _, err := os.Stat(pathC); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("join file kept after a refusal for good: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dirC, pki.CACertFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("CA after a refused join: %v", err)
	}
}
