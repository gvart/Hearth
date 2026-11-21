// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/cluster"
	"github.com/gvart/hearth/internal/pki"
)

func TestClusterTokenCreateRefusesBadRoles(t *testing.T) {
	for _, roles := range []string{"", "node", "storage,node", "root"} {
		err := runClusterTokenCreate(t.Context(), clusterTokenOptions{dataDir: t.TempDir(), ttl: time.Minute, roles: roles}, nil)
		if err == nil || !strings.Contains(err.Error(), "--roles") {
			t.Errorf("--roles %q: err = %v, want refused", roles, err)
		}
	}
}

// A hub joining with a storage-only token is a storage member and holds no
// CA key, though its host allows the master role.
func TestStorageOnlyJoinToken(t *testing.T) {
	dirA, dirB := t.TempDir(), t.TempDir()
	optsA := testHubOptions(t, dirA)
	optsA.cluster.nodeID = "hub-a"
	runBackupTestHub(t, optsA)
	members := func() map[string]cluster.MemberInfo {
		out, err := execute(t, "cluster", "status", "--json", "--data-dir", dirA)
		if err != nil {
			return nil
		}
		var s cluster.Status
		if json.Unmarshal([]byte(out), &s) != nil {
			return nil
		}
		ms := map[string]cluster.MemberInfo{}
		for _, m := range s.Members {
			if m.State == cluster.MemberAlive {
				ms[m.ID] = m
			}
		}
		return ms
	}
	waitFor(t, "hub-a to serve", 30*time.Second, func() bool { return len(members()) == 1 })

	out, err := execute(t, "cluster", "token", "create", "--data-dir", dirA, "--hub-url", "https://"+optsA.listen,
		"--roles", "storage")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "grants storage,") || !strings.Contains(out, " --allow-roles storage ") {
		t.Fatalf("token create output %q: want the roles granted and --allow-roles storage", out)
	}
	token := regexp.MustCompile(`hearthj1\.\S+`).FindString(out)
	optsB := testHubOptions(t, dirB)
	optsB.cluster.nodeID = "hub-b"
	// The host allows both roles (the default); the token grants storage.
	optsB.cluster.join, optsB.cluster.joinToken = "https://"+optsA.listen, token
	optsB.cluster.seeds = []string{optsA.cluster.listen}
	runBackupTestHub(t, optsB)
	waitFor(t, "hub-b to join", 60*time.Second, func() bool { return len(members()) == 2 })
	if b := members()["hub-b"]; b.Roles != cluster.RolesOf(cluster.RoleStorage) {
		t.Fatalf("hub-b roles = %s, want storage", b.Roles)
	}
	if _, err := os.Stat(filepath.Join(dirB, pki.CAKeyFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("hub-b CA key: %v, want none", err)
	}
}
