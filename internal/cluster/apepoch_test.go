// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import (
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/gvart/hearth/internal/pki"
	"github.com/gvart/hearth/internal/policy"
	clusterv1 "github.com/gvart/hearth/internal/proto/hearth/cluster/v1"
	"github.com/gvart/hearth/internal/store"
)

const testEpoch = "00112233445566778899aabbccddeeff"

// startAPTestNodeInEpoch is startAPTestNode for a member of cluster epoch
// epoch: a hub restored from a backup ("" for the cluster it came from).
func startAPTestNodeInEpoch(t *testing.T, ca *pki.CA, s apSpec, n int, seed, epoch string) *apTestNode {
	t.Helper()
	dir := t.TempDir()
	raft := filepath.Join(dir, StateDir)
	if err := os.MkdirAll(raft, 0o700); err != nil {
		t.Fatal(err)
	}
	key, err := ca.KeyDER()
	if err != nil {
		t.Fatal(err)
	}
	if err := pki.InstallCA(dir, ca.Cert().Raw, key, ca.Fingerprint()); err != nil {
		t.Fatal(err)
	}
	if epoch != "" {
		if err := writeEpoch(dir, epoch); err != nil {
			t.Fatal(err)
		}
	}
	if err := saveLocalRoles(dir, LocalRoles{Roles: s.roles}); err != nil {
		t.Fatal(err)
	}
	tn := &apTestNode{id: s.id, dir: dir, allowed: s.allowed}
	tn.start(t, n, seed)
	return tn
}

func aliveOn(on *apTestNode, id string) bool {
	for _, m := range on.node.Membership().Members() {
		if m.ID == id && m.State == MemberAlive {
			return true
		}
	}
	return false
}

// TestAPClusterEpoch: a hub restored from a backup starts a new epoch;
// members of it work together, and a member of the cluster the backup came
// from, which holds a certificate of the same CA, is refused by the gossip,
// FetchCAKey and Join signs in the new epoch.
func TestAPClusterEpoch(t *testing.T) {
	ctx := t.Context()
	ca, err := pki.LoadOrCreateCA(t.TempDir(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	a := startAPTestNodeInEpoch(t, ca, apSpec{"a", storageMaster, storageMaster}, 2, "", testEpoch)
	if a.node.Epoch() != testEpoch || pki.HubEpoch(a.node.cert.Load().Leaf) != testEpoch {
		t.Fatalf("restored member's epoch = %q, cert %q", a.node.Epoch(), pki.HubEpoch(a.node.cert.Load().Leaf))
	}
	b := startAPTestNodeInEpoch(t, ca, apSpec{"b", storageMaster, storageMaster}, 2, a.addr, testEpoch)
	old := startAPTestNodeInEpoch(t, ca, apSpec{"old", storageMaster, storageMaster}, 2, a.addr, "")
	waitUntil(t, 10*time.Second, "a and b to see each other", func() bool {
		return aliveOn(a, "b") && aliveOn(b, "a")
	})
	time.Sleep(time.Second)
	if aliveOn(a, "old") || aliveOn(b, "old") || aliveOn(old, "a") || aliveOn(old, "b") {
		t.Fatal("a member of the old epoch joined the restored cluster's gossip")
	}
	if err := a.node.checkPeer(old.node.cert.Load().Leaf); !errors.Is(err, errOtherEpoch) {
		t.Fatalf("checkPeer(old) = %v, want errOtherEpoch", err)
	}
	if err := a.node.checkPeer(b.node.cert.Load().Leaf); err != nil {
		t.Fatalf("checkPeer(b) = %v", err)
	}
	// The old member holds a certificate of the same CA: FetchCAKey still
	// refuses it.
	if _, err := old.node.fetchCAKey(ctx, a.node.cfg.AgentURL); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("FetchCAKey from the old epoch = %v, want permission denied", err)
	}
	entries, err := a.st.Audit().Query(ctx, store.AuditFilter{Actions: []string{string(policy.ClusterCAFetchKey)}}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].ActorID != "old" || !strings.Contains(entries[0].Result, "another cluster epoch") {
		t.Fatalf("audit of the refused fetch = %+v", entries)
	}
	// A hub joining the restored cluster gets a certificate in its epoch.
	tok, err := pki.NewToken(ca.Cert())
	if err != nil {
		t.Fatal(err)
	}
	if err := a.st.JoinTokens().Create(ctx, tok.Secret, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	key, err := pki.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	csr, err := pki.NewCSR(key, "d")
	if err != nil {
		t.Fatal(err)
	}
	js := NewAPJoinServer(a.node, a.st, a.ca, policy.NewWithConfig(a.st.Audit(), a.st.Approvals(), policy.Config{}), testLogger(t))
	resp, err := js.Join(ctx, connect.NewRequest(&clusterv1.JoinRequest{
		TokenSecret: tok.Secret, NodeId: "d", Csr: csr, SchemaVersion: store.SchemaVersion(),
	}))
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(resp.Msg.GetCertificate())
	if err != nil {
		t.Fatal(err)
	}
	if got := pki.HubEpoch(cert); got != testEpoch {
		t.Fatalf("joined hub's certificate epoch = %q, want %q", got, testEpoch)
	}
}
