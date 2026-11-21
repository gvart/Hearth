// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/gvart/hearth/internal/pki"
	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

// TestAPNodeCertRenewal: a member holding no CA key renews its expiring
// node certificate through a master, audited, and keeps gossiping with the
// new one; a certificate that does not expire soon is not renewed.
func TestAPNodeCertRenewal(t *testing.T) {
	ctx := t.Context()
	ca, err := pki.LoadOrCreateCA(t.TempDir(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	a := startAPTestNode(t, ca, apSpec{"a", storageMaster, storageMaster}, 2, "")
	// c's certificate expires in 5 days.
	c := prepareAPTestNode(t, ca, apSpec{"c", storageOnly, storageMaster})
	raft := filepath.Join(c.dir, RaftDir)
	for _, f := range []string{nodeCertFile, nodeKeyFile} {
		if err := os.Remove(filepath.Join(raft, f)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := loadOrIssueNodeCert(raft, ca, "c", "", time.Now().Add(-pki.HubCertValidity+5*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	c.start(t, 2, a.addr)
	old := c.node.cert.Load().Leaf
	waitUntil(t, 10*time.Second, "a and c to see each other", func() bool {
		return c.memberOn(a).State == MemberAlive && a.memberOn(c).State == MemberAlive
	})
	for _, tn := range []*apTestNode{a, c} {
		if err := tn.node.RecordNodeCert(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if err := a.st.Hubs().SetAgentURL(ctx, "a", a.node.cfg.AgentURL); err != nil {
		t.Fatal(err)
	}
	// a's certificate does not expire soon: refused, and audited.
	if _, err := fetchNextAs(t, ca, *a.node.cert.Load(), a.node.cfg.AgentURL, caFP(ca), nil); connect.CodeOf(err) != connect.CodePermissionDenied ||
		!strings.Contains(err.Error(), errNotDue.Error()) {
		t.Fatalf("renewal of a certificate not due: %v, want refused", err)
	}
	waitUntil(t, 10*time.Second, "c to renew its node certificate", func() bool {
		cur := c.node.cert.Load().Leaf
		return cur.SerialNumber.Cmp(old.SerialNumber) != 0 && time.Until(cur.NotAfter) > 300*24*time.Hour
	})
	if c.ca.HasKey() {
		t.Fatal("c holds the CA key")
	}
	cur := c.node.cert.Load().Leaf
	certs, err := a.st.Hubs().Certs(ctx, "c")
	if err != nil {
		t.Fatal(err)
	}
	recorded := false
	for _, hc := range certs {
		recorded = recorded || (hc.Serial == pki.SerialString(cur) && hc.Fingerprint == pki.FingerprintHex(cur))
	}
	if !recorded {
		t.Fatalf("c's new certificate is not recorded: %+v", certs)
	}
	entries, err := a.st.Audit().Query(ctx, store.AuditFilter{Actions: []string{string(policy.ClusterNodeCertRenew)}}, 10)
	if err != nil || len(entries) == 0 || entries[0].ActorID != "c" || entries[0].Decision != policy.Allow {
		t.Fatalf("audit of the renewal = %+v, %v", entries, err)
	}
	// It survives a restart, and c is still a member.
	c.stop()
	c.start(t, 2, a.addr)
	if got := c.node.cert.Load().Leaf; got.SerialNumber.Cmp(cur.SerialNumber) != 0 {
		t.Fatal("c restarted with another certificate")
	}
	waitUntil(t, 10*time.Second, "a to see c alive", func() bool { return c.memberOn(a).State == MemberAlive })
}
