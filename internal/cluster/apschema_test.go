// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/gvart/hearth/internal/pki"
	"github.com/gvart/hearth/internal/policy"
	clusterv1 "github.com/gvart/hearth/internal/proto/hearth/cluster/v1"
	"github.com/gvart/hearth/internal/store"
)

// TestSchemaGateAcrossVersions: a member whose binary supports a newer
// schema writes at the oldest schema a live member supports; once the older
// member is gone it writes its own, keeps that across a restart, and the
// older member is refused from then on, on the gossip and at a join.
func TestSchemaGateAcrossVersions(t *testing.T) {
	ctx := t.Context()
	ca, err := pki.LoadOrCreateCA(t.TempDir(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	old, next := store.SchemaVersion(), store.SchemaVersion()+1
	a := startAPTestNode(t, ca, apSpec{"a", storageMaster, storageMaster}, 2, "")
	b := prepareAPTestNode(t, ca, apSpec{"b", storageMaster, storageMaster})
	b.storeOpts = []store.Option{store.WithExtraMigration(next, `ALTER TABLE devices ADD COLUMN rolling TEXT NOT NULL DEFAULT ''`)}
	b.start(t, 2, a.addr)
	waitUntil(t, 10*time.Second, "b to see a alive", func() bool { return a.memberOn(b).State == MemberAlive })
	waitUntil(t, 10*time.Second, "a to see b alive", func() bool { return b.memberOn(a).State == MemberAlive })

	// Both live: b writes at a's schema.
	waitUntil(t, 5*time.Second, "b's write schema to follow a", func() bool { return b.node.WriteSchema() == old })
	if got := b.memberOn(a).Schema; got != next {
		t.Fatalf("b gossips schema %d, want %d", got, next)
	}
	if err := b.st.Devices().Upsert(ctx, store.Device{ID: "pi", Name: "pi", FirstSeen: time.Now(), LastSeen: time.Now()}); err != nil {
		t.Fatalf("a write from the newer member with the older one live: %v", err)
	}

	// a goes: b writes its own schema and keeps it.
	a.stop()
	waitUntil(t, 10*time.Second, "b's write schema to rise", func() bool { return b.node.WriteSchema() == next })
	if got := b.node.WrittenSchema(); got != next {
		t.Fatalf("b's written schema = %d, want %d", got, next)
	}
	raw, err := os.ReadFile(filepath.Join(b.dir, StateDir, schemaWrittenFile))
	if err != nil || strings.TrimSpace(string(raw)) != strconv.FormatInt(next, 10) {
		t.Fatalf("b's kept written schema: %q, %v", raw, err)
	}
	b.stop()
	b.start(t, 2, "")
	if got := b.node.WrittenSchema(); got != next {
		t.Fatalf("b's written schema after a restart = %d, want %d", got, next)
	}

	// The older member comes back: b refuses it on the gossip...
	a.start(t, 2, b.addr)
	time.Sleep(2 * time.Second)
	if s := a.memberOn(b).State; s == MemberAlive || s == MemberSuspect {
		t.Fatalf("b holds the older member %s", s)
	}
	// ...and at a join.
	key, err := pki.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	csr, err := pki.NewCSR(key, "c")
	if err != nil {
		t.Fatal(err)
	}
	// Also when the cluster cannot take the audit entry: an older binary is
	// told to upgrade, not to try again.
	for _, tc := range []struct {
		name  string
		audit policy.Auditor
	}{{"", b.st.Audit()}, {" with the cluster unavailable", unavailableAudit{}}} {
		srv := NewAPJoinServer(b.node, b.st, b.ca, policy.New(tc.audit), testLogger(t))
		_, err = srv.Join(ctx, connect.NewRequest(&clusterv1.JoinRequest{
			TokenSecret: "any", NodeId: "c", Csr: csr, Address: "c:7444", SchemaVersion: old,
		}))
		if connect.CodeOf(err) != connect.CodeFailedPrecondition || !strings.Contains(err.Error(), "has written") {
			t.Fatalf("join of an older binary%s: %v, want failed precondition", tc.name, err)
		}
	}
	// The gossip check itself.
	if err := b.node.schema.checkSchema("a", old); err == nil {
		t.Fatal("checkSchema accepted an older member")
	}
	if err := b.node.schema.checkSchema("a", 0); err == nil {
		t.Fatal("checkSchema accepted a member that says no schema")
	}
}

// TestHostFlagDrift: members gossip their host flags' digest, and differing
// ones show as groups.
func TestHostFlagDrift(t *testing.T) {
	ca, err := pki.LoadOrCreateCA(t.TempDir(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	a := prepareAPTestNode(t, ca, apSpec{"a", storageMaster, storageMaster})
	a.config = HostFlagsSource([]string{"reboot"})
	a.start(t, 2, "")
	b := prepareAPTestNode(t, ca, apSpec{"b", storageMaster, storageMaster})
	b.config = HostFlagsSource(nil)
	b.start(t, 2, a.addr)
	c := prepareAPTestNode(t, ca, apSpec{"c", storageMaster, storageMaster})
	c.config = HostFlagsSource([]string{"reboot", "reboot"})
	c.start(t, 2, a.addr)
	want := [][]string{{"a", "c"}, {"b"}}
	waitUntil(t, 10*time.Second, "the drift to show", func() bool {
		return slices.EqualFunc(HostFlagGroups(a.node.Membership().Members()), want, slices.Equal)
	})
	if got := HostFlagGroups([]MemberInfo{
		{ID: "x", State: MemberAlive, ConfigDigest: "1"}, {ID: "y", State: MemberDead, ConfigDigest: "2"},
	}); len(got) != 1 {
		t.Fatalf("a dead member counted: %v", got)
	}
}

// unavailableAudit is the audit log of a member that cannot reach enough
// replicas.
type unavailableAudit struct{}

func (unavailableAudit) Append(context.Context, store.AuditEntry) (int64, error) {
	return 0, store.ErrUnavailable
}
