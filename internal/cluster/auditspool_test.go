// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/hashicorp/raft"
	_ "modernc.org/sqlite" // to count raw audit rows

	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

// auditRows counts n's audit rows of action, outcome entries included: Query
// folds those into their start and would hide a duplicate.
func auditRows(t *testing.T, n *testNode, action string) int {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(n.dir, "hearth.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	var c int
	if err := db.QueryRowContext(t.Context(), `SELECT count(*) FROM audit_log WHERE action = ?`, action).Scan(&c); err != nil {
		t.Fatal(err)
	}
	return c
}

// TestOutcomeWithoutQuorumLandsOnce: the outcome of an action that lost the
// cluster's quorum while it ran is spooled on its hub, survives that hub's
// restart, and lands once on every hub when the quorum is back, though the
// first write sat in the old leader's log and may commit too.
func TestOutcomeWithoutQuorumLandsOnce(t *testing.T) {
	ca := newTestCA(t)
	nodes := threeNodes(t, ca)
	leader := leaderOf(t, nodes...)
	var others []*testNode
	for _, n := range nodes {
		if n != leader {
			others = append(others, n)
		}
	}
	spoolDir := filepath.Join(leader.dir, "audit-spool")
	log := testLogger(t)
	spool, err := policy.OpenSpool(spoolDir, leader.st.Audit(), log)
	if err != nil {
		t.Fatal(err)
	}
	pol := policy.New(leader.st.Audit())
	pol.SpoolTo(spool)

	req := policy.Request{ActorKind: policy.ActorAdmin, ActorID: "root", Action: policy.DeviceRevoke, Target: "pi"}
	if err := pol.Do(t.Context(), req, func(context.Context) error {
		for _, n := range others {
			n.stop()
		}
		return nil
	}); err != nil {
		t.Fatalf("Do = %v, want nil: the outcome is spooled", err)
	}
	files, err := filepath.Glob(filepath.Join(spoolDir, "*.json"))
	if err != nil || len(files) != 1 {
		t.Fatalf("spool holds %v (%v), want the outcome", files, err)
	}

	// The hub restarts while the cluster still has no quorum.
	id, dir, addr := leader.ID(), leader.dir, leader.Addr()
	leader.stop()
	hub := startNode(t, ca, id, dir, addr, false)
	restarted := []*testNode{hub}
	for _, n := range others {
		restarted = append(restarted, startNode(t, ca, n.ID(), n.dir, n.Addr(), false))
	}
	// These test nodes write on the leader only (a hub forwards through its
	// API, which they do not serve): the spooling hub has to lead.
	eventually(t, "the spooling hub to lead", func() bool {
		l := leaderOf(t, restarted...)
		if l != hub {
			_ = l.raft.LeadershipTransferToServer(raft.ServerID(hub.ID()), raft.ServerAddress(hub.Addr())).Error()
			return false
		}
		return true
	})
	waitReady(t, restarted...)

	spool, err = policy.OpenSpool(spoolDir, hub.st.Audit(), log)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- spool.Run(ctx) }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("spool Run = %v", err)
		}
	}()

	eventually(t, "the spool drained", func() bool {
		left, err := filepath.Glob(filepath.Join(spoolDir, "*.json"))
		return err == nil && len(left) == 0
	})
	// The spooled write committed through the leader: every hub applies it.
	eventually(t, "the outcome on every hub", func() bool {
		for _, n := range restarted {
			if auditRows(t, n, string(policy.DeviceRevoke)) < 2 {
				return false
			}
		}
		return true
	})
	for _, n := range restarted {
		if got := auditRows(t, n, string(policy.DeviceRevoke)); got != 2 {
			t.Errorf("%s: %d rows, want exactly 2 (started and one outcome)", n.ID(), got)
		}
		entries, err := n.st.Audit().Query(t.Context(), store.AuditFilter{Actions: []string{string(policy.DeviceRevoke)}}, 10)
		if err != nil || len(entries) != 1 || entries[0].Result != "ok" {
			t.Errorf("%s: entries = %+v, %v; want one ending ok", n.ID(), entries, err)
		}
	}
}
