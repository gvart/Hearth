// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

// TestActionRefusedWithoutQuorum: without a majority the audit entry cannot
// be written, so the action does not run and the operator is told why, while
// what a hub serves from its own database keeps working.
func TestActionRefusedWithoutQuorum(t *testing.T) {
	nodes := threeNodes(t, newTestCA(t))
	leader := leaderOf(t, nodes...)
	upsert(t, leader, "pi")
	pol := policy.New(leader.st.Audit())
	req := policy.Request{ActorKind: policy.ActorAdmin, ActorID: "root", Action: policy.DeviceRevoke, Target: "pi"}
	if err := pol.Do(t.Context(), req, func(context.Context) error { return nil }); err != nil {
		t.Fatalf("with quorum: %v", err)
	}
	for _, n := range nodes {
		if n != leader {
			n.stop()
		}
	}

	ctx, cancel := context.WithTimeout(t.Context(), 2*waitFor)
	defer cancel()
	called := false
	err := pol.Do(ctx, req, func(context.Context) error { called = true; return nil })
	if called {
		t.Error("the action ran without quorum")
	}
	if err == nil || !strings.Contains(err.Error(), "most of its hubs are unreachable") {
		t.Errorf("err = %v, want it to say why", err)
	}

	read, cancelRead := context.WithTimeout(t.Context(), time.Second)
	defer cancelRead()
	if _, err := leader.st.Devices().Get(read, "pi"); err != nil {
		t.Errorf("read a device without quorum: %v", err)
	}
	entries, err := leader.st.Audit().Query(read, store.AuditFilter{Actions: []string{string(policy.DeviceRevoke)}}, 10)
	if err != nil || len(entries) == 0 {
		t.Errorf("read the audit log without quorum: %d entries, %v", len(entries), err)
	}
}
