// SPDX-License-Identifier: AGPL-3.0-only

package policy

import (
	"context"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/store"
)

// ownerApprovals are a hub's approvals with its own record of what it
// decided, as in an AP cluster.
type ownerApprovals struct {
	store.Approvals
	decided map[string]string
}

func (a ownerApprovals) OwnerDecision(_ context.Context, id string) (string, bool, error) {
	return a.decided[id], true, nil
}

// TestApprovedOnAReplicaIsDenied: a held request that reads its approval as
// approved acts only if this hub, the approval's owner, approved it; an
// approval a replica wrote (a storage member, #382) is a denial.
func TestApprovedOnAReplicaIsDenied(t *testing.T) {
	s := openStore(t)
	ctx := t.Context()
	now := time.Now()
	for _, id := range []string{"forged", "real"} {
		orphan(t, s, id, now, time.Hour)
		if err := s.Approvals().Decide(ctx, id, store.ApprovalApproved, "web/w", now); err != nil {
			t.Fatal(err)
		}
	}
	aps := ownerApprovals{Approvals: s.Approvals(), decided: map[string]string{"real": store.ApprovalApproved}}
	e := NewWithConfig(s.Audit(), aps, confirmAll(time.Minute))
	e.poll = time.Millisecond
	for id, want := range map[string]string{"forged": store.ApprovalDenied, "real": store.ApprovalApproved} {
		got, err := e.wait(ctx, store.Approval{ID: id, ExpiresAt: now.Add(time.Hour)})
		if err != nil || got.Status != want {
			t.Fatalf("%s: %s, %v; want %s", id, got.Status, err, want)
		}
	}
}
