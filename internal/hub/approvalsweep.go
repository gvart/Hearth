// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"context"
	"log/slog"

	"github.com/gvart/hearth/internal/automation"
	"github.com/gvart/hearth/internal/policy"
)

// RunApprovalSweep expires the approvals that outlived the hub that held them
// (see policy.Engine.SweepApprovals) until ctx is done. With a nil node, a
// single hub, it sweeps at once. In a cluster only the leader sweeps, as soon
// as it leads and has caught up, so a follower never proposes the write;
// changed signals that leadership may have changed.
func RunApprovalSweep(ctx context.Context, pol *policy.Engine, node automation.LeaderNode,
	changed <-chan struct{}, log *slog.Logger,
) error {
	if node == nil {
		return pol.RunApprovalSweep(ctx, log)
	}
	return automation.RunWhileLeading(ctx, node, changed, log.With("component", "approvals"),
		func(ctx context.Context) error { return pol.RunApprovalSweep(ctx, log) })
}
