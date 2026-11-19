// SPDX-License-Identifier: AGPL-3.0-only

package policy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/gvart/hearth/internal/store"
)

// sweepBatch is how many overdue approvals one read of a sweep returns.
const sweepBatch = 100

// SweepApprovals expires the pending approvals whose expiry has passed, as
// the requester of each would have, and returns how many it expired. It is
// for the holds that outlive their requester: a hub that stops while an
// action waits for approval leaves it pending, with its plan, for good.
//
// Each one is expired through the store's replicated Decide, which clears its
// plan, and audited as a denial; one decided meanwhile, or expired by its
// own requester, is left to whoever decided it, and is not counted. It never
// touches an approval before its expiry. Only a hub that may write to the
// cluster, the leader, should call it. It keeps going past an approval it
// cannot expire and returns those errors together.
func (e *Engine) SweepApprovals(ctx context.Context) (int, error) {
	if e.approvals == nil {
		return 0, nil
	}
	var (
		total int
		errs  []error
	)
	for {
		now := e.now()
		due, err := e.approvals.Overdue(ctx, now, sweepBatch)
		if err != nil {
			return total, errors.Join(append(errs, fmt.Errorf("list overdue approvals: %w", err))...)
		}
		expired := 0
		for _, ap := range due {
			ok, err := e.expireOrphan(ctx, ap, now)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			if ok {
				expired++
			}
		}
		total += expired
		// Stop when nothing was left to read, or nothing moved: an approval
		// that cannot be expired would be read again.
		if len(due) < sweepBatch || expired == 0 {
			return total, errors.Join(errs...)
		}
	}
}

// expireOrphan expires ap, a pending approval past its expiry, and audits it.
// It reports false for one that was no longer pending.
func (e *Engine) expireOrphan(ctx context.Context, ap store.Approval, now time.Time) (bool, error) {
	if err := e.approvals.Decide(ctx, ap.ID, store.ApprovalExpired, "timeout", now); err != nil {
		if errors.Is(err, store.ErrApprovalClosed) {
			return false, nil
		}
		return false, fmt.Errorf("expire approval %s: %w", ap.ID, err)
	}
	// The plan is only for the approver, and is not audited.
	var detail map[string]any
	if len(ap.Detail) > 0 {
		if err := json.Unmarshal(ap.Detail, &detail); err != nil {
			detail = nil
		}
	}
	delete(detail, DetailPlan)
	req := Request{
		ActorKind: ap.ActorKind, ActorID: ap.ActorID, Action: Action(ap.Action), Target: ap.Target, Detail: detail,
	}
	if err := e.record(ctx, req, Deny, "approval expired: its requester was gone", map[string]any{"approval": ap.ID}); err != nil {
		return true, fmt.Errorf("expired approval %s, but its audit entry was not written: %w", ap.ID, err)
	}
	return true, nil
}

// RunApprovalSweep sweeps overdue approvals (see SweepApprovals) at once and
// then every minute, until ctx is done. A sweep that fails, for example
// because a cluster has no quorum, is logged and tried again on the next
// tick; it never ends the loop. It returns nil when ctx is done.
func (e *Engine) RunApprovalSweep(ctx context.Context, log *slog.Logger) error {
	tick := time.NewTicker(e.sweepEvery)
	defer tick.Stop()
	for {
		n, err := e.SweepApprovals(ctx)
		if ctx.Err() != nil {
			return nil
		}
		if err != nil {
			log.WarnContext(ctx, "sweeping overdue approvals failed, will retry", "err", err)
		}
		if n > 0 {
			log.InfoContext(ctx, "expired approvals left pending by a stopped hub", "count", n)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
		}
	}
}
