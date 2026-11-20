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

// SweepGrace is how long past its expiry an approval must be before a sweep
// expires it. Only the sweeping hub's clock says when that is, and expiring
// skips the check approving does, so a hub whose clock runs ahead would
// otherwise expire a live hold. A clock ahead by more than the grace still
// does; the requester's own timer, which is never behind the expiry, handles
// every other hold.
const SweepGrace = 5 * time.Minute

// sweepBatch is how many overdue approvals one read of a sweep returns.
const sweepBatch = 100

// SweepOnly makes SweepApprovals expire only the approvals owns says this hub
// owns: in an AP cluster, each master sweeps those it owns on the ring of
// masters. Call it before the sweep runs.
func (e *Engine) SweepOnly(owns func(id string) bool) { e.sweepOwns = owns }

// SweepApprovals expires the pending approvals whose expiry passed more than
// SweepGrace ago, as
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
		due, err := e.approvals.Overdue(ctx, now.Add(-SweepGrace), sweepBatch)
		if err != nil {
			return total, errors.Join(append(errs, fmt.Errorf("list overdue approvals: %w", err))...)
		}
		expired := 0
		for _, ap := range due {
			if e.sweepOwns != nil && !e.sweepOwns(ap.ID) {
				continue
			}
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

// expireOrphan audits and then expires ap, a pending approval past its expiry
// and the grace. The entry comes first, as run's does: a crash between the two
// leaves an entry and a pending approval the next sweep takes up, never an
// expired approval nobody audited. An approval closed meanwhile, by its own
// requester, leaves a stray entry. It reports false for one that was no
// longer pending.
func (e *Engine) expireOrphan(ctx context.Context, ap store.Approval, now time.Time) (bool, error) {
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
		return false, fmt.Errorf("expire approval %s: %w", ap.ID, err)
	}
	if err := e.approvals.Decide(ctx, ap.ID, store.ApprovalExpired, "timeout", now); err != nil {
		if errors.Is(err, store.ErrApprovalClosed) {
			return false, nil
		}
		return false, fmt.Errorf("expire approval %s: %w", ap.ID, err)
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
