// SPDX-License-Identifier: AGPL-3.0-only

package automation

import (
	"context"
	"log/slog"
)

// LeaderNode is the part of a cluster node RunWhileLeading needs.
type LeaderNode interface {
	// IsLeader reports whether this hub is the leader now.
	IsLeader() bool
	// WaitReady blocks until this node has applied everything the cluster
	// committed before it, or ctx is done.
	WaitReady(ctx context.Context) error
}

// RunWhileLeading calls run while node leads the cluster, so automations run
// on one hub only. run starts once node leads and has caught up, and its
// context is cancelled as soon as node stops leading; RunWhileLeading waits
// for it to return before it may start again. changed signals that
// leadership may have changed: IsLeader is checked again on every signal.
// It returns when ctx is done, after run has returned.
func RunWhileLeading(ctx context.Context, node LeaderNode, changed <-chan struct{}, log *slog.Logger,
	run func(context.Context) error,
) error {
	var (
		stop context.CancelFunc
		done chan struct{}
	)
	stopLeading := func() {
		if stop != nil {
			stop()
			<-done
			stop, done = nil, nil
		}
	}
	defer stopLeading()
	for {
		if !node.IsLeader() {
			stopLeading()
		} else if stop == nil {
			lctx, cancel := context.WithCancel(ctx)
			d := make(chan struct{})
			stop, done = cancel, d
			go func() {
				defer close(d)
				if node.WaitReady(lctx) != nil {
					return
				}
				log.InfoContext(lctx, "leading the cluster: running automations")
				if err := run(lctx); err != nil {
					log.ErrorContext(lctx, "automations stopped", "err", err)
				}
			}()
		}
		select {
		case <-ctx.Done():
			return nil
		case <-changed:
		}
	}
}
