// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"fmt"
)

// Applier executes store writes. Every repository write builds a Command and
// hands it to the store's Applier; reads go straight to the local database.
//
// The default Applier is the store's own ApplyLocal. A replicated Applier
// (Raft) proposes the encoded command to its log, and every node's state
// machine decodes it and calls ApplyLocal on its own Store, in log order.
type Applier interface {
	Apply(ctx context.Context, cmd Command) (Result, error)
}

// ApplierFunc adapts a function to the Applier interface.
type ApplierFunc func(ctx context.Context, cmd Command) (Result, error)

// Apply calls f(ctx, cmd).
func (f ApplierFunc) Apply(ctx context.Context, cmd Command) (Result, error) { return f(ctx, cmd) }

// Option configures Open.
type Option func(*Store)

// WithApplier makes the store route every write through the Applier returned
// by newApplier. newApplier is called once, after migrations, with the opened
// store, so the Applier it builds can call s.ApplyLocal, Snapshot and Restore.
func WithApplier(newApplier func(s *Store) Applier) Option {
	return func(s *Store) { s.applier = newApplier(s) }
}

// ApplyLocal applies cmd to the local database in one transaction. It is the
// state machine step: a replicated Applier calls it on every node, in log
// order. Other callers go through the repositories instead, so their writes
// reach the configured Applier.
func (s *Store) ApplyLocal(ctx context.Context, cmd Command) (res Result, err error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Result{}, fmt.Errorf("apply %s: %w", cmd.Op(), err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	if res, err = cmd.apply(ctx, tx); err != nil {
		return Result{}, err
	}
	if err = tx.Commit(); err != nil {
		return Result{}, fmt.Errorf("apply %s: %w", cmd.Op(), err)
	}
	return res, nil
}
