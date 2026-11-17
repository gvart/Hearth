// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"errors"
	"fmt"

	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
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
type Option func(*openConfig)

type openConfig struct {
	newApplier func(s *Store) Applier
	noUpgrade  bool
}

// WithApplier makes the store route every write through the Applier returned
// by newApplier. newApplier is called once, after migrations, with the opened
// store, so the Applier it builds can call s.ApplyLocal, Snapshot and Restore.
func WithApplier(newApplier func(s *Store) Applier) Option {
	return func(c *openConfig) { c.newApplier = newApplier }
}

// WithoutUpgrade stops Open from migrating an existing database: it fails
// with ErrSchemaMismatch unless the database is already at SchemaVersion. A
// new, empty database is still initialized. A Raft cluster member opens its
// store this way, because the schema is part of the replicated state and one
// node must never migrate on its own.
func WithoutUpgrade() Option {
	return func(c *openConfig) { c.noUpgrade = true }
}

// IsDomainError reports whether err, returned by ApplyLocal, is an outcome of
// the command itself rather than a failure of this node: an unknown row, a
// used or expired token, or a constraint violation. Such errors are
// deterministic, so every node applying the same command to the same state
// gets the same one and the transaction rolls back everywhere. Any other error
// (I/O, a full disk, a closed database) means this node failed to apply a
// write the others applied.
func IsDomainError(err error) bool {
	if errors.Is(err, ErrNotFound) || errors.Is(err, ErrTokenUsed) || errors.Is(err, ErrTokenExpired) {
		return true
	}
	var se *sqlite.Error
	return errors.As(err, &se) && se.Code()&0xff == sqlite3.SQLITE_CONSTRAINT
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
