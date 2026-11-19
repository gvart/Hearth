// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/pressly/goose/v3"
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
	extra      []*goose.Migration
}

// WithApplier makes the store route every write through the Applier returned
// by newApplier. newApplier is called once, after migrations, with the opened
// store, so the Applier it builds can call s.ApplyLocal, Snapshot and Restore.
func WithApplier(newApplier func(s *Store) Applier) Option {
	return func(c *openConfig) { c.newApplier = newApplier }
}

// WithoutUpgrade stops Open from migrating an existing database: it stays at
// its schema version, which must be one this binary supports (at most
// MaxSchemaVersion), or Open fails with ErrSchemaMismatch. A new, empty
// database is still initialized to the newest schema. A Raft cluster member
// opens its store this way, because the schema is part of the replicated
// state: it moves only by a MigrateSchema command in the log, on every node
// at the same point.
func WithoutUpgrade() Option {
	return func(c *openConfig) { c.noUpgrade = true }
}

// WithExtraMigration adds a migration to version, running the SQL in up, on
// top of the embedded ones. Tests use it to stand in for a newer hearth
// binary whose release adds a migration; version must be newer than
// SchemaVersion.
func WithExtraMigration(version int64, up string) Option {
	return func(c *openConfig) {
		c.extra = append(c.extra, goose.NewGoMigration(version, &goose.GoFunc{
			RunTx: func(ctx context.Context, tx *sql.Tx) error {
				_, err := tx.ExecContext(ctx, up)
				return err
			},
		}, nil))
	}
}

// IsDomainError reports whether err, returned by ApplyLocal, is an outcome of
// the command itself rather than a failure of this node: an unknown row, a
// used or expired token, a closed approval, a runbook run that moved on, or a constraint violation. Such errors are
// deterministic, so every node applying the same command to the same state
// gets the same one and the transaction rolls back everywhere. Any other error
// (I/O, a full disk, a closed database) means this node failed to apply a
// write the others applied.
func IsDomainError(err error) bool {
	if errors.Is(err, ErrNotFound) || errors.Is(err, ErrTokenUsed) || errors.Is(err, ErrTokenExpired) ||
		errors.Is(err, ErrSchemaNotNewer) || errors.Is(err, ErrSchemaTooOld) || errors.Is(err, ErrApprovalClosed) ||
		errors.Is(err, ErrRunbookRunConflict) || errors.Is(err, ErrRunbookRunsUnresolved) ||
		errors.Is(err, ErrCARotationActive) || errors.Is(err, ErrCARotationConflict) {
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
	if m, ok := cmd.(MigrateSchema); ok {
		// goose runs each migration in a transaction of its own.
		return Result{}, s.migrateTo(ctx, m.To)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Result{}, fmt.Errorf("apply %s: %w", cmd.Op(), err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	if err = checkSchema(ctx, tx, cmd); err != nil {
		return Result{}, err
	}
	if res, err = cmd.apply(ctx, tx); err != nil {
		return Result{}, err
	}
	if err = tx.Commit(); err != nil {
		return Result{}, fmt.Errorf("apply %s: %w", cmd.Op(), err)
	}
	return res, nil
}
