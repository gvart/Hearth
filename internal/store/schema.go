// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// Schema changes in a Raft cluster.
//
// A cluster member never migrates its database on its own (WithoutUpgrade):
// the schema is part of the replicated state and moves only by a
// MigrateSchema command in the log, which every node applies at the same
// point. Until then a member whose binary is newer runs at the older schema,
// so a command that needs a newer schema must not be applied before the
// migrate: such a command implements schemaGated, and ApplyLocal refuses it
// with ErrSchemaTooOld below that version, the same way on every node.

var (
	// ErrSchemaNotNewer refuses a MigrateSchema to a version the database is
	// already at or past.
	ErrSchemaNotNewer = errors.New("schema is already at or past the target version")
	// ErrSchemaTooOld refuses a command that needs a newer schema than the
	// database is at: run `hearth cluster migrate` first.
	ErrSchemaTooOld = errors.New("command needs a newer schema than the database is at")
)

// MigrateSchema runs every pending migration up to and including schema
// version To. A cluster leader proposes it once every hub's binary supports
// To; each node's state machine then migrates its own database in log order.
// It fails with ErrSchemaNotNewer, a domain error, when the database is
// already at To or past it, and with ErrSchemaMismatch, a failure of this
// node, when To is newer than this binary supports.
type MigrateSchema struct {
	To int64 `json:"to"`
}

// Op implements Command.
func (MigrateSchema) Op() string { return "migrate_schema" }

// apply is never called: ApplyLocal runs MigrateSchema through goose, which
// runs each migration in a transaction of its own.
func (MigrateSchema) apply(context.Context, *writer) (Result, error) {
	return Result{}, errors.New("migrate_schema runs outside a command transaction")
}

func (s *Store) migrateTo(ctx context.Context, to int64) error {
	p, err := s.newMigrator()
	if err != nil {
		return fmt.Errorf("migrate schema to %d: %w", to, err)
	}
	cur, err := p.GetDBVersion(ctx)
	if err != nil {
		return fmt.Errorf("migrate schema to %d: %w", to, err)
	}
	if to <= cur {
		return fmt.Errorf("migrate schema to %d: %w: the database is at %d", to, ErrSchemaNotNewer, cur)
	}
	if to > s.maxSchema {
		return fmt.Errorf("migrate schema to %d: %w: it supports up to %d; upgrade this hub's hearth",
			to, ErrSchemaMismatch, s.maxSchema)
	}
	if _, err := p.UpTo(ctx, to); err != nil {
		return fmt.Errorf("migrate schema to %d: %w", to, err)
	}
	return nil
}

// schemaGated is implemented by a command that needs at least schema
// version minSchema: one that writes a table or column a migration added.
type schemaGated interface {
	minSchema() int64
}

// checkSchema refuses cmd with ErrSchemaTooOld if it needs a newer schema
// than v, the version the database is at. Every node is at the same schema at the same log
// position, so the refusal is the same everywhere.
func checkSchema(cmd Command, v int64) error {
	g, ok := cmd.(schemaGated)
	if !ok {
		return nil
	}
	if v < g.minSchema() {
		return fmt.Errorf("apply %s: %w: it needs %d, the database is at %d; run `hearth cluster migrate` first",
			cmd.Op(), ErrSchemaTooOld, g.minSchema(), v)
	}
	return nil
}

type querier interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// schemaVersion reads the goose version of the database behind q.
func schemaVersion(ctx context.Context, q querier) (int64, error) {
	var v int64
	if err := q.QueryRowContext(ctx,
		`SELECT COALESCE(MAX(version_id), 0) FROM goose_db_version WHERE is_applied`).Scan(&v); err != nil {
		return 0, fmt.Errorf("schema version: %w", err)
	}
	return v, nil
}
