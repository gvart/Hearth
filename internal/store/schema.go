// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// Schema changes in a cluster.
//
// A member migrates its own database when it opens, to the newest schema its
// binary supports. A table or column a migration added is written only once
// every live member supports it: writes use the cluster's write schema
// (WithWriteSchema), the oldest schema a live member supports. A command that
// needs a newer schema than that implements schemaGated, and ApplyLocal
// refuses it with ErrSchemaTooOld.

// ErrSchemaTooOld refuses a command that needs a newer schema than the
// store's writes use: upgrade every hub of the cluster first.
var ErrSchemaTooOld = errors.New("command needs a newer schema than the database is at")

// schemaGated is implemented by a command that needs at least schema
// version minSchema: one that writes a table or column a migration added.
type schemaGated interface {
	minSchema() int64
}

// checkSchema refuses cmd with ErrSchemaTooOld if it needs a newer schema
// than v, the schema writes use.
func checkSchema(cmd Command, v int64) error {
	g, ok := cmd.(schemaGated)
	if !ok {
		return nil
	}
	if v < g.minSchema() {
		return fmt.Errorf("apply %s: %w: it needs %d, the database is at %d; upgrade every hub of the cluster first",
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
