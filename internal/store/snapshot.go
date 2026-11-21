// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// Snapshot writes a consistent copy of the whole database, schema and goose
// version included, to w. Writes may continue while it runs; the copy is the
// state at the moment its read transaction started.
func (s *Store) Snapshot(ctx context.Context, w io.Writer) error {
	dir, remove, err := s.tempDir()
	if err != nil {
		return fmt.Errorf("snapshot: %w", err)
	}
	defer remove()
	path := filepath.Join(dir, "snapshot.db")
	if err := s.VacuumInto(ctx, path); err != nil {
		return err
	}
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("snapshot: %w", err)
	}
	defer func() { _ = f.Close() }()
	if _, err := io.Copy(w, f); err != nil {
		return fmt.Errorf("snapshot: %w", err)
	}
	return nil
}

// VacuumInto writes a consistent copy of the whole database to a new file at
// path. Writes may continue while it runs.
func (s *Store) VacuumInto(ctx context.Context, path string) error {
	if _, err := s.db.ExecContext(ctx, `VACUUM INTO ?`, path); err != nil {
		return fmt.Errorf("snapshot: %w", err)
	}
	return nil
}

// CheckSnapshotFile verifies that the file at path is an intact SQLite database
// at a schema version this binary supports. It fails with ErrSchemaMismatch for
// a newer schema.
func CheckSnapshotFile(ctx context.Context, path string) error {
	return checkSnapshot(ctx, path, SchemaVersion())
}

// RetireHubCerts revokes every hub node certificate recorded in the database.
// A restored hub starts a new cluster, and the hubs of the old one share its CA:
// this keeps them out if they are still running. It writes the local file
// directly, so it is only for a restored database no hub runs on yet.
func (s *Store) RetireHubCerts(ctx context.Context, now time.Time) error {
	if err := s.Hubs().RequireCerts(ctx); errors.Is(err, ErrSchemaTooOld) {
		return nil // no hub certificates were recorded at this schema
	} else if err != nil {
		return fmt.Errorf("retire hub certs: %w", err)
	}
	if _, err := s.db.ExecContext(ctx,
		`UPDATE hub_certs SET revoked_at = ? WHERE revoked_at IS NULL`, toMillis(now)); err != nil {
		return fmt.Errorf("retire hub certs: %w", err)
	}
	return nil
}

// tempDir creates a private (0700) directory next to the database, so
// snapshot copies never leave the data dir and stay on the same filesystem.
func (s *Store) tempDir() (string, func(), error) {
	return NewTempDir(filepath.Dir(s.path), snapshotTempPrefix)
}

// checkSnapshot opens the snapshot at path read-only and verifies it is an
// intact SQLite database at a schema version this binary supports (at most
// maxSchema). An older schema is fine: Open migrates it.
func checkSnapshot(ctx context.Context, path string, maxSchema int64) error {
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()
	var result string
	if err := db.QueryRowContext(ctx, `PRAGMA quick_check`).Scan(&result); err != nil {
		return fmt.Errorf("check snapshot: %w", err)
	}
	if result != "ok" {
		return fmt.Errorf("check snapshot: %s", result)
	}
	version, err := schemaVersion(ctx, db)
	if err != nil {
		return fmt.Errorf("check snapshot: %w", err)
	}
	if version == 0 {
		return errors.New("check snapshot: no schema version")
	}
	if version > maxSchema {
		return fmt.Errorf("check snapshot: %w: the snapshot is at schema %d, this binary supports up to %d",
			ErrSchemaMismatch, version, maxSchema)
	}
	return nil
}
