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

	"modernc.org/sqlite"
)

// Snapshot writes a consistent copy of the whole database, schema and goose
// version included, to w. Writes may continue while it runs; the copy is the
// state at the moment its read transaction started.
func (s *Store) Snapshot(ctx context.Context, w io.Writer) error {
	dir, err := s.tempDir()
	if err != nil {
		return fmt.Errorf("snapshot: %w", err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	path := filepath.Join(dir, "snapshot.db")
	if _, err := s.db.ExecContext(ctx, `VACUUM INTO ?`, path); err != nil {
		return fmt.Errorf("snapshot: %w", err)
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

// Restore replaces the whole database with a snapshot written by Snapshot.
// The snapshot is staged in a temporary file and checked first, then copied
// into the live database in one write transaction with SQLite's backup API,
// so readers see either the old or the new state and the Store stays usable.
// The caller must not apply writes concurrently (a state machine never does).
func (s *Store) Restore(ctx context.Context, r io.Reader) error {
	dir, err := s.tempDir()
	if err != nil {
		return fmt.Errorf("restore: %w", err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	path := filepath.Join(dir, "restore.db")
	if err := writeFile(path, r); err != nil {
		return fmt.Errorf("restore: %w", err)
	}
	if err := checkSnapshot(ctx, path); err != nil {
		return fmt.Errorf("restore: %w", err)
	}
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("restore: %w", err)
	}
	defer func() { _ = conn.Close() }()
	err = conn.Raw(func(dc any) error {
		rc, ok := dc.(interface {
			NewRestore(string) (*sqlite.Backup, error)
		})
		if !ok {
			return errors.New("driver does not support the backup API")
		}
		b, err := rc.NewRestore(path)
		if err != nil {
			return err
		}
		// One step of -1 copies every page in a single write transaction.
		_, stepErr := b.Step(-1)
		return errors.Join(stepErr, b.Finish())
	})
	if err != nil {
		return fmt.Errorf("restore: %w", err)
	}
	return nil
}

// tempDir creates a private (0700) directory next to the database, so
// snapshot copies never leave the data dir and stay on the same filesystem.
func (s *Store) tempDir() (string, error) {
	return os.MkdirTemp(filepath.Dir(s.path), ".snapshot-")
}

func writeFile(path string, r io.Reader) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, r); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// checkSnapshot opens the staged snapshot read-only and verifies it is an
// intact SQLite database at this binary's schema version, before it touches
// the live database.
func checkSnapshot(ctx context.Context, path string) error {
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
	var version int64
	if err := db.QueryRowContext(ctx,
		`SELECT COALESCE(MAX(version_id), 0) FROM goose_db_version WHERE is_applied`).Scan(&version); err != nil {
		return fmt.Errorf("check snapshot: schema version: %w", err)
	}
	if version == 0 {
		return errors.New("check snapshot: no schema version")
	}
	if version != SchemaVersion() {
		return fmt.Errorf("check snapshot: %w: snapshot has %d, binary has %d", ErrSchemaMismatch, version, SchemaVersion())
	}
	return nil
}
