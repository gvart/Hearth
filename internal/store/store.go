// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"time"

	"github.com/pressly/goose/v3"
	_ "modernc.org/sqlite" // registers the pure-Go "sqlite" database/sql driver
)

//go:embed migrations/*.sql
var migrations embed.FS

// ErrNotFound is returned when a requested row does not exist.
var ErrNotFound = errors.New("not found")

// Store is the hub's SQLite-backed state. It is safe for concurrent use.
// Reads query the local database; writes go through the store's Applier.
type Store struct {
	db      *sql.DB
	path    string
	applier Applier
}

// Open opens (creating if needed) the SQLite database at path with WAL,
// a busy timeout and foreign keys enabled, and applies all pending migrations.
// Without options, writes apply directly to the local database.
func Open(ctx context.Context, path string, opts ...Option) (*Store, error) {
	// Pragmas go in the DSN so every pooled connection gets them.
	// _txlock=immediate takes the write lock at BEGIN, so concurrent writers
	// wait on busy_timeout instead of failing on a read-to-write lock upgrade.
	dsn := "file:" + path +
		"?_pragma=journal_mode(WAL)" +
		"&_pragma=busy_timeout(5000)" +
		"&_pragma=foreign_keys(1)" +
		"&_txlock=immediate"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite %s: %w", path, err)
	}
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("open sqlite %s: %w", path, err)
	}
	p, err := newMigrator(db)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	if _, err := p.Up(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("migrate %s: %w", path, err)
	}
	s := &Store{db: db, path: path}
	s.applier = ApplierFunc(s.ApplyLocal)
	for _, o := range opts {
		o(s)
	}
	return s, nil
}

// apply routes a write through the store's Applier.
func (s *Store) apply(ctx context.Context, cmd Command) (Result, error) {
	return s.applier.Apply(ctx, cmd)
}

// Close closes the database.
func (s *Store) Close() error {
	return s.db.Close()
}

func newMigrator(db *sql.DB) (*goose.Provider, error) {
	sub, err := fs.Sub(migrations, "migrations")
	if err != nil {
		return nil, fmt.Errorf("migrations fs: %w", err)
	}
	p, err := goose.NewProvider(goose.DialectSQLite3, db, sub)
	if err != nil {
		return nil, fmt.Errorf("migrations provider: %w", err)
	}
	return p, nil
}

func toMillis(t time.Time) int64 { return t.UnixMilli() }

func fromMillis(ms int64) time.Time { return time.UnixMilli(ms).UTC() }
