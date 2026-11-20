// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"sync"
	"time"

	"github.com/pressly/goose/v3"
	_ "modernc.org/sqlite" // registers the pure-Go "sqlite" database/sql driver

	"github.com/gvart/hearth/internal/hlc"
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
	// extra are migrations added with WithExtraMigration; maxSchema is the
	// newest schema version this store can migrate to.
	extra     []*goose.Migration
	maxSchema int64
	// clock stamps the writes this store accepts, as origin (see Stamp).
	clock  *hlc.Clock
	origin string
	// stmts caches the statements the writer builds (see sqlFor).
	stmts sync.Map
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
		"&_pragma=secure_delete(1)" +
		"&_pragma=journal_size_limit(0)" +
		"&_txlock=immediate"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite %s: %w", path, err)
	}
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("open sqlite %s: %w", path, err)
	}
	var cfg openConfig
	for _, o := range opts {
		o(&cfg)
	}
	if cfg.clock == nil {
		cfg.clock = hlc.NewClock(nil)
	}
	if cfg.origin == "" {
		cfg.origin = randomOrigin()
	}
	s := &Store{db: db, path: path, extra: cfg.extra, maxSchema: SchemaVersion(), clock: cfg.clock, origin: cfg.origin}
	for _, m := range cfg.extra {
		s.maxSchema = max(s.maxSchema, m.Version)
	}
	if err := s.migrate(ctx, cfg.noUpgrade); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("migrate %s: %w", path, err)
	}
	if err := s.observeStored(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("open sqlite %s: %w", path, err)
	}
	s.applier = ApplierFunc(s.ApplyLocal)
	if cfg.newApplier != nil {
		s.applier = cfg.newApplier(s)
	}
	return s, nil
}

// ErrSchemaMismatch means a database or snapshot is at a schema version
// newer than this binary supports.
var ErrSchemaMismatch = errors.New("schema version not supported by this binary")

// migrate brings the database to the newest schema. With noUpgrade, only a
// new database (schema version 0) is migrated; any other is left at its
// version, which must be one this binary supports (at most MaxSchemaVersion).
func (s *Store) migrate(ctx context.Context, noUpgrade bool) error {
	p, err := s.newMigrator()
	if err != nil {
		return err
	}
	if noUpgrade {
		v, err := p.GetDBVersion(ctx)
		if err != nil {
			return err
		}
		if v > s.maxSchema {
			return fmt.Errorf("%w: the database is at schema %d, this binary supports up to %d",
				ErrSchemaMismatch, v, s.maxSchema)
		}
		if v != 0 {
			return nil
		}
	}
	_, err = p.Up(ctx)
	return err
}

// SchemaVersion is the newest schema version of this binary: its newest
// embedded migration.
func SchemaVersion() int64 {
	names, _ := fs.Glob(migrations, "migrations/*.sql") // the pattern is valid
	var latest int64
	for _, n := range names {
		v, err := goose.NumericComponent(strings.TrimPrefix(n, "migrations/"))
		if err == nil && v > latest {
			latest = v
		}
	}
	return latest
}

// MaxSchemaVersion is the newest schema version this store can migrate to:
// SchemaVersion, or a newer migration added with WithExtraMigration.
func (s *Store) MaxSchemaVersion() int64 { return s.maxSchema }

// SchemaVersion returns the database's current schema (goose) version.
func (s *Store) SchemaVersion(ctx context.Context) (int64, error) {
	p, err := s.newMigrator()
	if err != nil {
		return 0, err
	}
	v, err := p.GetDBVersion(ctx)
	if err != nil {
		return 0, fmt.Errorf("schema version: %w", err)
	}
	return v, nil
}

// apply routes a write through the store's Applier. From VersionedSchema it
// first stamps the command with this hub's clock, unless it carries a stamp
// already; below it, the command goes as it is, so a member whose binary
// predates stamps can still decode it.
func (s *Store) apply(ctx context.Context, cmd Command) (Result, error) {
	if stampOf(cmd) == (Stamp{}) {
		versioned, err := isVersioned(ctx, s.db)
		if err != nil {
			return Result{}, fmt.Errorf("apply %s: %w", cmd.Op(), err)
		}
		if versioned {
			cmd = withStamp(cmd, Stamp{HLC: s.clock.Now(), Origin: s.origin})
		}
	}
	return s.applier.Apply(ctx, cmd)
}

// Close closes the database.
func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) newMigrator() (*goose.Provider, error) {
	sub, err := fs.Sub(migrations, "migrations")
	if err != nil {
		return nil, fmt.Errorf("migrations fs: %w", err)
	}
	p, err := goose.NewProvider(goose.DialectSQLite3, s.db, sub,
		goose.WithDisableGlobalRegistry(true), goose.WithGoMigrations(s.extra...))
	if err != nil {
		return nil, fmt.Errorf("migrations provider: %w", err)
	}
	return p, nil
}

func toMillis(t time.Time) int64 { return t.UnixMilli() }

func fromMillis(ms int64) time.Time { return time.UnixMilli(ms).UTC() }
