// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"database/sql/driver"
	"errors"
	"fmt"

	"modernc.org/sqlite"
)

// ErrReadRefused refuses a read another member sent that names a table it
// may not read: a master table's (#384), or one that is no replicated
// table, as sqlite_dbpage or dbstat, which would show any table's pages.
var ErrReadRefused = errors.New("read refused")

// ReadLocalUnproven is ReadLocal for a member that did not prove it holds
// the hub CA key: SQLite itself refuses, as it compiles the query, anything
// but a SELECT of the replicated tables that are not master tables (and of
// json_each, which the store's queries use). The table names of the query
// text are not what decides: the authorizer sees every table a query reads,
// however it is spelled, a view's or a virtual table's included.
func (s *Store) ReadLocalUnproven(ctx context.Context, query string, args Values) (Rows, error) {
	if s.ro == nil {
		return Rows{}, fmt.Errorf("read: %w", ErrNoRoute)
	}
	conn, err := s.ro.Conn(ctx)
	if err != nil {
		return Rows{}, fmt.Errorf("read: %w", err)
	}
	defer func() { _ = conn.Close() }()
	refused := ""
	auth := func(action sqlite.AuthorizerActionCode, arg1, _, _, _ string) sqlite.AuthorizerReturnCode {
		switch action {
		case sqlite.AuthSelect, sqlite.AuthFunction, sqlite.AuthRecursive:
			return sqlite.AuthorizerOK
		case sqlite.AuthRead:
			if unprovenReadable(arg1) {
				return sqlite.AuthorizerOK
			}
		}
		if refused == "" {
			refused = arg1
		}
		return sqlite.AuthorizerDeny
	}
	set := func(fn sqlite.AuthorizerFn) error {
		return conn.Raw(func(dc any) error {
			r, ok := dc.(sqlite.AuthorizerRegisterer)
			if !ok {
				return errors.New("the sqlite driver has no authorizer")
			}
			if err := r.RegisterAuthorizer(fn); err != nil {
				// The connection may keep a policy: it is not pooled again.
				return errors.Join(err, driver.ErrBadConn)
			}
			return nil
		})
	}
	if err := set(auth); err != nil {
		return Rows{}, fmt.Errorf("read: %w", err)
	}
	rows, err := s.readOn(ctx, conn, query, args)
	if uerr := set(nil); uerr != nil && err == nil {
		err = fmt.Errorf("read: %w", uerr)
	}
	if err != nil && refused != "" {
		return Rows{}, fmt.Errorf("read: %s: %w: %w", refused, ErrReadRefused, err)
	}
	return rows, err
}

// unprovenReadable reports whether a member that did not prove the hub CA
// key may read table: a replicated table, not a master table's.
func unprovenReadable(table string) bool {
	switch {
	case masterTables[table]:
		return false
	case table == auditTable, table == "json_each":
		return true
	}
	_, ok := tables[table]
	return ok
}
