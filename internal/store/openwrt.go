// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// openwrtRoutersSchema is the schema version whose migration (00037) added
// the openwrt_routers table. A newer binary runs on an older cluster database
// until every hub of the cluster is upgraded; before this version no router
// can be adopted.
const openwrtRoutersSchema = 37

// OpenWrtRouter is an OpenWrt router adopted through ubus.
type OpenWrtRouter struct {
	ID   string
	Name string
	// Sealed is the encrypted connection. The store never sees it in the clear.
	Sealed    []byte
	CreatedAt time.Time
}

// AddOpenWrtRouter stores a router and its sealed connection. A duplicate ID
// or name is a constraint violation.
type AddOpenWrtRouter struct {
	Stamp
	ID        string `json:"id"`
	Name      string `json:"name"`
	Sealed    []byte `json:"sealed"`
	CreatedAt int64  `json:"created_at"`
}

// Op implements Command.
func (AddOpenWrtRouter) Op() string { return "add_openwrt_router" }

func (AddOpenWrtRouter) minSchema() int64 { return openwrtRoutersSchema }

func (c AddOpenWrtRouter) apply(ctx context.Context, w *writer) (Result, error) {
	return Result{}, w.insert(ctx, "openwrt_routers", row{
		"id": c.ID, "name": c.Name, "connection": c.Sealed, "created_at": c.CreatedAt,
	})
}

// RemoveOpenWrtRouter deletes a router. It fails with ErrNotFound if there is
// none with ID.
type RemoveOpenWrtRouter struct {
	Stamp
	ID string `json:"id"`
}

// Op implements Command.
func (RemoveOpenWrtRouter) Op() string { return "remove_openwrt_router" }

func (RemoveOpenWrtRouter) minSchema() int64 { return openwrtRoutersSchema }

func (c RemoveOpenWrtRouter) apply(ctx context.Context, w *writer) (Result, error) {
	return deleteRow(ctx, w, "openwrt_routers", c.ID)
}

// OpenWrtRouters is the repository for adopted OpenWrt routers.
type OpenWrtRouters struct{ s *Store }

// OpenWrtRouters returns the OpenWrt router repository.
func (s *Store) OpenWrtRouters() OpenWrtRouters { return OpenWrtRouters{s: s} }

// requireSchema refuses a write before the schema that added the table. It
// runs before the proposal: a hub still on an older binary halts on a command
// it cannot decode.
func (r OpenWrtRouters) requireSchema(ctx context.Context) error {
	v, err := schemaVersion(ctx, r.s.db)
	if err != nil {
		return err
	}
	if v < openwrtRoutersSchema {
		return fmt.Errorf("%w: it needs %d, the database is at %d; upgrade every hub of the cluster first",
			ErrSchemaTooOld, openwrtRoutersSchema, v)
	}
	return nil
}

// Add stores c. Its connection must already be sealed. Before schema 37 it
// fails with ErrSchemaTooOld.
func (r OpenWrtRouters) Add(ctx context.Context, c OpenWrtRouter) error {
	if c.ID == "" || c.Name == "" || len(c.Sealed) == 0 {
		return errors.New("add openwrt router: ID, name and sealed connection are required")
	}
	if err := r.requireSchema(ctx); err != nil {
		return fmt.Errorf("add openwrt router %s: %w", c.Name, err)
	}
	if _, err := r.s.apply(ctx, AddOpenWrtRouter{
		ID: c.ID, Name: c.Name, Sealed: c.Sealed, CreatedAt: toMillis(c.CreatedAt),
	}); err != nil {
		return fmt.Errorf("add openwrt router %s: %w", c.Name, err)
	}
	return nil
}

// Remove deletes router id, or fails with ErrNotFound. Before schema 37 it
// fails with ErrSchemaTooOld.
func (r OpenWrtRouters) Remove(ctx context.Context, id string) error {
	if err := r.requireSchema(ctx); err != nil {
		return fmt.Errorf("remove openwrt router %s: %w", id, err)
	}
	if _, err := r.s.apply(ctx, RemoveOpenWrtRouter{ID: id}); err != nil {
		return fmt.Errorf("remove openwrt router %s: %w", id, err)
	}
	return nil
}

// List returns every router ordered by name. Before the schema that added
// them there are none.
func (r OpenWrtRouters) List(ctx context.Context) ([]OpenWrtRouter, error) {
	ok, err := atSchema(ctx, r.s.db, openwrtRoutersSchema)
	if err != nil {
		return nil, fmt.Errorf("list openwrt routers: %w", err)
	}
	if !ok {
		return nil, nil
	}
	rows, err := r.s.db.QueryContext(ctx,
		`SELECT id, name, connection, created_at FROM openwrt_routers WHERE _deleted = 0 ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("list openwrt routers: %w", err)
	}
	defer rows.Close()
	var out []OpenWrtRouter
	for rows.Next() {
		var (
			c  OpenWrtRouter
			ms int64
		)
		if err := rows.Scan(&c.ID, &c.Name, &c.Sealed, &ms); err != nil {
			return nil, fmt.Errorf("list openwrt routers: %w", err)
		}
		c.CreatedAt = fromMillis(ms)
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list openwrt routers: %w", err)
	}
	return out, nil
}
