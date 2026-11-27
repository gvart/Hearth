// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// unifiControllersSchema is the schema version whose migration (00039) added
// the unifi_controllers table. A newer binary runs on an older cluster database
// until every hub of the cluster is upgraded; before this version no controller
// can be adopted.
const unifiControllersSchema = 39

// UniFiController is a UniFi Network controller adopted through its API.
type UniFiController struct {
	ID   string
	Name string
	// Sealed is the encrypted connection. The store never sees it in the clear.
	Sealed    []byte
	CreatedAt time.Time
}

// AddUniFiController stores a controller and its sealed connection. A duplicate ID
// or name is a constraint violation.
type AddUniFiController struct {
	Stamp
	ID        string `json:"id"`
	Name      string `json:"name"`
	Sealed    []byte `json:"sealed"`
	CreatedAt int64  `json:"created_at"`
}

// Op implements Command.
func (AddUniFiController) Op() string { return "add_unifi_controller" }

func (AddUniFiController) minSchema() int64 { return unifiControllersSchema }

func (c AddUniFiController) apply(ctx context.Context, w *writer) (Result, error) {
	return Result{}, w.insert(ctx, "unifi_controllers", row{
		"id": c.ID, "name": c.Name, "connection": c.Sealed, "created_at": c.CreatedAt,
	})
}

// RemoveUniFiController deletes a controller. It fails with ErrNotFound if there is
// none with ID.
type RemoveUniFiController struct {
	Stamp
	ID string `json:"id"`
}

// Op implements Command.
func (RemoveUniFiController) Op() string { return "remove_unifi_controller" }

func (RemoveUniFiController) minSchema() int64 { return unifiControllersSchema }

func (c RemoveUniFiController) apply(ctx context.Context, w *writer) (Result, error) {
	return deleteRow(ctx, w, "unifi_controllers", c.ID)
}

// UniFiControllers is the repository for adopted UniFi controllers.
type UniFiControllers struct{ s *Store }

// UniFiControllers returns the UniFi controller repository.
func (s *Store) UniFiControllers() UniFiControllers { return UniFiControllers{s: s} }

// requireSchema refuses a write before the schema that added the table. It
// runs before the proposal: a hub still on an older binary halts on a command
// it cannot decode.
func (r UniFiControllers) requireSchema(ctx context.Context) error {
	v, err := schemaVersion(ctx, r.s.db)
	if err != nil {
		return err
	}
	if v < unifiControllersSchema {
		return fmt.Errorf("%w: it needs %d, the database is at %d; upgrade every hub of the cluster first",
			ErrSchemaTooOld, unifiControllersSchema, v)
	}
	return nil
}

// Add stores c. Its connection must already be sealed. Before schema 39 it
// fails with ErrSchemaTooOld.
func (r UniFiControllers) Add(ctx context.Context, c UniFiController) error {
	if c.ID == "" || c.Name == "" || len(c.Sealed) == 0 {
		return errors.New("add unifi controller: ID, name and sealed connection are required")
	}
	if err := r.requireSchema(ctx); err != nil {
		return fmt.Errorf("add unifi controller %s: %w", c.Name, err)
	}
	if _, err := r.s.apply(ctx, AddUniFiController{
		ID: c.ID, Name: c.Name, Sealed: c.Sealed, CreatedAt: toMillis(c.CreatedAt),
	}); err != nil {
		return fmt.Errorf("add unifi controller %s: %w", c.Name, err)
	}
	return nil
}

// Remove deletes controller id, or fails with ErrNotFound. Before schema 39 it
// fails with ErrSchemaTooOld.
func (r UniFiControllers) Remove(ctx context.Context, id string) error {
	if err := r.requireSchema(ctx); err != nil {
		return fmt.Errorf("remove unifi controller %s: %w", id, err)
	}
	if _, err := r.s.apply(ctx, RemoveUniFiController{ID: id}); err != nil {
		return fmt.Errorf("remove unifi controller %s: %w", id, err)
	}
	return nil
}

// List returns every controller ordered by name. Before the schema that added
// them there are none.
func (r UniFiControllers) List(ctx context.Context) ([]UniFiController, error) {
	ok, err := atSchema(ctx, r.s.db, unifiControllersSchema)
	if err != nil {
		return nil, fmt.Errorf("list unifi controllers: %w", err)
	}
	if !ok {
		return nil, nil
	}
	rows, err := r.s.db.QueryContext(ctx,
		`SELECT id, name, connection, created_at FROM unifi_controllers WHERE _deleted = 0 ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("list unifi controllers: %w", err)
	}
	defer rows.Close()
	var out []UniFiController
	for rows.Next() {
		var (
			c  UniFiController
			ms int64
		)
		if err := rows.Scan(&c.ID, &c.Name, &c.Sealed, &ms); err != nil {
			return nil, fmt.Errorf("list unifi controllers: %w", err)
		}
		c.CreatedAt = fromMillis(ms)
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list unifi controllers: %w", err)
	}
	return out, nil
}
