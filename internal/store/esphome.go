// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// esphomeDevicesSchema is the schema version whose migration (00036) added
// the esphome_devices table. A newer binary runs on an older cluster database
// until every hub of the cluster is upgraded; before this version no device
// can be adopted.
const esphomeDevicesSchema = 36

// ESPHomeDevice is an ESPHome device adopted through its native API.
type ESPHomeDevice struct {
	ID   string
	Name string
	// Sealed is the encrypted connection. The store never sees it in the clear.
	Sealed    []byte
	CreatedAt time.Time
}

// AddESPHomeDevice stores a device and its sealed connection. A duplicate ID
// or name is a constraint violation.
type AddESPHomeDevice struct {
	Stamp
	ID        string `json:"id"`
	Name      string `json:"name"`
	Sealed    []byte `json:"sealed"`
	CreatedAt int64  `json:"created_at"`
}

// Op implements Command.
func (AddESPHomeDevice) Op() string { return "add_esphome_device" }

func (AddESPHomeDevice) minSchema() int64 { return esphomeDevicesSchema }

func (c AddESPHomeDevice) apply(ctx context.Context, w *writer) (Result, error) {
	return Result{}, w.insert(ctx, "esphome_devices", row{
		"id": c.ID, "name": c.Name, "connection": c.Sealed, "created_at": c.CreatedAt,
	})
}

// RemoveESPHomeDevice deletes a device. It fails with ErrNotFound if there is
// none with ID.
type RemoveESPHomeDevice struct {
	Stamp
	ID string `json:"id"`
}

// Op implements Command.
func (RemoveESPHomeDevice) Op() string { return "remove_esphome_device" }

func (RemoveESPHomeDevice) minSchema() int64 { return esphomeDevicesSchema }

func (c RemoveESPHomeDevice) apply(ctx context.Context, w *writer) (Result, error) {
	return deleteRow(ctx, w, "esphome_devices", c.ID)
}

// ESPHomeDevices is the repository for adopted ESPHome devices.
type ESPHomeDevices struct{ s *Store }

// ESPHomeDevices returns the ESPHome device repository.
func (s *Store) ESPHomeDevices() ESPHomeDevices { return ESPHomeDevices{s: s} }

// requireSchema refuses a write before the schema that added the table. It
// runs before the proposal: a hub still on an older binary halts on a command
// it cannot decode.
func (r ESPHomeDevices) requireSchema(ctx context.Context) error {
	v, err := schemaVersion(ctx, r.s.db)
	if err != nil {
		return err
	}
	if v < esphomeDevicesSchema {
		return fmt.Errorf("%w: it needs %d, the database is at %d; upgrade every hub of the cluster first",
			ErrSchemaTooOld, esphomeDevicesSchema, v)
	}
	return nil
}

// Add stores c. Its connection must already be sealed. Before schema 36 it
// fails with ErrSchemaTooOld.
func (r ESPHomeDevices) Add(ctx context.Context, c ESPHomeDevice) error {
	if c.ID == "" || c.Name == "" || len(c.Sealed) == 0 {
		return errors.New("add esphome device: ID, name and sealed connection are required")
	}
	if err := r.requireSchema(ctx); err != nil {
		return fmt.Errorf("add esphome device %s: %w", c.Name, err)
	}
	if _, err := r.s.apply(ctx, AddESPHomeDevice{
		ID: c.ID, Name: c.Name, Sealed: c.Sealed, CreatedAt: toMillis(c.CreatedAt),
	}); err != nil {
		return fmt.Errorf("add esphome device %s: %w", c.Name, err)
	}
	return nil
}

// Remove deletes device id, or fails with ErrNotFound. Before schema 36 it
// fails with ErrSchemaTooOld.
func (r ESPHomeDevices) Remove(ctx context.Context, id string) error {
	if err := r.requireSchema(ctx); err != nil {
		return fmt.Errorf("remove esphome device %s: %w", id, err)
	}
	if _, err := r.s.apply(ctx, RemoveESPHomeDevice{ID: id}); err != nil {
		return fmt.Errorf("remove esphome device %s: %w", id, err)
	}
	return nil
}

// List returns every device ordered by name. Before the schema that added
// them there are none.
func (r ESPHomeDevices) List(ctx context.Context) ([]ESPHomeDevice, error) {
	ok, err := atSchema(ctx, r.s.db, esphomeDevicesSchema)
	if err != nil {
		return nil, fmt.Errorf("list esphome devices: %w", err)
	}
	if !ok {
		return nil, nil
	}
	rows, err := r.s.db.QueryContext(ctx,
		`SELECT id, name, connection, created_at FROM esphome_devices WHERE _deleted = 0 ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("list esphome devices: %w", err)
	}
	defer rows.Close()
	var out []ESPHomeDevice
	for rows.Next() {
		var (
			c  ESPHomeDevice
			ms int64
		)
		if err := rows.Scan(&c.ID, &c.Name, &c.Sealed, &ms); err != nil {
			return nil, fmt.Errorf("list esphome devices: %w", err)
		}
		c.CreatedAt = fromMillis(ms)
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list esphome devices: %w", err)
	}
	return out, nil
}
