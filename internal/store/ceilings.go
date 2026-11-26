// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// deviceCeilingsSchema is the schema version whose migration (00035) added
// device_ceilings.
const deviceCeilingsSchema = 35

// DeviceCeiling is the capability ceiling the hub sets for a device's agent
// (#346).
type DeviceCeiling struct {
	DeviceID string
	// Ceiling is protojson of a hearth.agent.v1.Ceiling.
	Ceiling   json.RawMessage
	UpdatedAt time.Time
	// UpdatedBy is the actor that set it, as kind/id.
	UpdatedBy string
}

// DeviceCeilings is the repository of the ceilings the hub sets.
type DeviceCeilings struct{ s *Store }

// DeviceCeilings returns the device ceilings repository.
func (s *Store) DeviceCeilings() DeviceCeilings { return DeviceCeilings{s: s} }

// Set records ceiling, protojson of a Ceiling, as device's, set by by at
// now. Below schema 35 it fails with ErrSchemaTooOld.
func (r DeviceCeilings) Set(ctx context.Context, device string, ceiling json.RawMessage, by string, now time.Time) error {
	if !json.Valid(ceiling) {
		return fmt.Errorf("set ceiling of device %s: not valid JSON", device)
	}
	if _, err := r.s.apply(ctx, SetDeviceCeiling{DeviceID: device, Ceiling: string(ceiling), UpdatedAt: toMillis(now), UpdatedBy: by}); err != nil {
		return fmt.Errorf("set ceiling of device %s: %w", device, err)
	}
	return nil
}

// Get returns the ceiling set for device, or ErrNotFound when none was, or
// the database predates them.
func (r DeviceCeilings) Get(ctx context.Context, device string) (DeviceCeiling, error) {
	if ok, err := atSchema(ctx, r.s.db, deviceCeilingsSchema); err != nil || !ok {
		if err == nil {
			err = ErrNotFound
		}
		return DeviceCeiling{}, fmt.Errorf("ceiling of device %s: %w", device, err)
	}
	var (
		ceiling, by string
		at          int64
	)
	err := r.s.queryRowLive(ctx, "device_ceilings", device,
		`SELECT ceiling, updated_at, updated_by`, ` FROM device_ceilings WHERE device_id = ?`, device).Scan(&ceiling, &at, &by)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return DeviceCeiling{}, fmt.Errorf("ceiling of device %s: %w", device, ErrNotFound)
		}
		return DeviceCeiling{}, fmt.Errorf("ceiling of device %s: %w", device, err)
	}
	return DeviceCeiling{DeviceID: device, Ceiling: json.RawMessage(ceiling), UpdatedAt: fromMillis(at), UpdatedBy: by}, nil
}

// SetDeviceCeiling records the capability ceiling the hub sets for a
// device.
type SetDeviceCeiling struct {
	Stamp
	DeviceID  string `json:"device_id"`
	Ceiling   string `json:"ceiling"`
	UpdatedAt int64  `json:"updated_at"`
	UpdatedBy string `json:"updated_by"`
}

// Op implements Command.
func (SetDeviceCeiling) Op() string { return "set_device_ceiling" }

func (SetDeviceCeiling) minSchema() int64 { return deviceCeilingsSchema }

func (c SetDeviceCeiling) apply(ctx context.Context, w *writer) (Result, error) {
	return Result{}, w.put(ctx, "device_ceilings", row{
		"device_id": c.DeviceID, "ceiling": c.Ceiling, "updated_at": c.UpdatedAt, "updated_by": c.UpdatedBy,
	})
}
