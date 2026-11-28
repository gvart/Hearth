// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"errors"
	"fmt"
)

// ProtocolDeviceID is the id in the devices table of the Device Protocol
// device named name (docs/spec/device-protocol-v1.md): derived from the name,
// so every hub of a cluster registers it under one id, and 16 hex digits, so
// it never collides with an enrolled device's 20.
func ProtocolDeviceID(name string) string { return naturalID("protocol_devices", []byte(name)) }

// LabelSource is the label that tells what registered a device that has no
// agent; SourceDeviceProtocol is its value for a Device Protocol device.
const (
	LabelSource          = "hearth.source"
	SourceDeviceProtocol = "device-protocol"
)

// ErrDeviceHasCerts refuses to remove a device the hub issued certificates
// to: an enrolled device is revoked, not removed, and the tombstone's GC
// would delete its certificates with the row.
var ErrDeviceHasCerts = errors.New("the device has certificates: revoke it instead")

// RemoveDevice deletes a device without certificates, a Device Protocol
// device (#406), as a tombstone. It fails with ErrNotFound if there is none
// with ID, and with ErrDeviceHasCerts if the hub issued it any.
type RemoveDevice struct {
	Stamp
	ID string `json:"id"`
}

// Op implements Command.
func (RemoveDevice) Op() string { return "remove_device" }

func (c RemoveDevice) apply(ctx context.Context, w *writer) (Result, error) {
	certs, err := w.query(ctx, "certs", `device_id = ?`, "", c.ID)
	if err != nil {
		return Result{}, err
	}
	if len(certs) > 0 {
		return Result{}, ErrDeviceHasCerts
	}
	return deleteRow(ctx, w, "devices", c.ID)
}

// Remove deletes device id, or fails with ErrNotFound or ErrDeviceHasCerts.
// A device that announces itself again is a new row.
func (r Devices) Remove(ctx context.Context, id string) error {
	if _, err := r.s.apply(ctx, RemoveDevice{ID: id}); err != nil {
		return fmt.Errorf("remove device %s: %w", id, err)
	}
	return nil
}
