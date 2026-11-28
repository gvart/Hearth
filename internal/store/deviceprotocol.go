// SPDX-License-Identifier: AGPL-3.0-only

package store

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
