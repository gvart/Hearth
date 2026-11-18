// SPDX-License-Identifier: AGPL-3.0-only

//go:build !linux && !darwin

package hub

// lowerPriority is a no-op here: the child still keeps the hash off the hub's
// Go scheduler, without a lower OS priority.
func lowerPriority() error { return nil }
