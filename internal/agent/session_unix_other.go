// SPDX-License-Identifier: AGPL-3.0-only

//go:build unix && !linux && !darwin

package agent

// processes lists no processes here: closing a shell signals its process
// group only.
func processes() []int { return nil }
