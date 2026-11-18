// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"fmt"
	"syscall"
)

// lowerPriority sets this process to nice 19 (on macOS nice is per process).
func lowerPriority() error {
	if err := syscall.Setpriority(syscall.PRIO_PROCESS, 0, lowestPriority); err != nil {
		return fmt.Errorf("nice: %w", err)
	}
	return nil
}
