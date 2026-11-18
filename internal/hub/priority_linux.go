// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"fmt"
	"os"
	"strconv"
	"syscall"
)

// lowerPriority sets every thread of this process to nice 19. On Linux nice is
// per thread, and a new thread inherits it from the thread that creates it, so
// once all current threads are niced every later one is too. It repeats until
// a pass finds no thread it has not niced.
func lowerPriority() error {
	done := map[int]bool{}
	for {
		ents, err := os.ReadDir("/proc/self/task")
		if err != nil {
			return fmt.Errorf("list threads: %w", err)
		}
		fresh := false
		for _, e := range ents {
			tid, err := strconv.Atoi(e.Name())
			if err != nil || done[tid] {
				continue
			}
			fresh = true
			// A thread may exit between the listing and this call; that is fine.
			if err := syscall.Setpriority(syscall.PRIO_PROCESS, tid, lowestPriority); err != nil && err != syscall.ESRCH {
				return fmt.Errorf("nice thread %d: %w", tid, err)
			}
			done[tid] = true
		}
		if !fresh {
			return nil
		}
	}
}
