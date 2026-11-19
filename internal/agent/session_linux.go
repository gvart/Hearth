// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"os"
	"strconv"
)

// processes lists the ids of the running processes.
func processes() []int {
	ents, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	var pids []int
	for _, e := range ents {
		if pid, err := strconv.Atoi(e.Name()); err == nil {
			pids = append(pids, pid)
		}
	}
	return pids
}
