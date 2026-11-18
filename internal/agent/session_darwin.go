// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"os"

	"golang.org/x/sys/unix"
)

// processes lists the ids of this user's running processes: the only ones
// the agent may signal.
func processes() []int {
	procs, err := unix.SysctlKinfoProcSlice("kern.proc.uid", os.Getuid())
	if err != nil {
		return nil
	}
	pids := make([]int, 0, len(procs))
	for _, p := range procs {
		pids = append(pids, int(p.Proc.P_pid))
	}
	return pids
}
