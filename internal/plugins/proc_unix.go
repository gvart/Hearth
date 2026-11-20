// SPDX-License-Identifier: AGPL-3.0-only

//go:build unix

package plugins

import (
	"os"
	"os/exec"
	"syscall"
)

// inOwnGroup starts cmd in a process group of its own, so that killTree
// reaches whatever it starts too, such as the program a wrapper runs.
func inOwnGroup(cmd *exec.Cmd) { cmd.SysProcAttr = sysProcAttr() }

// killTree kills the plugin's process group, and the plugin.
func killTree(p *os.Process) {
	_ = syscall.Kill(-p.Pid, syscall.SIGKILL)
	_ = p.Kill()
}
