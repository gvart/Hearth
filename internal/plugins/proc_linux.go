// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package plugins

import "syscall"

// sysProcAttr puts a plugin in its own process group, and has the kernel
// kill it should the hub die without stopping it.
func sysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
}
