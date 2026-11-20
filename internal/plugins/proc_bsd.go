// SPDX-License-Identifier: AGPL-3.0-only

//go:build unix && !linux

package plugins

import "syscall"

// sysProcAttr puts a plugin in its own process group.
func sysProcAttr() *syscall.SysProcAttr { return &syscall.SysProcAttr{Setpgid: true} }
