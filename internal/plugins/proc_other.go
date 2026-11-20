// SPDX-License-Identifier: AGPL-3.0-only

//go:build !unix

package plugins

import (
	"os"
	"os/exec"
)

// inOwnGroup does nothing: killTree kills the plugin only.
func inOwnGroup(*exec.Cmd) {}

// killTree kills the plugin.
func killTree(p *os.Process) { _ = p.Kill() }
