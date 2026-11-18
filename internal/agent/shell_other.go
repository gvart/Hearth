// SPDX-License-Identifier: AGPL-3.0-only

//go:build !unix

package agent

import (
	"errors"

	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
)

// ShellSupported reports whether this agent can run interactive shells.
const ShellSupported = false

// errShellUnsupported is the refusal of an agent that cannot run shells.
var errShellUnsupported = errors.New("interactive shells are not supported on this platform")

// startShell refuses: there is no PTY here.
func startShell(*agentv1.TerminalSize, []string) (*shell, error) { return nil, errShellUnsupported }

func (*shell) resize(*agentv1.TerminalSize) error { return errShellUnsupported }

func hangupSession(int) {}

func killSession(int) {}
