// SPDX-License-Identifier: AGPL-3.0-only

//go:build !windows

package agent

import (
	"context"
	"io"
)

// RunService runs run until ctx is done, logging to logOut. On Windows,
// started by the service manager, it runs run as the agent's service.
func RunService(ctx context.Context, logOut io.Writer, run func(ctx context.Context, logOut io.Writer) error) error {
	return run(ctx, logOut)
}

// selfRestartRefusal says why the agent cannot upgrade itself here: never,
// off Windows. systemd (Restart=always) or launchd (KeepAlive) starts the
// new binary, and an agent run another way is upgraded by whoever runs it.
func selfRestartRefusal() string { return "" }
