// SPDX-License-Identifier: AGPL-3.0-only

// Command hearth is the single Hearth binary. It runs as a hub (`hearth hub`)
// or as an agent (`hearth agent`) on every device in the lab.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/gvart/hearth/internal/agent"
)

// Set at link time via -ldflags "-X main.version=... -X main.commit=... -X main.date=...".
var (
	version = "dev"
	commit  = ""
	date    = ""
)

func main() {
	os.Exit(run())
}

func run() int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cmd := newRootCmd(resolveBuildInfo(version, commit, date))
	if err := cmd.ExecuteContext(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		if errors.Is(err, agent.ErrRevoked) {
			return agent.ExitRevoked // the service unit does not restart on it
		}
		return 1
	}
	return 0
}
