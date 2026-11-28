// SPDX-License-Identifier: AGPL-3.0-only

//go:build !windows

package agent

import (
	"context"
	"errors"

	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
)

// errNoEventLog ends an event log source on a device without one.
var errNoEventLog = errors.New("the event log is Windows only: this device has none")

// readEventLog refuses: only Windows has an event log.
func readEventLog(context.Context, string, int, func(*agentv1.LogLine)) error {
	return errNoEventLog
}
