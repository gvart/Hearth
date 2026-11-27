// SPDX-License-Identifier: AGPL-3.0-only

package agent

import "strings"

// ServiceName is the agent's Windows service, and the source of its
// entries in the Windows event log.
const ServiceName = "hearth-agent"

// Event log entry types of a log line, as eventLevel returns them.
const (
	eventInfo = iota
	eventWarning
	eventError
)

// eventLevel is the event log entry type of a line of the agent's text log
// (log/slog's TextHandler, whose first level= field is the record's level):
// an error, a warning, or else information.
func eventLevel(line string) int {
	_, rest, _ := strings.Cut(line, " level=")
	switch {
	case strings.HasPrefix(rest, "ERROR"):
		return eventError
	case strings.HasPrefix(rest, "WARN"):
		return eventWarning
	}
	return eventInfo
}
