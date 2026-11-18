// SPDX-License-Identifier: AGPL-3.0-only

package policy

import (
	"errors"
	"fmt"
	"path"
	"slices"
	"strings"

	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
)

// WithinCeiling checks req against a device's capability ceiling c, as the
// hub does before it sends req and the agent does again before it runs it.
// It returns an error wrapping ErrBeyondCeiling when c does not allow req;
// a nil c allows nothing.
func WithinCeiling(c *agentv1.Ceiling, req *agentv1.ExecRequest) error {
	switch a := req.GetAction().(type) {
	case *agentv1.ExecRequest_Command:
		argv := a.Command.GetArgv()
		if len(argv) == 0 || argv[0] == "" {
			return errors.New("empty command")
		}
		if !slices.Contains(c.GetExec(), argv[0]) {
			return fmt.Errorf("exec %s: %w", argv[0], ErrBeyondCeiling)
		}
		return nil
	case *agentv1.ExecRequest_Restart:
		service := a.Restart.GetManager() + ":" + a.Restart.GetName()
		if !slices.Contains(c.GetRestart(), service) {
			return fmt.Errorf("restart %s: %w", service, ErrBeyondCeiling)
		}
		return nil
	}
	return errors.New("unknown action")
}

// ProbeWithinCeiling checks a ProbeRequest against a device's capability
// ceiling c, as the hub does before it sends one and the agent does again
// before it runs it. It returns an error wrapping ErrBeyondCeiling unless c
// allows probes; a nil c allows nothing.
func ProbeWithinCeiling(c *agentv1.Ceiling) error {
	if !c.GetProbe() {
		return fmt.Errorf("probe: %w", ErrBeyondCeiling)
	}
	return nil
}

// LogsWithinCeiling checks a log source against a device's capability
// ceiling c, as the hub does before it sends a LogRequest and the agent does
// again before it reads the source. A ceiling entry manager:pattern allows
// the sources of that manager whose name matches pattern (path.Match, so
// "*" allows them all). It returns an error wrapping ErrBeyondCeiling
// unless an entry allows src; a nil c allows nothing.
func LogsWithinCeiling(c *agentv1.Ceiling, src *agentv1.LogSource) error {
	if src.GetManager() == "" || src.GetName() == "" {
		return errors.New("empty log source")
	}
	for _, e := range c.GetLogs() {
		manager, pattern, ok := strings.Cut(e, ":")
		if !ok || manager != src.GetManager() {
			continue
		}
		if m, err := path.Match(pattern, src.GetName()); err == nil && m {
			return nil
		}
	}
	return fmt.Errorf("logs %s:%s: %w", src.GetManager(), src.GetName(), ErrBeyondCeiling)
}
