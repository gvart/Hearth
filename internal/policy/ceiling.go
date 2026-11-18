// SPDX-License-Identifier: AGPL-3.0-only

package policy

import (
	"errors"
	"fmt"
	"slices"

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
