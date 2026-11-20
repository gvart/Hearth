// SPDX-License-Identifier: AGPL-3.0-only

package policy

import (
	"errors"
	"fmt"
	"net/netip"
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

// ShellWithinCeiling checks a shell session against a device's capability
// ceiling c, as the hub does before it opens one and the agent does again
// before it starts the shell. It returns an error wrapping ErrBeyondCeiling
// unless c allows shells; a nil c allows nothing.
func ShellWithinCeiling(c *agentv1.Ceiling) error {
	if !c.GetShell() {
		return fmt.Errorf("shell: %w", ErrBeyondCeiling)
	}
	return nil
}

// ScanWithinCeiling checks a network scan of subnets against a device's
// capability ceiling c, as the hub does before it sends a ScanRequest and the
// agent does again before it sweeps. Each subnet must lie within one of the
// ceiling's scan subnets: a /24 ceiling allows that /24 or a part of it, never
// a wider one. It returns an error wrapping ErrBeyondCeiling unless every
// subnet is allowed; a nil c, or one with no scan subnet, allows none.
func ScanWithinCeiling(c *agentv1.Ceiling, subnets []netip.Prefix) error {
	if len(subnets) == 0 {
		return errors.New("no subnet to scan")
	}
	var allowed []netip.Prefix
	for _, e := range c.GetScan() {
		if p, err := netip.ParsePrefix(e); err == nil {
			allowed = append(allowed, p.Masked())
		}
	}
	for _, s := range subnets {
		if !slices.ContainsFunc(allowed, func(a netip.Prefix) bool {
			return a.Addr().Is4() == s.Addr().Is4() && a.Bits() <= s.Bits() && a.Contains(s.Addr())
		}) {
			return fmt.Errorf("scan %s: %w", s, ErrBeyondCeiling)
		}
	}
	return nil
}

// DockerVerbs are the container actions a DockerAction may name.
var DockerVerbs = []string{"start", "stop", "restart"}

// MaxDockerLogTail caps the lines a DockerLogs request reads.
const MaxDockerLogTail = 200

// ValidContainer reports whether ref may name a container in a request to a
// Docker engine: an id or a name, letters, digits, '_', '.' and '-', starting
// with a letter or digit, at most 128 characters. Nothing else reaches the
// engine's URL, so no ref can add a path segment or a query.
func ValidContainer(ref string) bool {
	if ref == "" || len(ref) > 128 {
		return false
	}
	for i, r := range ref {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case i > 0 && (r == '_' || r == '.' || r == '-'):
		default:
			return false
		}
	}
	return true
}

// DockerWithinCeiling checks a DockerRequest against a device's capability
// ceiling c, as the hub does before it sends one and the agent does again
// before it asks the engine. It returns an error wrapping ErrBeyondCeiling
// unless c allows docker, and one wrapping ErrDenied for a request no agent
// takes: an unknown operation or verb, or an invalid container. A nil c
// allows nothing.
func DockerWithinCeiling(c *agentv1.Ceiling, req *agentv1.DockerRequest) error {
	if !c.GetDocker() {
		return fmt.Errorf("docker: %w", ErrBeyondCeiling)
	}
	var container string
	switch op := req.GetOp().(type) {
	case *agentv1.DockerRequest_List:
		return nil
	case *agentv1.DockerRequest_Action:
		if !slices.Contains(DockerVerbs, op.Action.GetVerb()) {
			return fmt.Errorf("docker %q: not a container action (start, stop, restart): %w", op.Action.GetVerb(), ErrDenied)
		}
		container = op.Action.GetContainer()
	case *agentv1.DockerRequest_Logs:
		container = op.Logs.GetContainer()
	default:
		return fmt.Errorf("docker: unknown operation: %w", ErrDenied)
	}
	if !ValidContainer(container) {
		return fmt.Errorf("docker: invalid container %q: %w", container, ErrDenied)
	}
	return nil
}
