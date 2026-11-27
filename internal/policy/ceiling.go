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
		if a.Restart.GetName() == "" || !matchEntry(c.GetRestart(), a.Restart.GetManager(), a.Restart.GetName()) {
			return fmt.Errorf("restart %s: %w", service, ErrBeyondCeiling)
		}
		return nil
	}
	return errors.New("unknown action")
}

// matchEntry reports whether one of entries, each manager:pattern, allows
// name of manager: the pattern is a name or a glob (path.Match, so "*"
// allows every name). A requested name with a glob character of its own is
// never allowed: systemctl and journalctl expand it, so web*.service would
// reach every unit a grant of web?.service matched.
func matchEntry(entries []string, manager, name string) bool {
	if strings.ContainsAny(name, globChars) {
		return false
	}
	for _, e := range entries {
		m, pattern, ok := strings.Cut(e, ":")
		if !ok || m != manager {
			continue
		}
		if ok, err := path.Match(pattern, name); err == nil && ok {
			return true
		}
	}
	return false
}

// IsPattern reports whether a manager:pattern ceiling entry is a glob rather
// than one name: it allows a set of names, and names no one service.
func IsPattern(entry string) bool {
	_, pattern, _ := strings.Cut(entry, ":")
	return strings.ContainsAny(pattern, globChars)
}

// globChars are the characters that make a name a glob (path.Match), and
// that systemctl and journalctl expand.
const globChars = `*?[\`

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
	if matchEntry(c.GetLogs(), src.GetManager(), src.GetName()) {
		return nil
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
// before it asks the engine. Listing and reading a log need docker or
// docker_read; a start, stop or restart needs docker. It returns an error
// wrapping ErrBeyondCeiling unless c allows req, and one wrapping ErrDenied
// for a request no agent takes: an unknown operation or verb, or an invalid
// container. A nil c allows nothing.
func DockerWithinCeiling(c *agentv1.Ceiling, req *agentv1.DockerRequest) error {
	if !c.GetDocker() && !c.GetDockerRead() {
		return fmt.Errorf("docker: %w", ErrBeyondCeiling)
	}
	var container string
	switch op := req.GetOp().(type) {
	case *agentv1.DockerRequest_List:
		return nil
	case *agentv1.DockerRequest_Action:
		if !c.GetDocker() {
			return fmt.Errorf("docker %s: read only: %w", op.Action.GetVerb(), ErrBeyondCeiling)
		}
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

// ceilingManagers are the service managers a logs or restart entry names.
var ceilingManagers = []string{"systemd", "systemd-user", "docker"}

// CheckHubCeiling checks a ceiling the hub sets for a device (#346), entry
// by entry, as the agent checks its flags: programs are absolute paths,
// matched exactly; logs and restart entries are manager:pattern with
// manager systemd, systemd-user or docker and pattern a name or a glob; scan
// entries are IPv4 subnets. The hub checks it before it stores it, and the
// agent again before it applies it.
func CheckHubCeiling(c *agentv1.Ceiling) error {
	for _, e := range c.GetExec() {
		if !strings.HasPrefix(e, "/") || path.Clean(e) != e {
			return fmt.Errorf("exec entry %q: want an absolute path", e)
		}
	}
	entries := func(what string, list []string) error {
		for _, e := range list {
			manager, pattern, ok := strings.Cut(e, ":")
			if !ok || pattern == "" || !slices.Contains(ceilingManagers, manager) {
				return fmt.Errorf("%s entry %q: want manager:name with manager one of %s", what, e, strings.Join(ceilingManagers, ", "))
			}
			if _, err := path.Match(pattern, ""); err != nil {
				return fmt.Errorf("%s entry %q: %w", what, e, err)
			}
		}
		return nil
	}
	if err := entries("logs", c.GetLogs()); err != nil {
		return err
	}
	if err := entries("restart", c.GetRestart()); err != nil {
		return err
	}
	for _, e := range c.GetScan() {
		if p, err := netip.ParsePrefix(e); err != nil || !p.Addr().Is4() {
			return fmt.Errorf("scan entry %q: want an IPv4 subnet such as 192.168.1.0/24", e)
		}
	}
	return CheckPluginGrants(c.GetPlugins())
}

// CheckPluginGrants checks a ceiling's plugin grants: each names a plugin
// (letters, digits, '.', '_' and '-'; up to 64) once, with a class of read,
// safe or dangerous.
func CheckPluginGrants(grants []*agentv1.PluginGrant) error {
	seen := map[string]bool{}
	for _, g := range grants {
		if !ValidPluginName(g.GetName()) {
			return fmt.Errorf("plugin entry %q: want 1-64 letters, digits, '.', '_' or '-'", g.GetName())
		}
		if _, ok := classRank[Class(g.GetMaxClass())]; !ok {
			return fmt.Errorf("plugin entry %s: class %q: want read, safe or dangerous", g.GetName(), g.GetMaxClass())
		}
		if seen[g.GetName()] {
			return fmt.Errorf("plugin entry %s: listed twice", g.GetName())
		}
		seen[g.GetName()] = true
	}
	return nil
}

// ValidPluginName reports whether name may name an exec plugin: 1-64
// letters, digits, '.', '_' and '-', starting with a letter or digit. A
// plugin's name becomes a directory on the device, so nothing else is.
func ValidPluginName(name string) bool {
	if name == "" || len(name) > 64 {
		return false
	}
	for i, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case i > 0 && (r == '_' || r == '.' || r == '-'):
		default:
			return false
		}
	}
	return true
}

// PluginGrantOf is the class c allows for plugin name's commands, and
// whether c allows the plugin at all.
func PluginGrantOf(c *agentv1.Ceiling, name string) (Class, bool) {
	for _, g := range c.GetPlugins() {
		if g.GetName() == name {
			if _, ok := classRank[Class(g.GetMaxClass())]; ok {
				return Class(g.GetMaxClass()), true
			}
			return "", false
		}
	}
	return "", false
}

// PluginWithinCeiling checks a command of class of plugin name against a
// device's capability ceiling c, as the hub does before it sends one and
// the agent does again, with the class its installed manifest declares,
// before it runs it. An empty class checks only that c allows the plugin, as
// installing it needs. It returns an error wrapping ErrBeyondCeiling unless
// c allows the plugin up to class; a nil c allows nothing.
func PluginWithinCeiling(c *agentv1.Ceiling, name string, class Class) error {
	limit, ok := PluginGrantOf(c, name)
	if !ok {
		return fmt.Errorf("plugin %s: not allowed on this device: %w", name, ErrBeyondCeiling)
	}
	if class != "" && !Within(class, limit) {
		return fmt.Errorf("plugin %s: a %s command is above the %s the device allows: %w", name, class, limit, ErrBeyondCeiling)
	}
	return nil
}

// ClassAbove reports whether class a ranks above class b.
func ClassAbove(a, b Class) bool { return classRank[a] > classRank[b] }
