// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/gvart/hearth/internal/policy"
	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
)

// Ceiling is what this device lets the hub run: its capability ceiling, the
// union of the agent's flags and the ceiling the hub manages for it (see
// ceiling.go). The agent enforces it itself. The zero Ceiling allows
// nothing.
type Ceiling struct {
	// Exec are the programs the hub may run, matched exactly against argv[0]
	// as the hub sends it, with any arguments.
	Exec []string
	// Restart are the services the hub may restart, as manager:name, where
	// manager is systemd, systemd-user or docker and name a name or a glob
	// such as *.
	Restart []string
	// Probe lets the hub run HTTP, TCP and DNS checks from this device: the
	// http, tcp and dns automation triggers with from: set to it.
	Probe bool
	// Logs are the log sources the hub may stream, as manager:pattern,
	// where manager is systemd, systemd-user or docker and pattern a name or
	// a glob such as *.
	Logs []string
	// Shell lets the hub open an interactive shell here, as the agent's
	// user: the web UI's terminal. It is as much as the agent's user can do.
	Shell bool
	// Scan are the IPv4 subnets the hub may have this device sweep for
	// network discovery (see ParseScan); none allows no scan.
	Scan []string
	// NetEdges lets the agent report its network edges: its neighbour table
	// and a summary of its established TCP connections (see netedges.go).
	NetEdges bool
	// Docker lets the hub list the containers and images of this device's
	// Docker or Podman engine, read a bounded tail of a container's log, and
	// start, stop and restart its containers (see docker.go).
	Docker bool
	// DockerRead lets the hub list the containers and images and read a
	// container's log, but not start, stop or restart one. Docker implies it.
	DockerRead bool
	// Plugins are the exec plugins the hub may install and run here, each
	// with the highest class of command it may run (see plugins.go), sorted
	// by name.
	Plugins []PluginGrant
}

// Service managers a restart may name.
var restartManagers = []string{"systemd", "systemd-user", "docker"}

// ParseRestart checks a Ceiling.Restart entry: manager:name, where name may
// be a glob (path.Match).
func ParseRestart(entry string) error {
	manager, name, ok := strings.Cut(entry, ":")
	if !ok || name == "" || !slices.Contains(restartManagers, manager) {
		return fmt.Errorf("restart entry %q: want manager:name with manager one of %s", entry, strings.Join(restartManagers, ", "))
	}
	if _, err := path.Match(name, ""); err != nil {
		return fmt.Errorf("restart entry %q: %w", entry, err)
	}
	return nil
}

const (
	// defaultExecTimeout applies when a request sets none.
	defaultExecTimeout = time.Minute
	// maxExecTimeout caps what the hub may ask for.
	maxExecTimeout = 10 * time.Minute
	// stderrTail is how much of stderr a failure reports.
	stderrTail = 256
)

// proto is the ceiling as the agent reports it to the hub.
func (c Ceiling) proto() *agentv1.Ceiling {
	return &agentv1.Ceiling{
		Exec: slices.Clone(c.Exec), Restart: slices.Clone(c.Restart), Probe: c.Probe, Logs: slices.Clone(c.Logs),
		Shell: c.Shell, Scan: slices.Clone(c.Scan), NetEdges: c.NetEdges, Docker: c.Docker, DockerRead: c.DockerRead,
		Plugins: grantsProto(c.Plugins),
	}
}

// command returns the program and arguments req runs, or an error wrapping
// policy.ErrBeyondCeiling. The hub checks the same before it sends req; the
// agent never relies on that. No shell is involved: argv goes to
// exec.Command as is.
func (c Ceiling) command(req *agentv1.ExecRequest) ([]string, error) {
	if err := policy.WithinCeiling(c.proto(), req); err != nil {
		return nil, err
	}
	switch a := req.GetAction().(type) {
	case *agentv1.ExecRequest_Command:
		return a.Command.GetArgv(), nil
	case *agentv1.ExecRequest_Restart:
		m, name := a.Restart.GetManager(), a.Restart.GetName()
		switch m {
		case "systemd":
			return []string{"systemctl", "restart", "--", name}, nil
		case "systemd-user":
			return []string{"systemctl", "--user", "restart", "--", name}, nil
		case "docker":
			return []string{"docker", "restart", "--", name}, nil
		}
		return nil, fmt.Errorf("unknown service manager %q", m)
	}
	return nil, errors.New("unknown action")
}

// execute runs req if the ceiling allows it and reports the outcome.
func (c Ceiling) execute(ctx context.Context, req *agentv1.ExecRequest) *agentv1.ExecResult {
	res := &agentv1.ExecResult{Id: req.GetId(), ExitCode: -1}
	argv, err := c.command(req)
	if err != nil {
		res.Denied = errors.Is(err, policy.ErrBeyondCeiling)
		res.Error = err.Error()
		return res
	}
	timeout := defaultExecTimeout
	if d := req.GetTimeout().AsDuration(); d > 0 {
		timeout = min(d, maxExecTimeout)
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...) //nolint:gosec // argv[0] is in the ceiling; no shell
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err = cmd.Run()
	if cmd.ProcessState != nil {
		res.ExitCode = int32(cmd.ProcessState.ExitCode()) //nolint:gosec // exit statuses fit in int32
	}
	if err != nil {
		if ctx.Err() != nil {
			err = fmt.Errorf("%w after %s", ctx.Err(), timeout)
		}
		res.Error = err.Error()
		if tail := lastBytes(stderr.Bytes(), stderrTail); tail != "" {
			res.Error += ": " + tail
		}
	}
	return res
}

// lastBytes is the trimmed end of b, at most n bytes, cut on a rune boundary.
func lastBytes(b []byte, n int) string {
	b = bytes.TrimSpace(b)
	if len(b) > n {
		b = b[len(b)-n:]
		for len(b) > 0 && !utf8.RuneStart(b[0]) {
			b = b[1:]
		}
	}
	return string(b)
}
