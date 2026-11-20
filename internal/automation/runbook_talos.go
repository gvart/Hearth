// SPDX-License-Identifier: AGPL-3.0-only

package automation

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/gvart/hearth/internal/integrations/talos"
	"github.com/gvart/hearth/internal/policy"
)

// TalosNodes reads the Talos nodes of the hub's talosconfig, for a runbook's
// talos_node checks: *talos.Client. Read must not audit: the engine runs it
// inside its own policy decision on policy.TalosRead.
type TalosNodes interface {
	// Target names what is read: the context and its first endpoint.
	Target() string
	// Read reads every node of the talosconfig once. A node the API cannot
	// reach comes back with its Error set.
	Read(ctx context.Context) ([]talos.Node, error)
}

// errNoTalos fails a talos_node check on a hub that cannot run one.
var errNoTalos = errors.New("this hub reads no Talos nodes: start it with --talosconfig (see docs/talos.md)")

// errTalosNotGranted refuses a read outside a policy decision on
// policy.TalosRead.
var errTalosNotGranted = errors.New("a Talos read needs a talos.read decision")

// talosNodeCheck is a check that a Talos node answers, and runs a version or
// has every service healthy, read by the hub through the Talos API.
type talosNodeCheck struct {
	// node is the node's address as the talosconfig names it, or its
	// hostname.
	node string
	// version is the Talos version the node must run; "" for any.
	version string
	healthy bool
}

// run reads the nodes once. Every failure is one the step polls through: a
// node that reboots cannot be read, and may not be found by its hostname,
// until it is back.
func (t *talosNodeCheck) run(ctx context.Context, nodes TalosNodes) error {
	if !policy.Granted(ctx, policy.TalosRead) {
		return errTalosNotGranted
	}
	all, err := nodes.Read(ctx)
	if err != nil {
		return fmt.Errorf("read the Talos nodes through %s: %w", nodes.Target(), err)
	}
	var read []string
	for _, n := range all {
		if n.Address != t.node && (n.Hostname == "" || n.Hostname != t.node) {
			read = append(read, n.Address)
			continue
		}
		return t.verify(n)
	}
	return fmt.Errorf("node %s is not among the nodes read through %s (%s): name it as the talosconfig or --talos-nodes does",
		t.node, nodes.Target(), strings.Join(read, ", "))
}

// verify checks the node n that was read.
func (t *talosNodeCheck) verify(n talos.Node) error {
	if n.Error != "" {
		return fmt.Errorf("node %s cannot be read: %s", t.node, n.Error)
	}
	if t.version != "" && strings.TrimPrefix(n.Version, "v") != strings.TrimPrefix(t.version, "v") {
		return fmt.Errorf("node %s runs %s, not %s", t.node, n.Version, t.version)
	}
	if t.healthy && !n.Healthy {
		var bad []string
		for _, s := range n.Services {
			if s.State != "Running" && s.State != "Finished" || s.Health == talos.HealthUnhealthy {
				msg := s.ID + " " + s.State + " " + s.Health
				if s.Message != "" {
					msg += ": " + s.Message
				}
				bad = append(bad, msg)
			}
		}
		if len(bad) == 0 {
			bad = append(bad, "no services reported")
		}
		return fmt.Errorf("node %s (%s) is not healthy: %s", t.node, n.Version, strings.Join(bad, "; "))
	}
	return nil
}

// buildTalosNodeCheck builds a runbook's talos_node check. It runs from the
// hub only: it has no from.
func buildTalosNodeCheck(p Params) (Trigger, error) {
	var cfg struct {
		Node    string `yaml:"node"`
		Version string `yaml:"version"`
		Healthy bool   `yaml:"healthy"`
	}
	if err := p.Decode(&cfg); err != nil {
		return nil, err
	}
	if cfg.Node == "" || strings.ContainsAny(cfg.Node, " \t\r\n") {
		return nil, errors.New("node is required: the node's address as the talosconfig names it, or its hostname")
	}
	if strings.ContainsAny(cfg.Version, " \t\r\n") {
		return nil, errors.New("version must be a Talos version, such as v1.12.8")
	}
	what := "Talos node " + cfg.Node + " answers"
	switch {
	case cfg.Version != "" && cfg.Healthy:
		what = fmt.Sprintf("Talos node %s runs %s and is healthy", cfg.Node, cfg.Version)
	case cfg.Version != "":
		what = fmt.Sprintf("Talos node %s runs %s", cfg.Node, cfg.Version)
	case cfg.Healthy:
		what = fmt.Sprintf("Talos node %s is healthy", cfg.Node)
	}
	return &checkTrigger{
		what:      what,
		target:    cfg.Node,
		talosNode: &talosNodeCheck{node: cfg.Node, version: cfg.Version, healthy: cfg.Healthy},
	}, nil
}
