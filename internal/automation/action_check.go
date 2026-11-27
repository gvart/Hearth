// SPDX-License-Identifier: AGPL-3.0-only

package automation

import (
	"context"
	"errors"
	"fmt"

	"go.yaml.in/yaml/v3"

	"github.com/gvart/hearth/internal/policy"
)

// probeAction, the check action, runs an http, tcp or dns check once, from
// the hub or from a device, and fails when the check fails: to verify that a
// restart worked. It is automation.probe, class read, as a check trigger is.
type probeAction struct {
	c *checkTrigger
}

// buildCheckAction builds a check action from its check field, a mapping
// with the check's type and fields, as a runbook's check step takes it.
func buildCheckAction(p Params, probers Probers) (Action, error) {
	var cfg struct {
		Check yaml.Node `yaml:"check"`
	}
	if err := p.Decode(&cfg); err != nil {
		return nil, err
	}
	n := &cfg.Check
	if n.Kind != yaml.MappingNode {
		return nil, errors.New("check is required: a mapping with the check's type (http, tcp or dns) and fields")
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if k := n.Content[i]; k.Value == "every" || k.Value == "for" {
			return nil, lineError(k.Line, "a check action runs once: %s is for check triggers", k.Value)
		}
	}
	deps := TriggerDeps{Probers: probers}
	builders := map[string]Builder[Trigger]{
		"http": func(p Params) (Trigger, error) { return buildHTTPCheck(p, deps) },
		"tcp":  func(p Params) (Trigger, error) { return buildTCPCheck(p, deps) },
		"dns":  func(p Params) (Trigger, error) { return buildDNSCheck(p, deps) },
	}
	var errs []error
	list := &yaml.Node{Kind: yaml.SequenceNode, Line: n.Line, Content: []*yaml.Node{n}}
	built := buildSteps(list, "check", builders, &errs)
	if len(errs) > 0 {
		return nil, errs[0]
	}
	c, ok := built[0].Impl.(*checkTrigger)
	if !ok {
		return nil, errors.New("check must be an http, tcp or dns check")
	}
	return &probeAction{c: c}, nil
}

func (a *probeAction) Describe() string {
	where := "the hub"
	if a.c.from != "" {
		where = "device " + a.c.from
	}
	return fmt.Sprintf("check %s from %s; fail if it fails", a.c.what, where)
}

func (a *probeAction) Policy() policy.Action { return policy.AutomationProbe }

func (a *probeAction) Target() Text { return Literal(a.c.from) }

// Precheck refuses a check from a device whose reported ceiling does not
// allow probes, as a check trigger's decision does.
func (a *probeAction) Precheck(ctx context.Context, _ Event) error {
	if a.c.from == "" || a.c.probers == nil {
		return nil
	}
	return a.c.probers.CheckProbe(ctx, a.c.from)
}

func (a *probeAction) Run(ctx context.Context, _ Event) error {
	if a.c.from != "" && a.c.probers == nil {
		return errors.New("this hub does not run checks from devices")
	}
	ran, err := a.c.run(ctx)
	switch {
	case !ran:
		return fmt.Errorf("check %s cannot run from device %s: %w", a.c.what, a.c.from, err)
	case err != nil:
		return fmt.Errorf("check %s failed: %w", a.c.what, err)
	}
	return nil
}
