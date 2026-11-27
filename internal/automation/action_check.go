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

// buildCheckAction builds a check action: check names the kind (http, tcp
// or dns) and the other fields are that check trigger's, without every and
// for, so that the editor gives it a form as flat as a trigger's.
func buildCheckAction(p Params, probers Probers) (Action, error) {
	kind, line := "", 0
	rest := &yaml.Node{Kind: yaml.MappingNode, Line: p.node.Line}
	for i := 0; i+1 < len(p.node.Content); i += 2 {
		k, v := p.node.Content[i], p.node.Content[i+1]
		switch k.Value {
		case "check":
			if v.Kind != yaml.ScalarNode {
				return nil, lineError(v.Line, "check must be http, tcp or dns")
			}
			kind, line = v.Value, v.Line
		case "every", "for":
			return nil, lineError(k.Line, "a check action runs once: %s is for check triggers", k.Value)
		case "url", "status", "address", "name", "server", "from", "timeout":
			rest.Content = append(rest.Content, k, v)
		default:
			return nil, lineError(k.Line, "unknown field %q", k.Value)
		}
	}
	builders := map[string]func(Params, TriggerDeps) (Trigger, error){
		"http": buildHTTPCheck, "tcp": buildTCPCheck, "dns": buildDNSCheck,
	}
	build := builders[kind]
	switch {
	case kind == "":
		return nil, errors.New("check is required: http, tcp or dns")
	case build == nil:
		return nil, lineError(line, "check must be http, tcp or dns, not %q", kind)
	}
	t, err := build(Params{node: rest}, TriggerDeps{Probers: probers})
	if err != nil {
		return nil, err
	}
	c, ok := t.(*checkTrigger)
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
