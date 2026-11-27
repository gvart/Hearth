// SPDX-License-Identifier: AGPL-3.0-only

package automation

import (
	"encoding/hex"
	"errors"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/gvart/hearth/internal/policy"
	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
)

// A local automation (`local: true`, #70) runs on the device its checks run
// from, by that device's agent, so that it keeps working while no hub is
// reachable: a DNS watchdog on the Pi that serves DNS. The hub pushes it to
// the agent instead of watching its triggers. Only a narrow subset of
// automations qualifies, checked when the file loads:
//
//   - triggers: http, tcp or dns checks, all with the same from;
//   - actions: restart a service on that device (device written as from
//     is), or a check from it;
//   - mode single, and no conditions.

// localShape checks that a, marked local, is an automation a device can run
// alone. line is where local is set.
func localShape(a *Automation, line int, errs *[]error) {
	if a.Mode != ModeSingle {
		*errs = append(*errs, lineError(line, "a local automation runs one run at a time: mode must be single"))
	}
	if len(a.Conditions) > 0 {
		*errs = append(*errs, lineError(a.Conditions[0].Line, "a local automation cannot have conditions"))
	}
	device := ""
	for _, t := range a.Triggers {
		c, ok := t.Impl.(*checkTrigger)
		if !ok || c.from == "" {
			*errs = append(*errs, lineError(t.Line,
				"trigger %s: a local automation's triggers must be http, tcp or dns checks with from: the device that runs it", t.ID))
			continue
		}
		if device == "" {
			device = c.from
		} else if c.from != device {
			*errs = append(*errs, lineError(t.Line,
				"trigger %s: every check of a local automation must run from the same device (%s, not %s)", t.ID, device, c.from))
		}
	}
	if device == "" {
		return
	}
	for _, s := range a.Actions {
		switch impl := s.Impl.(type) {
		case *agentAction:
			if impl.policy != policy.AutomationRestart {
				break
			}
			if impl.device.t != nil || impl.device.raw != device {
				*errs = append(*errs, lineError(s.Line,
					"action %s: a local automation restarts services on its own device only: device must be %s, as its checks' from", s.ID, device))
			}
			continue
		case *probeAction:
			if impl.c.from != device {
				*errs = append(*errs, lineError(s.Line,
					"action %s: a local automation's check must run from its device: from must be %s", s.ID, device))
			}
			continue
		}
		*errs = append(*errs, lineError(s.Line,
			"action %s: a local automation can only restart a service on its device or run a check from it, not %s", s.ID, s.Type))
	}
}

// LocalDevice is the device a local automation runs on, as its checks name
// it in from; "" when a is not local.
func (a *Automation) LocalDevice() string {
	if !a.Local || len(a.Triggers) == 0 {
		return ""
	}
	if c, ok := a.Triggers[0].Impl.(*checkTrigger); ok {
		return c.from
	}
	return ""
}

// LocalRule is a, a local automation, as its device's agent runs it.
func (a *Automation) LocalRule() (*agentv1.LocalRule, error) {
	if a.LocalDevice() == "" {
		return nil, errors.New("not a local automation")
	}
	r := &agentv1.LocalRule{Id: a.ID, Digest: hex.EncodeToString(a.sum[:])}
	for _, t := range a.Triggers {
		c := t.Impl.(*checkTrigger) //nolint:forcetypeassert // localShape checked it
		probe := proto.CloneOf(c.req)
		probe.Timeout = durationpb.New(c.timing.Timeout)
		r.Triggers = append(r.Triggers, &agentv1.LocalTrigger{
			Id: t.ID, Type: t.Type, Probe: probe, Target: c.target,
			Every: durationpb.New(c.timing.Every), Hold: durationpb.New(c.timing.For),
		})
	}
	for _, s := range a.Actions {
		la := &agentv1.LocalAction{Id: s.ID, Type: s.Type}
		switch impl := s.Impl.(type) {
		case *agentAction:
			la.Timeout = durationpb.New(impl.timeout)
			la.Action = &agentv1.LocalAction_Restart{Restart: impl.req().GetRestart()}
		case *probeAction:
			probe := proto.CloneOf(impl.c.req)
			probe.Timeout = durationpb.New(impl.c.timing.Timeout)
			la.Timeout = probe.Timeout
			la.Action = &agentv1.LocalAction_Check{Check: probe}
		default:
			return nil, errors.New("not a local automation")
		}
		r.Actions = append(r.Actions, la)
	}
	return r, nil
}

// Local returns the local automations this runtime loaded: the hub pushes
// them to their devices' agents and watches none of their triggers.
func (r *Runtime) Local() []*Automation {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []*Automation
	for _, in := range r.live {
		if in.a.Local {
			out = append(out, in.a)
		}
	}
	return out
}
