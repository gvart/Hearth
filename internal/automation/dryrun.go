// SPDX-License-Identifier: AGPL-3.0-only

package automation

import (
	"context"
	"errors"
	"fmt"

	"github.com/gvart/hearth/internal/policy"
)

// DecidingPolicy is a Policy that can also say what it would decide:
// *policy.Engine.
type DecidingPolicy interface {
	Policy
	Check(req policy.Request) (decision, reason string)
}

// ActionDecision is what policy would decide on one action of an automation.
type ActionDecision struct {
	Step   string `json:"step"`
	Type   string `json:"type"`
	Action string `json:"action"`
	Class  string `json:"class"`
	// Target is the action's target as written: a template is not rendered.
	Target string `json:"target"`
	// Decision is policy.Allow, policy.Confirm or policy.Deny.
	Decision string `json:"decision"`
	Reason   string `json:"reason,omitempty"`
}

// errDryRunExecuted is never returned: policy runs no function in a dry run.
var errDryRunExecuted = errors.New("dry run reached an action")

// DryRun asks policy about every action of a, as the automation itself would
// ask when it runs, and reports the decisions. Each is audited with the result
// policy.DryRun and the detail requestedBy. It runs no action, and starts no
// trigger.
func DryRun(ctx context.Context, a *Automation, pol DecidingPolicy, requestedBy string) ([]ActionDecision, error) {
	var ev Event
	if len(a.Triggers) > 0 {
		t := a.Triggers[0]
		ev.TriggerID, ev.TriggerType, ev.Data = t.ID, t.Type, t.Impl.Sample()
	}
	out := make([]ActionDecision, 0, len(a.Actions))
	for _, s := range a.Actions {
		class, _ := policy.ClassOf(s.Impl.Policy())
		req := policy.Request{
			ActorKind: policy.ActorAutomation,
			ActorID:   a.ID,
			Action:    s.Impl.Policy(),
			Target:    s.Impl.Target().String(),
			Detail:    map[string]any{"step": s.ID, "requested_by": requestedBy},
			DryRun:    true,
		}
		if p, ok := s.Impl.(prechecker); ok {
			req.Precheck = func(ctx context.Context) error { return p.Precheck(ctx, ev) }
		}
		d := ActionDecision{
			Step: s.ID, Type: s.Type, Action: string(s.Impl.Policy()), Class: string(class), Target: req.Target,
		}
		err := pol.Do(ctx, req, func(context.Context) error { return errDryRunExecuted })
		switch {
		case errors.Is(err, policy.ErrDenied):
			d.Decision, d.Reason = policy.Deny, err.Error()
		case err != nil:
			return nil, fmt.Errorf("dry run of step %s: %w", s.ID, err)
		default:
			d.Decision, d.Reason = pol.Check(req)
		}
		out = append(out, d)
	}
	return out, nil
}
