// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/gvart/hearth/internal/policy"
)

// RoleChangeRequest is a promotion, demotion or removal the CLI on a
// master's host asks the running hub for (`hearth cluster promote|demote|
// remove`). The hub decides it with its own policy engine, so an isolated
// master refuses it as it refuses the UI.
type RoleChangeRequest struct {
	// Op is promote, demote or remove.
	Op     string `json:"op"`
	Member string `json:"member"`
	Role   string `json:"role,omitempty"`
	DryRun bool   `json:"dry_run,omitempty"`
	// Actor names the admin, as the audit log does (user@host).
	Actor string `json:"actor"`
}

// RoleChangeFunc runs a RoleChangeRequest through policy: the hub's master
// layer sets it while this member is a master.
type RoleChangeFunc func(ctx context.Context, req RoleChangeRequest) (any, error)

type roleChangeReply struct {
	Result json.RawMessage `json:"result,omitempty"`
	Error  *wireError      `json:"error,omitempty"`
}

// errDeniedKind is the wire kind of a policy denial.
const errDeniedKind = "denied"

// SetRoleChanges sets what runs the CLI's role changes; nil while this
// member is no master.
func (n *APNode) SetRoleChanges(f RoleChangeFunc) {
	if f == nil {
		n.changeFn.Store(nil)
		return
	}
	n.changeFn.Store(&f)
}

// serveRoleChange answers POST /v1/change on the control socket.
func (n *APNode) serveRoleChange(w http.ResponseWriter, r *http.Request) {
	var req RoleChangeRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<12)).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var reply roleChangeReply
	f := n.changeFn.Load()
	if f == nil {
		reply.Error = &wireError{Kind: "not_master", Message: ErrNotMasterHere.Error() + " (run the command on a master's host)"}
		writeJSON(w, reply)
		return
	}
	out, err := (*f)(r.Context(), req)
	switch {
	case err == nil:
		reply.Result, _ = json.Marshal(out)
	case errors.Is(err, policy.ErrDenied):
		reply.Error = &wireError{Kind: errDeniedKind, Message: err.Error()}
	default:
		reply.Error = &wireError{Kind: RoleErrorKind(err), Message: err.Error()}
	}
	writeJSON(w, reply)
}

// ChangeRoles asks the running hub to promote, demote or remove a member
// (RoleChangeRequest) and decodes its result into out. A refusal keeps its
// kind: errors.Is matches policy.ErrDenied and the role change errors.
func (c *ControlClient) ChangeRoles(ctx context.Context, req RoleChangeRequest, out any) error {
	// A change held for approval waits for it: no client timeout.
	var reply roleChangeReply
	if err := c.postWith(ctx, &http.Client{Transport: c.http.Transport}, "/v1/change", req, &reply); err != nil {
		return err
	}
	if reply.Error != nil {
		if reply.Error.Kind == errDeniedKind {
			return &kindError{msg: reply.Error.Message, target: policy.ErrDenied}
		}
		if target, ok := roleKinds[reply.Error.Kind]; ok {
			return &kindError{msg: reply.Error.Message, target: target}
		}
		return errors.New(reply.Error.Message)
	}
	if out != nil && len(reply.Result) > 0 {
		if err := json.Unmarshal(reply.Result, out); err != nil {
			return fmt.Errorf("hub control socket: decode result: %w", err)
		}
	}
	return nil
}

// CARequest is a hub CA rotation step the CLI on a master's host asks the
// running hub for (`hearth cluster ca rotate|finish|abort`). The hub decides
// it with its own policy engine, as it decides role changes.
type CARequest struct {
	// Op is rotate, finish or abort.
	Op             string `json:"op"`
	AcceptUnpinned bool   `json:"accept_unpinned,omitempty"`
	Force          bool   `json:"force,omitempty"`
	// Plan returns what the step would do, with no policy decision and no
	// audit entry.
	Plan bool `json:"plan,omitempty"`
	// DryRun decides and audits the step without doing it.
	DryRun bool `json:"dry_run,omitempty"`
	// Actor names the admin, as the audit log does (user@host).
	Actor string `json:"actor"`
}

// The hub CA rotation steps of a CARequest.
const (
	CAOpRotate = "rotate"
	CAOpFinish = "finish"
	CAOpAbort  = "abort"
)

// CAResult is what a CARequest did or would do, and for a dry run the
// policy decision.
type CAResult struct {
	Rotate   *RotatePlan `json:"rotate,omitempty"`
	Finish   *FinishPlan `json:"finish,omitempty"`
	Abort    *AbortPlan  `json:"abort,omitempty"`
	Decision string      `json:"decision,omitempty"`
}

type caChangeReply struct {
	Result CAResult   `json:"result"`
	Error  *wireError `json:"error,omitempty"`
}

// ChangeCA runs req on this master: it plans the step, then, unless
// req.Plan, has it decided by the master layer's policy engine (an isolated
// master refuses it) and audited as the admin req.Actor.
func (n *APNode) ChangeCA(ctx context.Context, req CARequest) (CAResult, error) {
	pol := n.caPolicy.Load()
	if pol == nil || !n.IsMaster() {
		return CAResult{}, ErrNotMasterHere
	}
	var (
		res  CAResult
		preq policy.Request
		do   func(context.Context) error
	)
	switch req.Op {
	case CAOpRotate:
		plan, err := n.RotateCA(ctx, RotateOptions{AcceptUnpinned: req.AcceptUnpinned, DryRun: true})
		res.Rotate = &plan
		if err != nil || req.Plan {
			return res, err
		}
		preq = policy.Request{Action: policy.ClusterCARotate, Target: "hub CA", Detail: map[string]any{
			"hubs": len(plan.Pins), "unpinned": len(plan.Unpinned), "accept_unpinned": req.AcceptUnpinned,
		}}
		do = func(ctx context.Context) error {
			plan, err := n.RotateCA(ctx, RotateOptions{AcceptUnpinned: req.AcceptUnpinned})
			res.Rotate = &plan
			return err
		}
	case CAOpFinish:
		plan, err := n.FinishCA(ctx, FinishOptions{Force: req.Force, DryRun: true})
		res.Finish = &plan
		if err != nil || req.Plan {
			return res, err
		}
		preq = policy.Request{Action: policy.ClusterCAFinish, Target: "hub CA " + plan.NewCAFP, Detail: map[string]any{
			"force": req.Force, "cut_off_devices": plan.OldDevices, "cut_off_hubs": plan.OldHubs,
		}}
		do = func(ctx context.Context) error {
			plan, err := n.FinishCA(ctx, FinishOptions{Force: req.Force})
			res.Finish = &plan
			return err
		}
	case CAOpAbort:
		plan, err := n.AbortCA(ctx, AbortOptions{DryRun: true})
		res.Abort = &plan
		if err != nil || req.Plan {
			return res, err
		}
		preq = policy.Request{Action: policy.ClusterCAAbort, Target: "hub CA " + plan.NewCAFP, Detail: map[string]any{
			"cut_off_devices": plan.RenewedDevices,
		}}
		do = func(ctx context.Context) error {
			plan, err := n.AbortCA(ctx, AbortOptions{})
			res.Abort = &plan
			return err
		}
	default:
		return res, fmt.Errorf("hub CA rotation: no step %q: want rotate, finish or abort", req.Op)
	}
	preq.ActorKind, preq.ActorID, preq.DryRun = policy.ActorAdmin, req.Actor, req.DryRun
	if err := pol.Do(ctx, preq, do); err != nil {
		return res, err
	}
	if req.DryRun {
		res.Decision, _ = pol.Check(preq)
	}
	return res, nil
}

// serveCAChange answers POST /v1/ca/change on the control socket.
func (n *APNode) serveCAChange(w http.ResponseWriter, r *http.Request) {
	var req CARequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<12)).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	res, err := n.ChangeCA(r.Context(), req)
	reply := caChangeReply{Result: res}
	switch {
	case err == nil:
	case errors.Is(err, policy.ErrDenied):
		reply.Error = &wireError{Kind: errDeniedKind, Message: err.Error()}
	case errors.Is(err, ErrNotMasterHere):
		reply.Error = &wireError{Kind: "not_master", Message: err.Error() + " (run the command on a master's host)"}
	default:
		reply.Error = toWireError(err)
	}
	writeJSON(w, reply)
}

// serveCAStatus answers GET /v1/ca/status on the control socket.
func (n *APNode) serveCAStatus(w http.ResponseWriter, r *http.Request) {
	st, err := n.CAStatus(r.Context())
	reply := caStatusReply{Status: st}
	if err != nil {
		reply.Error = toWireError(err)
	}
	writeJSON(w, reply)
}

// CAStatus returns the latest hub CA rotation and each hub's side of it.
func (c *ControlClient) CAStatus(ctx context.Context) (CAStatus, error) {
	var reply caStatusReply
	if err := c.do(ctx, http.MethodGet, "/v1/ca/status", nil, &reply); err != nil {
		return CAStatus{}, err
	}
	if reply.Error != nil {
		return CAStatus{}, reply.Error.toError()
	}
	return reply.Status, nil
}

// ChangeCA asks the running hub of an AP master for a hub CA rotation step
// (CARequest). A refusal keeps its kind: errors.Is matches policy.ErrDenied
// and the rotation's errors.
func (c *ControlClient) ChangeCA(ctx context.Context, req CARequest) (CAResult, error) {
	var reply caChangeReply
	// A finish waits for every member, and a step held for approval for
	// its decision: no client timeout.
	if err := c.postWith(ctx, &http.Client{Transport: c.http.Transport}, "/v1/ca/change", req, &reply); err != nil {
		return CAResult{}, err
	}
	if reply.Error != nil {
		switch reply.Error.Kind {
		case errDeniedKind:
			return reply.Result, &kindError{msg: reply.Error.Message, target: policy.ErrDenied}
		case "not_master":
			return reply.Result, &kindError{msg: reply.Error.Message, target: ErrNotMasterHere}
		}
		return reply.Result, reply.Error.toError()
	}
	return reply.Result, nil
}
