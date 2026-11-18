// SPDX-License-Identifier: AGPL-3.0-only

package policy

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/gvart/hearth/internal/store"
)

// Auditor is where decisions are recorded.
type Auditor interface {
	Append(ctx context.Context, e store.AuditEntry) (int64, error)
}

// Approvals holds actions for confirmation: store.Approvals.
type Approvals interface {
	Create(ctx context.Context, a store.Approval) error
	Get(ctx context.Context, id string) (store.Approval, error)
	Decide(ctx context.Context, id, status, decider string, at time.Time) error
}

// Request describes an action someone wants to perform.
type Request struct {
	ActorKind string
	ActorID   string
	Action    Action
	Target    string
	// Detail is marshalled into the audit entry. It must never contain secrets.
	Detail map[string]any
	// DryRun decides on the request and audits the decision with the result
	// DryRun, and never runs it nor holds it for approval. Do then returns
	// nil, unless the request would be denied.
	DryRun bool
	// Precheck, when set, runs once the configuration would allow or hold
	// the request, before anything else happens. An error matching ErrDenied
	// (such as ErrBeyondCeiling) turns the decision into a denial, with the
	// error as the reason. Other errors are ignored: the action meets them.
	Precheck func(ctx context.Context) error
	// OnHold, when set, is called once the request is held for approval,
	// with the approval's id and expiry.
	OnHold func(id string, expires time.Time)
}

// Engine decides on actions and audits every decision.
type Engine struct {
	audit     Auditor
	approvals Approvals
	cfg       Config
	now       func() time.Time
	// poll is how often a held request reads its approval.
	poll time.Duration
}

// DefaultApprovalTimeout is how long an action waits for approval when the
// configuration sets no timeout. An action nobody approves in time is
// denied.
const DefaultApprovalTimeout = 10 * time.Minute

// New returns an Engine with the default configuration that writes to
// audit. It holds nothing for approval.
func New(audit Auditor) *Engine { return NewWithConfig(audit, nil, Config{}) }

// NewWithConfig returns an Engine that writes to audit, applies cfg, and
// holds the requests cfg says to confirm in approvals. With nil approvals
// those requests are denied. cfg must be valid (see Config.Validate).
func NewWithConfig(audit Auditor, approvals Approvals, cfg Config) *Engine {
	if cfg.ApprovalTimeout <= 0 {
		cfg.ApprovalTimeout = DefaultApprovalTimeout
	}
	return &Engine{audit: audit, approvals: approvals, cfg: cfg, now: time.Now, poll: time.Second}
}

// Do decides on req and, if allowed, runs fn. A request the configuration
// says to confirm is first held as a pending approval, and Do waits until
// it is approved, denied or expires, or ctx is done. Every decision is in
// the audit log: one entry for a request allowed, denied or dry-run, two for
// a held one (the hold, then its outcome). A denied request returns an
// error wrapping ErrDenied; an allowed one returns fn's error.
func (e *Engine) Do(ctx context.Context, req Request, fn func(context.Context) error) error {
	decision, reason, class := e.decide(req)
	var precheckErr error
	if decision != Deny && req.Precheck != nil {
		if err := req.Precheck(ctx); errors.Is(err, ErrDenied) {
			decision, reason, precheckErr = Deny, err.Error(), err
		}
	}

	if req.DryRun {
		result := DryRun
		if reason != "" {
			result += ": " + reason
		}
		if err := e.record(ctx, req, decision, result, nil); err != nil {
			return err
		}
		if decision == Deny {
			return denied(req, reason, precheckErr)
		}
		return nil
	}

	var extra map[string]any
	auditCtx := ctx
	if decision == Confirm {
		var err error
		if decision, reason, extra, err = e.hold(ctx, req, class); err != nil {
			return err
		}
		// The hold's outcome is audited even when the requester gave up.
		auditCtx = context.WithoutCancel(ctx)
	}

	var runErr error
	result := reason
	if decision == Allow {
		runErr = fn(ctx)
		result = "ok"
		if runErr != nil {
			result = "error: " + runErr.Error()
		}
	}
	if err := e.record(auditCtx, req, decision, result, extra); err != nil {
		return withAuditErr(runErr, err)
	}
	if decision == Deny {
		return denied(req, reason, precheckErr)
	}
	return runErr
}

func denied(req Request, reason string, precheckErr error) error {
	if precheckErr != nil {
		// It wraps ErrDenied already, and says why.
		return fmt.Errorf("%s by %s/%s: %w", req.Action, req.ActorKind, req.ActorID, precheckErr)
	}
	return fmt.Errorf("%s by %s/%s: %s: %w", req.Action, req.ActorKind, req.ActorID, reason, ErrDenied)
}

// record writes one audit entry for req, its detail merged with extra.
func (e *Engine) record(ctx context.Context, req Request, decision, result string, extra map[string]any) error {
	detail, err := detailJSON(req.Detail, extra)
	if err != nil {
		return fmt.Errorf("audit %s: encode detail: %w", req.Action, err)
	}
	if _, err := e.audit.Append(ctx, store.AuditEntry{
		TS:        e.now(),
		ActorKind: orUnknown(req.ActorKind),
		ActorID:   orUnknown(req.ActorID),
		Action:    string(req.Action),
		Target:    req.Target,
		Decision:  decision,
		Result:    result,
		Detail:    detail,
	}); err != nil {
		return fmt.Errorf("audit %s: %w", req.Action, err)
	}
	return nil
}

// detailJSON encodes detail with extra's keys added, or returns nil when
// both are nil.
func detailJSON(detail, extra map[string]any) (json.RawMessage, error) {
	if detail == nil && extra == nil {
		return nil, nil
	}
	m := make(map[string]any, len(detail)+len(extra))
	maps.Copy(m, detail)
	maps.Copy(m, extra)
	return json.Marshal(m)
}

// hold stores req as a pending approval, audits the hold and waits for the
// approval's outcome. It returns the decision to go on with (Allow or Deny),
// the reason for a denial, and the detail that ties the final audit entry
// to the approval. It fails only when the hold could not be audited.
func (e *Engine) hold(ctx context.Context, req Request, class Class) (decision, reason string, extra map[string]any, err error) {
	if e.approvals == nil {
		return Deny, "needs approval, which this hub cannot hold", nil, nil
	}
	detail, err := detailJSON(req.Detail, nil)
	if err != nil {
		return "", "", nil, fmt.Errorf("audit %s: encode detail: %w", req.Action, err)
	}
	now := e.now()
	ap := store.Approval{
		ID: strings.ToLower(rand.Text()), CreatedAt: now, ExpiresAt: now.Add(e.cfg.ApprovalTimeout),
		ActorKind: orUnknown(req.ActorKind), ActorID: orUnknown(req.ActorID), Action: string(req.Action),
		Class: string(class), Target: req.Target, Detail: detail,
	}
	if err := e.approvals.Create(ctx, ap); err != nil {
		// Deny by default: what cannot be held cannot be approved.
		return Deny, "needs approval, but it could not be held: " + err.Error(), nil, nil
	}
	extra = map[string]any{"approval": ap.ID}
	if err := e.record(ctx, req, Confirm, "pending approval "+ap.ID, extra); err != nil {
		e.expire(ctx, ap.ID)
		return "", "", nil, err
	}
	if req.OnHold != nil {
		req.OnHold(ap.ID, ap.ExpiresAt)
	}

	final, err := e.wait(ctx, ap)
	switch {
	case err != nil:
		return Deny, "approval " + err.Error(), extra, nil
	case final.Status == store.ApprovalApproved:
		extra["approved_by"] = final.DecidedBy
		return Allow, "", extra, nil
	case final.Status == store.ApprovalDenied:
		return Deny, "approval denied by " + final.DecidedBy, extra, nil
	}
	return Deny, "approval " + final.Status, extra, nil
}

// wait reads the approval until it is decided. When it expires, wait closes
// it as expired; when ctx is done first, it closes it too and fails.
func (e *Engine) wait(ctx context.Context, ap store.Approval) (store.Approval, error) {
	tick := time.NewTicker(e.poll)
	defer tick.Stop()
	timeout := time.NewTimer(ap.ExpiresAt.Sub(e.now()))
	defer timeout.Stop()
	expired := false
	for {
		select {
		case <-ctx.Done():
			e.expire(ctx, ap.ID)
			return store.Approval{}, fmt.Errorf("cancelled: %w", context.Cause(ctx))
		case <-timeout.C:
			e.expire(ctx, ap.ID)
			expired = true
		case <-tick.C:
		}
		cur, err := e.approvals.Get(ctx, ap.ID)
		if err != nil {
			if expired {
				// Unreadable past its expiry: deny by default.
				return store.Approval{Status: store.ApprovalExpired}, nil
			}
			continue // retried on the next tick; the timeout still ends the wait
		}
		if cur.Status != store.ApprovalPending {
			return cur, nil
		}
	}
}

// expire closes a pending approval as expired. It does nothing to one
// decided meanwhile: the next read sees that decision.
func (e *Engine) expire(ctx context.Context, id string) {
	_ = e.approvals.Decide(context.WithoutCancel(ctx), id, store.ApprovalExpired, "timeout", e.now())
}

// Decide approves or denies the held request id as actorKind/actorID, an
// action that goes through policy itself (ApprovalApprove or ApprovalDeny).
// It fails with store.ErrNotFound for an unknown approval and with
// store.ErrApprovalClosed for one no longer pending.
func (e *Engine) Decide(ctx context.Context, actorKind, actorID, id string, approve bool) error {
	if e.approvals == nil {
		return errors.New("decide approval: this hub holds no approvals")
	}
	held, err := e.approvals.Get(ctx, id)
	if err != nil {
		return err
	}
	action, status := ApprovalDeny, store.ApprovalDenied
	if approve {
		action, status = ApprovalApprove, store.ApprovalApproved
	}
	return e.Do(ctx, Request{
		ActorKind: actorKind, ActorID: actorID, Action: action, Target: id,
		Detail: map[string]any{
			"action": held.Action, "actor": held.ActorKind + "/" + held.ActorID, "target": held.Target,
		},
	}, func(ctx context.Context) error {
		return e.approvals.Decide(ctx, id, status, actorKind+"/"+actorID, e.now())
	})
}

// withAuditErr combines a failed action with its failed audit append. When
// both failed for the same root cause (typically the store or the cluster
// being unavailable, which fails every write the same way), the cause is
// reported once instead of twice. The result still matches both errors with
// errors.Is when they differ.
func withAuditErr(runErr, auditErr error) error {
	if runErr == nil {
		return auditErr
	}
	if rootCause(runErr).Error() == rootCause(auditErr).Error() {
		return fmt.Errorf("%w (the audit entry was not written either)", runErr)
	}
	return errors.Join(runErr, auditErr)
}

// rootCause follows a chain of single wrapped errors to its end.
func rootCause(err error) error {
	for {
		next := errors.Unwrap(err)
		if next == nil {
			return err
		}
		err = next
	}
}

// orUnknown keeps denied anonymous requests auditable.
func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

// Check returns the decision Do would make on req (Allow, Confirm or Deny)
// and the reason for a denial, without Precheck, auditing or running
// anything. It is for explaining a decision Do already audited.
func (e *Engine) Check(req Request) (decision, reason string) {
	decision, reason, _ = e.decide(req)
	return decision, reason
}

// decide applies the rule table and then the configuration to req.
func (e *Engine) decide(req Request) (decision, reason string, class Class) {
	r, ok := rules[req.Action]
	if !ok {
		return Deny, "unknown action", ""
	}
	if req.ActorID == "" {
		return Deny, "anonymous actor", r.class
	}
	if !slices.Contains(r.actors, req.ActorKind) {
		return Deny, "actor kind not allowed", r.class
	}
	if r.fixed {
		return Allow, "", r.class
	}
	mode, configured := e.cfg.mode(r.class, req.ActorKind, req.ActorID)
	switch mode {
	case ModeAllow:
		return Allow, "", r.class
	case ModeConfirm:
		return Confirm, "", r.class
	}
	if !configured {
		return Deny, "dangerous action not granted to this automation", r.class
	}
	return Deny, fmt.Sprintf("%s actions by %s are denied by the policy configuration", r.class, req.ActorKind), r.class
}
