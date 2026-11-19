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
	Overdue(ctx context.Context, at time.Time, limit int) ([]store.Approval, error)
}

// Request describes an action someone wants to perform.
type Request struct {
	ActorKind string
	ActorID   string
	Action    Action
	Target    string
	// Detail is marshalled into the audit entry. It must never contain secrets.
	Detail map[string]any
	// ApprovalDetail is added to Detail in the approval of a held request, and
	// is never audited: it is for what only the approver should read, such as
	// DetailPlan.
	ApprovalDetail map[string]any
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
	// RecordOutcome makes a read-class request write its outcome even when it
	// succeeds, as every other class does: for a rare read whose fn adds to
	// Detail what the audit log should show. See Engine.run.
	RecordOutcome bool
}

// Results of the entry written before an allowed action runs. The entry that
// reports the action's outcome, "ok" or "error: ...", replaces it for readers
// of the audit log (see store.Audit.Query).
const (
	// Started means the action was about to run. Alone in the log, it means
	// the action is still running, the hub stopped before it could report, or
	// the write seemed to fail, refusing the action, and committed after all.
	Started = "started"
	// ReadAllowed is the one entry of a read that did not fail: reads are the
	// frequent actions and change nothing, so success adds no second write.
	ReadAllowed = "read allowed"
)

// ErrOutcomeNotRecorded is returned when an action ran but the audit entry
// reporting how it ended could not be written. The entry written before it
// exists, so the audit log shows the action as Started.
//
// The action must not be taken for one that did not run, and retrying it
// repeats it. An error matching only ErrOutcomeNotRecorded means the action's
// function returned nil; one that also matches another error carries the
// function's own failure. It deliberately does not match the audit write's
// error: store.ErrUnavailable means nothing happened and a retry is safe,
// which is not true here. A caller that cannot tell how a step ended, such as
// a runbook, should treat it as unknown.
var ErrOutcomeNotRecorded = errors.New("its outcome was not recorded")

// outcomeTimeout bounds the write of an action's outcome, which outlives the
// request. It covers waiting for a cluster leader and the Raft apply.
const outcomeTimeout = 20 * time.Second

type scopeKey struct{}

// WithScope returns ctx with the highest class its requester's credential
// allows, such as an MCP token's scope. Do denies, and audits as denied, any
// request on ctx of a higher class, whatever the configuration says.
func WithScope(ctx context.Context, scope Class) context.Context {
	return context.WithValue(ctx, scopeKey{}, scope)
}

// classRank orders the classes; an unknown class ranks nowhere.
var classRank = map[Class]int{Read: 1, Safe: 2, Dangerous: 3}

// Within reports whether class is at most scope. An unknown class or scope
// is never within.
func Within(class, scope Class) bool {
	c, s := classRank[class], classRank[scope]
	return c > 0 && s > 0 && c <= s
}

// Engine decides on actions and audits every decision.
type Engine struct {
	audit     Auditor
	approvals Approvals
	cfg       Config
	now       func() time.Time
	// poll is how often a held request reads its approval.
	poll time.Duration
	// onHeld is told about every approval this engine holds; see OnHeld.
	onHeld func(ctx context.Context, ap store.Approval)
	// sweepEvery is how often RunApprovalSweep looks for overdue approvals.
	sweepEvery time.Duration
	// spool keeps the outcomes that could not be written; see SpoolTo.
	spool *Spool
	// outcomeTimeout bounds the first write of an outcome.
	outcomeTimeout time.Duration
}

// SpoolTo makes the engine keep in s every entry that reports how an action
// or a held request ended and that could not be written, instead of losing
// it: s writes it later (see Spool.Run). An action whose outcome was spooled
// returns its own result, without ErrOutcomeNotRecorded. Call it before the
// engine is used.
func (e *Engine) SpoolTo(s *Spool) { e.spool = s }

// OnHeld sets fn to be called with every approval the engine holds, once
// it is stored and audited and before the requester waits: the hub sends
// it to a notification channel. fn must not block for long (it delays the
// requester's wait, not the approval's expiry) and its failures are its
// own. Call it before the engine is used.
func (e *Engine) OnHeld(fn func(ctx context.Context, ap store.Approval)) { e.onHeld = fn }

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
	return &Engine{audit: audit, approvals: approvals, cfg: cfg, now: time.Now, poll: time.Second, sweepEvery: time.Minute, outcomeTimeout: outcomeTimeout}
}

// Do decides on req and, if allowed, runs fn. A request the configuration
// says to confirm is first held as a pending approval, and Do waits until
// it is approved, denied or expires, or ctx is done. Every decision is in
// the audit log, and fn never runs unless its entry was written first (see
// run). A denied request returns an error wrapping ErrDenied; an allowed one
// returns fn's error.
func (e *Engine) Do(ctx context.Context, req Request, fn func(context.Context) error) error {
	decision, reason, class := e.decide(req)
	if decision != Deny {
		if scope, ok := ctx.Value(scopeKey{}).(Class); ok && !Within(class, scope) {
			decision, reason = Deny, fmt.Sprintf("%s action beyond the credential's scope (%s)", class, scope)
		}
	}
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
	held := decision == Confirm
	if held {
		var err error
		if decision, reason, extra, err = e.hold(ctx, req, class); err != nil {
			return err
		}
		// The hold's outcome is audited even when the requester gave up.
		auditCtx = context.WithoutCancel(ctx)
	}

	if decision == Allow {
		return e.run(ctx, req, class, held, extra, fn)
	}
	record := e.record
	if held {
		// It closes the hold written in the log already.
		record = e.recordOutcome
	}
	if err := record(auditCtx, req, decision, reason, extra); err != nil {
		return err
	}
	return denied(req, reason, precheckErr)
}

// run runs the allowed req with its audit entry written first: fn is not
// called unless the entry exists. A second entry, tied to the first by an
// operation id, records the outcome on a context that survives ctx being
// cancelled. A read that succeeds writes no second entry, unless it was held
// for approval or asks to with RecordOutcome.
func (e *Engine) run(ctx context.Context, req Request, class Class, held bool, extra map[string]any, fn func(context.Context) error) error {
	op := strings.ToLower(rand.Text())
	failureOnly := class == Read && !req.RecordOutcome && !held
	first := Started
	if failureOnly {
		first = ReadAllowed
	}
	if err := e.record(ctx, req, Allow, first, withDetail(extra, store.AuditOpKey, op)); err != nil {
		if held {
			// The hold has to end in an outcome, if one can still be written.
			_ = e.recordOutcome(ctx, req, Deny, "approved, but not run: "+err.Error(), extra)
		}
		return refused(ctx, req, err)
	}

	runErr := fn(context.WithValue(ctx, grantKey{}, req.Action))
	if runErr == nil && failureOnly {
		return nil
	}
	result := "ok"
	if runErr != nil {
		result = "error: " + runErr.Error()
	}
	if err := e.recordOutcome(ctx, req, Allow, result, withDetail(extra, store.AuditOutcomeOfKey, op)); err != nil {
		return outcomeNotRecorded(req, runErr, err)
	}
	return runErr
}

// outcomeNotRecorded is the error of an action that ran, with runErr its own
// failure if it had one, whose outcome could not be written because of
// auditErr. It matches ErrOutcomeNotRecorded and runErr, never auditErr. When
// both failed for the same root cause (typically the store or the cluster
// being unavailable), the cause is reported once.
func outcomeNotRecorded(req Request, runErr, auditErr error) error {
	switch {
	case runErr == nil:
		return fmt.Errorf("%s ran, but %w: %v", req.Action, ErrOutcomeNotRecorded, auditErr) //nolint:errorlint // see ErrOutcomeNotRecorded
	case rootCause(runErr).Error() == rootCause(auditErr).Error():
		return fmt.Errorf("%w (%w either)", runErr, ErrOutcomeNotRecorded)
	}
	return fmt.Errorf("%w (%w: %v)", runErr, ErrOutcomeNotRecorded, auditErr) //nolint:errorlint // see ErrOutcomeNotRecorded
}

// recordOutcome is record for an entry reporting how something already
// written in the log ended, on a context that ctx being cancelled cannot
// stop. With a spool, the entry carries a key from its first write, which
// may commit after seeming to fail, and goes to the spool if it could not be
// written.
func (e *Engine) recordOutcome(ctx context.Context, req Request, decision, result string, extra map[string]any) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), e.outcomeTimeout)
	defer cancel()
	entry, err := e.entry(req, decision, result, extra)
	if err != nil {
		return err
	}
	if e.spool != nil {
		entry.Key = strings.ToLower(rand.Text())
	}
	_, err = e.audit.Append(ctx, entry)
	if err == nil {
		return nil
	}
	err = fmt.Errorf("audit %s: %w", req.Action, err)
	if e.spool == nil {
		return err
	}
	if sErr := e.spool.Put(entry); sErr != nil {
		return fmt.Errorf("%w (%w)", err, sErr)
	}
	return nil
}

// withDetail returns a copy of extra with key set to value.
func withDetail(extra map[string]any, key, value string) map[string]any {
	out := make(map[string]any, len(extra)+1)
	maps.Copy(out, extra)
	out[key] = value
	return out
}

// refused is the error of an action that did not run because its audit entry
// could not be written. It still matches the write's error.
func refused(ctx context.Context, req Request, err error) error {
	if ctx.Err() != nil {
		return fmt.Errorf("%s refused, nothing was run: the request ended before its audit entry was written: %w", req.Action, err)
	}
	return fmt.Errorf("%s refused, nothing was run: its audit entry could not be written "+
		"(a hub cluster refuses every action while most of its hubs are unreachable): %w", req.Action, err)
}

// grantKey is the context key of the action Do allowed: the context it
// passes to fn carries it.
type grantKey struct{}

// Granted reports whether ctx is the context Do passes to the function it
// runs for action a, or derives from it. An entry point that carries out an
// action without auditing it itself checks it, so that it cannot run
// outside policy: only Do grants.
func Granted(ctx context.Context, a Action) bool {
	g, ok := ctx.Value(grantKey{}).(Action)
	return ok && g == a
}

// WithGrant returns ctx carrying the grant of granted, if it has one: for a
// function Do runs that goes on in a context of its own.
func WithGrant(ctx, granted context.Context) context.Context {
	if g, ok := granted.Value(grantKey{}).(Action); ok {
		return context.WithValue(ctx, grantKey{}, g)
	}
	return ctx
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
	entry, err := e.entry(req, decision, result, extra)
	if err != nil {
		return err
	}
	if _, err := e.audit.Append(ctx, entry); err != nil {
		return fmt.Errorf("audit %s: %w", req.Action, err)
	}
	return nil
}

// entry is the audit entry for req, its detail merged with extra.
func (e *Engine) entry(req Request, decision, result string, extra map[string]any) (store.AuditEntry, error) {
	detail, err := detailJSON(req.Detail, extra)
	if err != nil {
		return store.AuditEntry{}, fmt.Errorf("audit %s: encode detail: %w", req.Action, err)
	}
	return store.AuditEntry{
		TS:        e.now(),
		ActorKind: orUnknown(req.ActorKind),
		ActorID:   orUnknown(req.ActorID),
		Action:    string(req.Action),
		Target:    req.Target,
		Decision:  decision,
		Result:    result,
		Detail:    detail,
	}, nil
}

// DetailPlan is the key, in Request.ApprovalDetail, of the plan of what a held
// request would do. A plan quotes commands and messages, which may hold
// secrets: only a signed-in approver is shown it.
const DetailPlan = "plan"

// DetailOmitted is the key of the placeholder detail of an entry whose
// request detail nested too deep for the audit log (see detailJSON).
const DetailOmitted = "detail_omitted"

// detailJSON encodes detail with extra's keys added, or returns nil when
// both are nil. A detail the audit log would refuse for nesting too deep is
// replaced by a placeholder that keeps extra: an entry is never lost over its
// detail, and an outcome still folds with its start.
func detailJSON(detail, extra map[string]any) (json.RawMessage, error) {
	if detail == nil && extra == nil {
		return nil, nil
	}
	m := make(map[string]any, len(detail)+len(extra))
	maps.Copy(m, detail)
	// These tie an action's entries together: only the engine sets them.
	delete(m, store.AuditOpKey)
	delete(m, store.AuditOutcomeOfKey)
	maps.Copy(m, extra)
	b, err := json.Marshal(m)
	if err == nil && store.AuditDetailTooDeep(b) {
		m = map[string]any{DetailOmitted: "the request's detail nested deeper than the audit log stores"}
		maps.Copy(m, extra)
		return json.Marshal(m)
	}
	return b, err
}

// hold stores req as a pending approval, audits the hold and waits for the
// approval's outcome. It returns the decision to go on with (Allow or Deny),
// the reason for a denial, and the detail that ties the final audit entry
// to the approval. It fails only when the hold could not be audited.
func (e *Engine) hold(ctx context.Context, req Request, class Class) (decision, reason string, extra map[string]any, err error) {
	if e.approvals == nil {
		return Deny, "needs approval, which this hub cannot hold", nil, nil
	}
	detail, err := detailJSON(req.Detail, req.ApprovalDetail)
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
	if e.onHeld != nil {
		e.onHeld(ctx, ap)
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
//
// Approving needs reauth, which re-authenticates the approver (checks their
// password) and returns nil if they are who they claim. A nil reauth, or one
// that fails for any reason, refuses the approval, audited, with an error
// matching ErrReauth, ErrDenied and reauth's error; the approval stays
// pending. Denying ignores reauth: it can only stop an action.
//
// A decision on an open approval is audited before it takes effect: the held
// request acts as soon as it reads the decision, on any hub, and the audit
// log must show the approval before the action it allowed.
func (e *Engine) Decide(ctx context.Context, actorKind, actorID, id string, approve bool, reauth func(context.Context) error) error {
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
	req := Request{
		ActorKind: actorKind, ActorID: actorID, Action: action, Target: id,
		Detail: map[string]any{
			"action": held.Action, "actor": held.ActorKind + "/" + held.ActorID, "target": held.Target,
		},
	}
	if approve {
		req.Precheck = func(ctx context.Context) error { return checkReauth(ctx, reauth) }
	}
	decided := false
	err = e.Do(ctx, req, func(ctx context.Context) error {
		err := e.approvals.Decide(ctx, id, status, actorKind+"/"+actorID, e.now())
		decided = err == nil
		return err
	})
	if decided && errors.Is(err, ErrOutcomeNotRecorded) {
		// The decision took effect and its started entry is in the log: a
		// retry could only be told that the approval is closed.
		return nil
	}
	return err
}

// checkReauth runs reauth for an approval. Re-authentication fails closed:
// a missing check, or any error, is a denial, whatever its cause.
func checkReauth(ctx context.Context, reauth func(context.Context) error) error {
	if reauth == nil {
		return fmt.Errorf("%w (%w)", ErrReauth, ErrDenied)
	}
	if err := reauth(ctx); err != nil {
		return fmt.Errorf("%w: %w (%w)", ErrReauth, err, ErrDenied)
	}
	return nil
}

// DecideLink denies, as the holder of an approval link from actorID (its
// remote address), the approval the link was sent for. use spends the link,
// once, and returns its approval's id. A link that cannot be used (unknown,
// used or expired) is audited as a denial and returns use's error, which
// also wraps ErrDenied; otherwise it is Decide as ActorApprovalLink.
//
// A link never approves: with approve set, the attempt is audited as a
// denial and refused with ErrLinkApprove (and ErrDenied), and the link is
// left unspent, so it can still deny.
func (e *Engine) DecideLink(ctx context.Context, actorID string, approve bool, use func(context.Context) (string, error)) error {
	if approve {
		req := Request{ActorKind: ActorApprovalLink, ActorID: actorID, Action: ApprovalApprove}
		if err := e.record(ctx, req, Deny, ErrLinkApprove.Error(), nil); err != nil {
			return errors.Join(ErrLinkApprove, ErrDenied, err)
		}
		return fmt.Errorf("%s by %s/%s: %w (%w)", ApprovalApprove, ActorApprovalLink, orUnknown(actorID), ErrLinkApprove, ErrDenied)
	}
	action := ApprovalDeny
	id, err := use(ctx)
	if err != nil {
		req := Request{ActorKind: ActorApprovalLink, ActorID: actorID, Action: action}
		reason := "approval link not usable: " + err.Error()
		if aErr := e.record(ctx, req, Deny, reason, nil); aErr != nil {
			return errors.Join(err, aErr)
		}
		return fmt.Errorf("%s by %s/%s: %w (%w)", action, ActorApprovalLink, orUnknown(actorID), err, ErrDenied)
	}
	return e.Decide(ctx, ActorApprovalLink, actorID, id, false, nil)
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
