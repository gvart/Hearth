// SPDX-License-Identifier: AGPL-3.0-only

package policy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/gvart/hearth/internal/store"
)

// Class is the risk class of an action.
type Class string

// Action classes.
const (
	Read      Class = "read"
	Safe      Class = "safe"
	Dangerous Class = "dangerous"
)

// Action names an operation that must pass through policy.
type Action string

// Known actions.
const (
	TokenCreate  Action = "token.create"
	DeviceEnroll Action = "device.enroll"
	DeviceRevoke Action = "device.revoke"
)

// Actor kinds.
const (
	// ActorAdmin is a local operator using the CLI on the hub host.
	ActorAdmin = "admin"
	// ActorToken is an agent authenticating with an enrollment token.
	ActorToken = "token"
)

// Decisions recorded in the audit log.
const (
	Allow = "allow"
	Deny  = "deny"
)

type rule struct {
	class  Class
	actors []string
}

// rules is the action table. Anything not listed here is denied.
var rules = map[Action]rule{
	TokenCreate:  {class: Safe, actors: []string{ActorAdmin}},
	DeviceEnroll: {class: Safe, actors: []string{ActorToken}},
	DeviceRevoke: {class: Dangerous, actors: []string{ActorAdmin}},
}

// ClassOf returns the class of a known action.
func ClassOf(a Action) (Class, bool) {
	r, ok := rules[a]
	return r.class, ok
}

// ErrDenied is returned when policy denies an action.
var ErrDenied = errors.New("denied by policy")

// Auditor is where decisions are recorded.
type Auditor interface {
	Append(ctx context.Context, e store.AuditEntry) (int64, error)
}

// Request describes an action someone wants to perform.
type Request struct {
	ActorKind string
	ActorID   string
	Action    Action
	Target    string
	// Detail is marshalled into the audit entry. It must never contain secrets.
	Detail map[string]any
}

// Engine decides on actions and audits every decision.
type Engine struct {
	audit Auditor
	now   func() time.Time
}

// New returns an Engine that writes to audit.
func New(audit Auditor) *Engine { return &Engine{audit: audit, now: time.Now} }

// Do decides on req and, if allowed, runs fn. Exactly one audit entry is
// written either way, carrying the decision and fn's outcome. A denied request
// returns an error wrapping ErrDenied; an allowed one returns fn's error.
func (e *Engine) Do(ctx context.Context, req Request, fn func(context.Context) error) error {
	decision, reason := decide(req)
	var runErr error
	result := reason
	if decision == Allow {
		runErr = fn(ctx)
		result = "ok"
		if runErr != nil {
			result = "error: " + runErr.Error()
		}
	}

	detail, err := json.Marshal(req.Detail)
	if err != nil {
		return errors.Join(runErr, fmt.Errorf("audit %s: encode detail: %w", req.Action, err))
	}
	if req.Detail == nil {
		detail = nil
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
		return errors.Join(runErr, fmt.Errorf("audit %s: %w", req.Action, err))
	}

	if decision == Deny {
		return fmt.Errorf("%s by %s/%s: %s: %w", req.Action, req.ActorKind, req.ActorID, reason, ErrDenied)
	}
	return runErr
}

// orUnknown keeps denied anonymous requests auditable.
func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

func decide(req Request) (decision, reason string) {
	r, ok := rules[req.Action]
	if !ok {
		return Deny, "unknown action"
	}
	if req.ActorID == "" {
		return Deny, "anonymous actor"
	}
	for _, a := range r.actors {
		if a == req.ActorKind {
			return Allow, ""
		}
	}
	return Deny, "actor kind not allowed"
}
