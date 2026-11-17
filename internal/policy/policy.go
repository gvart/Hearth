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
	// AdminSetPassword sets or resets the admin password.
	AdminSetPassword Action = "admin.set_password"
	// AdminLogin is a login attempt on the hub's web API.
	AdminLogin Action = "admin.login"
	// ClusterTokenCreate creates a token that lets a new hub join the cluster
	// and receive the CA key.
	ClusterTokenCreate Action = "cluster.token.create"
	// ClusterJoin admits a new hub: it receives a node certificate and the CA
	// key, and is added to the Raft configuration as a non-voter.
	ClusterJoin Action = "cluster.join"
	// ClusterPromote makes a joined, caught-up hub a Raft voter.
	ClusterPromote Action = "cluster.promote"
)

// Actor kinds.
const (
	// ActorAdmin is a local operator using the CLI on the hub host.
	ActorAdmin = "admin"
	// ActorToken is an agent authenticating with an enrollment token.
	ActorToken = "token"
	// ActorWeb is a client of the hub's web API, identified by its remote
	// address. The API checks the admin session before any action other than
	// admin.login reaches policy.
	ActorWeb = "web"
	// ActorJoinToken is a hub joining the cluster with a join token. It is not
	// ActorToken, so an enrollment path can never be taken for a join.
	ActorJoinToken = "join_token"
	// ActorHub is a cluster member identified by its hub node certificate.
	ActorHub = "hub"
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
	// The web UI's "Add device" creates tokens behind an admin session.
	TokenCreate:  {class: Safe, actors: []string{ActorAdmin, ActorWeb}},
	DeviceEnroll: {class: Safe, actors: []string{ActorToken}},
	DeviceRevoke: {class: Dangerous, actors: []string{ActorAdmin}},
	// Changing the credential that guards everything else is dangerous.
	AdminSetPassword: {class: Dangerous, actors: []string{ActorAdmin}},
	// Anyone on the network may try to log in; the password decides.
	AdminLogin: {class: Safe, actors: []string{ActorWeb}},
	// Joining hands out the CA key: every step of it is dangerous.
	ClusterTokenCreate: {class: Dangerous, actors: []string{ActorAdmin}},
	ClusterJoin:        {class: Dangerous, actors: []string{ActorJoinToken}},
	ClusterPromote:     {class: Dangerous, actors: []string{ActorHub}},
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
		return withAuditErr(runErr, fmt.Errorf("audit %s: %w", req.Action, err))
	}

	if decision == Deny {
		return fmt.Errorf("%s by %s/%s: %s: %w", req.Action, req.ActorKind, req.ActorID, reason, ErrDenied)
	}
	return runErr
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
