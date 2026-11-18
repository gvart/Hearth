// SPDX-License-Identifier: AGPL-3.0-only

package policy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
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
	// ClusterRemove removes a hub from the Raft configuration and revokes
	// its hub node certificates.
	ClusterRemove Action = "cluster.remove"
	// ClusterTransferLeadership asks the leader to hand leadership to
	// another voter.
	ClusterTransferLeadership Action = "cluster.transfer_leadership"
	// ClusterMigrate migrates the cluster's store schema to a newer version
	// on every hub, through the Raft log.
	ClusterMigrate Action = "cluster.migrate"
	// AutomationLog is an automation's log action: it writes a line to the
	// hub log and touches no device.
	AutomationLog Action = "automation.log"
	// AutomationWebhook is an automation's webhook action: an HTTP request
	// from the hub.
	AutomationWebhook Action = "automation.webhook"
	// AutomationRestart restarts a systemd unit or Docker container on a
	// device, through its agent.
	AutomationRestart Action = "automation.restart"
	// AutomationExec runs a command on a device, through its agent.
	AutomationExec Action = "automation.exec"
	// KubeClusterAdd adopts a Kubernetes cluster: the hub stores its
	// kubeconfig, sealed, and starts watching it read-only.
	KubeClusterAdd Action = "kube.cluster.add"
	// KubeClusterRemove forgets an adopted Kubernetes cluster and its
	// kubeconfig.
	KubeClusterRemove Action = "kube.cluster.remove"
	// KubePodLogs reads the recent log lines of a pod's container.
	KubePodLogs Action = "kube.pod.logs"
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
	// ActorAutomation is an automation run on the cluster leader, identified
	// by the automation's id.
	ActorAutomation = "automation"
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
	// Removal changes the quorum and locks a hub out for good.
	ClusterRemove: {class: Dangerous, actors: []string{ActorAdmin}},
	// A transfer changes no state: the cluster elects the chosen voter, with
	// a write pause no longer than an ordinary election.
	ClusterTransferLeadership: {class: Safe, actors: []string{ActorAdmin}},
	// A schema migration cannot be undone: downgrades are unsupported.
	ClusterMigrate: {class: Dangerous, actors: []string{ActorAdmin}},
	// Writing a log line changes nothing.
	AutomationLog: {class: Read, actors: []string{ActorAutomation}},
	// A webhook touches no device: it tells another system something.
	AutomationWebhook: {class: Safe, actors: []string{ActorAutomation}},
	// A restart is bounded and repeatable, the routine homelab fix, and
	// the device's agent restarts only the services its ceiling names.
	AutomationRestart: {class: Safe, actors: []string{ActorAutomation}},
	// An arbitrary command can do anything the agent can.
	AutomationExec: {class: Dangerous, actors: []string{ActorAutomation}},
	// Adding a cluster hands the hub a credential to it; the hub only ever
	// reads with it (no Kubernetes write action exists yet).
	KubeClusterAdd:    {class: Safe, actors: []string{ActorWeb}},
	KubeClusterRemove: {class: Safe, actors: []string{ActorWeb}},
	// Logs may carry secrets, so reading them is audited.
	KubePodLogs: {class: Read, actors: []string{ActorWeb}},
}

// ClassOf returns the class of a known action.
func ClassOf(a Action) (Class, bool) {
	r, ok := rules[a]
	return r.class, ok
}

// ErrDenied is returned when policy denies an action.
var ErrDenied = errors.New("denied by policy")

// ErrBeyondCeiling is returned when a device's agent refuses an action
// policy allowed: the action is beyond the device's capability ceiling, which
// the hub can never raise. It matches ErrDenied.
var ErrBeyondCeiling = fmt.Errorf("beyond the device's capability ceiling: %w", ErrDenied)

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
	// dangerous are the automations granted dangerous actions.
	dangerous map[string]bool
}

// Config is the operator's policy configuration on top of the rule table.
type Config struct {
	// DangerousAutomations are the ids of the automations allowed to take
	// dangerous actions. Every other automation is denied them: until
	// actions can be approved one at a time, an explicit grant is the only
	// way an automation may take one.
	DangerousAutomations []string
}

// New returns an Engine that writes to audit.
func New(audit Auditor) *Engine { return NewWithConfig(audit, Config{}) }

// NewWithConfig returns an Engine that writes to audit and applies cfg.
func NewWithConfig(audit Auditor, cfg Config) *Engine {
	e := &Engine{audit: audit, now: time.Now, dangerous: map[string]bool{}}
	for _, id := range cfg.DangerousAutomations {
		e.dangerous[id] = true
	}
	return e
}

// Do decides on req and, if allowed, runs fn. Exactly one audit entry is
// written either way, carrying the decision and fn's outcome. A denied request
// returns an error wrapping ErrDenied; an allowed one returns fn's error.
func (e *Engine) Do(ctx context.Context, req Request, fn func(context.Context) error) error {
	decision, reason := e.decide(req)
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

func (e *Engine) decide(req Request) (decision, reason string) {
	r, ok := rules[req.Action]
	if !ok {
		return Deny, "unknown action"
	}
	if req.ActorID == "" {
		return Deny, "anonymous actor"
	}
	if !slices.Contains(r.actors, req.ActorKind) {
		return Deny, "actor kind not allowed"
	}
	if r.class == Dangerous && req.ActorKind == ActorAutomation && !e.dangerous[req.ActorID] {
		return Deny, "dangerous action not granted to this automation"
	}
	return Allow, ""
}
