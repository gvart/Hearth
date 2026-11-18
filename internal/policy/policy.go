// SPDX-License-Identifier: AGPL-3.0-only

package policy

import (
	"errors"
	"fmt"
	"maps"
	"slices"
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
	// AutomationProbe is an http, tcp or dns trigger checking from a
	// device: the device's agent runs the check for the hub.
	AutomationProbe Action = "automation.probe"
	// KubeClusterAdd adopts a Kubernetes cluster: the hub stores its
	// kubeconfig, sealed, and starts watching it read-only.
	KubeClusterAdd Action = "kube.cluster.add"
	// KubeClusterRemove forgets an adopted Kubernetes cluster and its
	// kubeconfig.
	KubeClusterRemove Action = "kube.cluster.remove"
	// KubePodLogs reads the recent log lines of a pod's container.
	KubePodLogs Action = "kube.pod.logs"
	// KubeWorkloadRestart restarts a Deployment, StatefulSet or DaemonSet
	// with a rolling update, as `kubectl rollout restart` does.
	KubeWorkloadRestart Action = "kube.workload.restart"
	// KubeWorkloadScale sets the replicas of a Deployment or StatefulSet.
	KubeWorkloadScale Action = "kube.workload.scale"
	// KubePodDelete deletes a pod; its controller, if any, recreates it.
	KubePodDelete Action = "kube.pod.delete"
	// KubeNodeCordon marks a node unschedulable.
	KubeNodeCordon Action = "kube.node.cordon"
	// KubeNodeUncordon marks a node schedulable again.
	KubeNodeUncordon Action = "kube.node.uncordon"
	// KubeNodeDrain cordons a node and evicts its pods, honouring their
	// PodDisruptionBudgets.
	KubeNodeDrain Action = "kube.node.drain"
	// AutomationNotify is an automation's notify action: a message to a
	// notification channel (ntfy, Telegram) configured on the hub.
	AutomationNotify Action = "automation.notify"
	// NotifyTest sends a test message to a notification channel from the
	// web UI.
	NotifyTest Action = "notify.test"
	// ApprovalApprove releases an action policy held for confirmation.
	ApprovalApprove Action = "approval.approve"
	// ApprovalDeny refuses an action policy held for confirmation.
	ApprovalDeny Action = "approval.deny"
	// DeviceRead lists, searches or reads the facts of devices, for an MCP
	// client.
	DeviceRead Action = "device.read"
	// DeviceMetrics reads a device's current metrics from Prometheus, for an
	// MCP client.
	DeviceMetrics Action = "device.metrics"
	// DeviceRestart restarts a systemd unit or Docker container on a device,
	// through its agent, for an MCP client.
	DeviceRestart Action = "device.restart"
	// DeviceExec runs a command on a device, through its agent, for an MCP
	// client.
	DeviceExec Action = "device.exec"
	// KubeRead lists the clusters or objects of adopted Kubernetes
	// clusters, for an MCP client.
	KubeRead Action = "kube.read"
	// AutomationPlan checks an automation file and describes what it would
	// do, for an MCP client. Nothing runs.
	AutomationPlan Action = "automation.plan"
	// AutomationApply writes an automation file to the hub's automations
	// directory, for an MCP client; the hub then loads and runs it.
	AutomationApply Action = "automation.apply"
	// MCPTokenCreate creates a bearer token for an MCP client.
	MCPTokenCreate Action = "mcp.token.create" //nolint:gosec // an action name
	// MCPTokenRevoke revokes an MCP client's token.
	MCPTokenRevoke Action = "mcp.token.revoke" //nolint:gosec // an action name
	// NetworkScan is one network discovery scan by the hub: an ARP sweep
	// and an mDNS browse of the configured subnets.
	NetworkScan Action = "network.scan"
	// NetworkHostMark marks a host network discovery found known or
	// ignored, or neither again, which silences or restores its new-device
	// alerts.
	NetworkHostMark Action = "network.host.mark"
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
	// ActorHub is a cluster member identified by its hub node certificate,
	// or the hub itself for its own scheduled work (network discovery).
	ActorHub = "hub"
	// ActorAutomation is an automation run on the cluster leader, identified
	// by the automation's id.
	ActorAutomation = "automation"
	// ActorApprovalLink is the holder of an approval link sent to a
	// notification channel, identified by its remote address. The link
	// itself is the credential, for one approval only.
	ActorApprovalLink = "approval_link"
	// ActorMCP is an MCP client (an AI assistant such as Claude Code),
	// identified by the name of its MCP token. The token's scope caps the
	// classes it may request (see WithScope).
	ActorMCP = "mcp"
)

// Decisions recorded in the audit log.
const (
	Allow = "allow"
	Deny  = "deny"
	// Confirm is the decision to hold an action until an operator approves
	// it. The entry that ends the hold is an Allow or a Deny.
	Confirm = "confirm"
)

// DryRun is the result of an audit entry for a dry run: the decision was
// made and recorded, and nothing ran.
const DryRun = "dry-run"

type rule struct {
	class  Class
	actors []string
	// fixed rules ignore the class modes of Config: their actor proves
	// itself with a credential (a token, a certificate, a password) as part
	// of a protocol no operator could stop to approve, or they are the
	// operator's own approval and recovery paths.
	fixed bool
}

// rules is the action table. Anything not listed here is denied.
var rules = map[Action]rule{
	// The web UI's "Add device" creates tokens behind an admin session.
	TokenCreate:  {class: Safe, actors: []string{ActorAdmin, ActorWeb}},
	DeviceEnroll: {class: Safe, actors: []string{ActorToken}, fixed: true},
	DeviceRevoke: {class: Dangerous, actors: []string{ActorAdmin}},
	// Changing the credential that guards everything else is dangerous. It
	// is also how a hub gets its first password, and the way back in when
	// it is lost, so it is never held for approval.
	AdminSetPassword: {class: Dangerous, actors: []string{ActorAdmin}, fixed: true},
	// Anyone on the network may try to log in; the password decides.
	AdminLogin: {class: Safe, actors: []string{ActorWeb}, fixed: true},
	// Joining hands out the CA key: every step of it is dangerous.
	ClusterTokenCreate: {class: Dangerous, actors: []string{ActorAdmin}},
	ClusterJoin:        {class: Dangerous, actors: []string{ActorJoinToken}, fixed: true},
	ClusterPromote:     {class: Dangerous, actors: []string{ActorHub}, fixed: true},
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
	// A check from a device only connects and reads: it changes nothing,
	// and the device's agent runs it only if its ceiling allows probes.
	AutomationProbe: {class: Read, actors: []string{ActorAutomation}},
	// Adding a cluster hands the hub a credential to it; the hub only ever
	// reads with it, except for the kube.workload, kube.pod and kube.node
	// write actions below, each decided and audited on its own.
	KubeClusterAdd:    {class: Safe, actors: []string{ActorWeb}},
	KubeClusterRemove: {class: Safe, actors: []string{ActorWeb}},
	// Logs may carry secrets, so reading them is audited.
	KubePodLogs: {class: Read, actors: []string{ActorWeb, ActorMCP}},
	// A rolling restart, a scale, a pod deletion and a cordon are bounded and
	// undone by the next one: the controllers keep the workload running.
	// Automations may take them too (internal/automation's kube.* actions).
	KubeWorkloadRestart: {class: Safe, actors: []string{ActorWeb, ActorAutomation, ActorMCP}},
	KubeWorkloadScale:   {class: Safe, actors: []string{ActorWeb, ActorAutomation, ActorMCP}},
	KubePodDelete:       {class: Safe, actors: []string{ActorWeb, ActorAutomation, ActorMCP}},
	KubeNodeCordon:      {class: Safe, actors: []string{ActorWeb, ActorAutomation, ActorMCP}},
	KubeNodeUncordon:    {class: Safe, actors: []string{ActorWeb, ActorAutomation, ActorMCP}},
	// A drain takes every workload off a node: on a small homelab cluster
	// that can be most of the capacity. Being dangerous, an automation's
	// drain is denied unless it is granted or approved.
	KubeNodeDrain: {class: Dangerous, actors: []string{ActorWeb, ActorAutomation, ActorMCP}},
	// A notification touches no device: it tells a person something, on a
	// channel the operator configured.
	AutomationNotify: {class: Safe, actors: []string{ActorAutomation}},
	NotifyTest:       {class: Safe, actors: []string{ActorWeb}},
	// Approving releases an action of any class, so it counts as the worst.
	// Deciding is the operator's answer to a hold: holding it in turn would
	// never end.
	// An approval link decides the one approval it was sent for.
	ApprovalApprove: {class: Dangerous, actors: []string{ActorAdmin, ActorWeb, ActorApprovalLink}, fixed: true},
	ApprovalDeny:    {class: Safe, actors: []string{ActorAdmin, ActorWeb, ActorApprovalLink}, fixed: true},
	// What an MCP client reads is what the web UI shows.
	DeviceRead:    {class: Read, actors: []string{ActorMCP}},
	DeviceMetrics: {class: Read, actors: []string{ActorMCP}},
	KubeRead:      {class: Read, actors: []string{ActorMCP}},
	// As automation.restart and automation.exec, for an MCP client.
	DeviceRestart: {class: Safe, actors: []string{ActorMCP}},
	DeviceExec:    {class: Dangerous, actors: []string{ActorMCP}},
	// A plan only parses the file.
	AutomationPlan: {class: Read, actors: []string{ActorMCP}},
	// An applied automation runs on its own, again and again, long after the
	// request: as dangerous as anything it may do.
	AutomationApply: {class: Dangerous, actors: []string{ActorMCP}},
	// A token may carry the dangerous scope; revoking one only takes access
	// away.
	MCPTokenCreate: {class: Dangerous, actors: []string{ActorAdmin}},
	MCPTokenRevoke: {class: Safe, actors: []string{ActorAdmin}},
	// A scan only asks who is there (one datagram per address, one mDNS
	// query) and changes nothing on any host.
	NetworkScan: {class: Read, actors: []string{ActorHub}},
	// Marking a host changes only which alerts the operator gets about it.
	NetworkHostMark: {class: Safe, actors: []string{ActorWeb}},
}

// Actions returns every known action, sorted.
func Actions() []Action {
	out := slices.Collect(maps.Keys(rules))
	slices.Sort(out)
	return out
}

// ClassOf returns the class of a known action.
func ClassOf(a Action) (Class, bool) {
	r, ok := rules[a]
	return r.class, ok
}

// ErrDenied is returned when policy denies an action.
var ErrDenied = errors.New("denied by policy")

// ErrBeyondCeiling is returned when an action is beyond a device's
// capability ceiling, which the hub can never raise: the hub refuses it
// before sending it, and the device's agent refuses it again if it gets it.
// It matches ErrDenied.
var ErrBeyondCeiling = fmt.Errorf("beyond the device's capability ceiling: %w", ErrDenied)
