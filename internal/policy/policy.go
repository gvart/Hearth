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
	// AdminReauth is a signed-in admin entering the password again, before a
	// sensitive action of the web UI.
	AdminReauth Action = "admin.reauth"
	// ClusterTokenCreate creates a token that lets a new hub join the cluster
	// and receive the CA key.
	ClusterTokenCreate Action = "cluster.token.create"
	// ClusterJoin admits a new hub: it receives a node certificate and the CA
	// key, and joins the cluster as a member.
	ClusterJoin Action = "cluster.join"
	// ClusterPromote gives a member of the cluster the storage or master
	// role.
	ClusterPromote Action = "cluster.promote"
	// ClusterDemote takes the storage or master role from a member of the
	// cluster: a storage member hands its rows off first; a master spends
	// its tokens, expires its approvals and deletes the CA key.
	ClusterDemote Action = "cluster.demote"
	// ClusterRemove removes a member from the cluster for good.
	ClusterRemove Action = "cluster.remove"
	// ClusterCARotate starts a hub CA rotation: the leader generates a new CA
	// that every hub trusts next to the old one and signs new certificates with.
	ClusterCARotate Action = "cluster.ca.rotate"
	// ClusterCAFinish finishes a hub CA rotation: every hub serves the new CA,
	// drops the old one and deletes its key. Agents and hubs still on the old CA
	// are cut off.
	ClusterCAFinish Action = "cluster.ca.finish"
	// ClusterCAAbort gives up a hub CA rotation before its cutover: every hub
	// drops the new CA and its key. Agents it renewed have to enroll again.
	ClusterCAAbort Action = "cluster.ca.abort"
	// ClusterCAFetchKey hands the new CA's key, and a node certificate of it,
	// to a cluster member during a hub CA rotation.
	ClusterCAFetchKey Action = "cluster.ca.fetch_key"
	// ClusterNodeCertRenew issues a member of an AP cluster that holds no CA
	// key a new node certificate of the same CA, for the same member and
	// cluster epoch, as its certificate nears its expiry.
	ClusterNodeCertRenew Action = "cluster.node_cert.renew"
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
	// AutomationScript is an automation's script action: a Starlark script
	// run on the hub. It reads and acts only through the device.read and
	// automation actions it calls, each decided and audited on its own.
	AutomationScript Action = "automation.script"
	// AutomationProbe is an http, tcp or dns trigger, or a runbook check
	// step, checking from a device: the device's agent runs the check for
	// the hub.
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
	// KubeNodeDelete deletes a Node object from the cluster, such as one
	// left behind by a machine that was reset or uninstalled.
	KubeNodeDelete Action = "kube.node.delete"
	// KubeNodeReady reads whether a Node is Ready: a runbook's kube_node
	// check.
	KubeNodeReady Action = "kube.node.ready"
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
	// client or an automation's script.
	DeviceRead Action = "device.read"
	// DeviceMetrics reads a device's current metrics from Prometheus, for an
	// MCP client.
	DeviceMetrics Action = "device.metrics"
	// DeviceRestart restarts a systemd unit or Docker container on a device,
	// through its agent, for an MCP client or the guest of a panel whose
	// widget allows it.
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
	// directory, for an MCP client or the web UI's automation editor; the hub
	// then loads and runs it.
	AutomationApply Action = "automation.apply"
	// DeviceLogs opens a stream of a device's log source (a systemd unit or
	// Docker container), through its agent.
	DeviceLogs Action = "device.logs"
	// DeviceNetEdges reads the network edges a device's agent reported: its
	// neighbours and who it holds TCP connections with.
	DeviceNetEdges Action = "device.net_edges"
	// NetworkTopology reads the network edges every device's agent reported,
	// at once, for the topology view.
	NetworkTopology Action = "network.topology"
	// DeviceDockerList lists the containers and images of a device's Docker
	// or Podman engine, through its agent.
	DeviceDockerList Action = "device.docker.list"
	// DeviceDockerLogs reads the last lines of a container's log on a
	// device, through its agent: a bounded tail, never a follow.
	DeviceDockerLogs Action = "device.docker.logs"
	// DeviceDockerStart, DeviceDockerStop and DeviceDockerRestart start,
	// stop and restart a container on a device, through its agent.
	DeviceDockerStart   Action = "device.docker.start"
	DeviceDockerStop    Action = "device.docker.stop"
	DeviceDockerRestart Action = "device.docker.restart"
	// MCPTokenCreate creates a bearer token for an MCP client.
	MCPTokenCreate Action = "mcp.token.create" //nolint:gosec // an action name
	// MCPTokenRevoke revokes an MCP client's token.
	MCPTokenRevoke Action = "mcp.token.revoke" //nolint:gosec // an action name
	// NetworkScan is one network discovery scan by the hub: an ARP sweep
	// and an mDNS browse of the configured subnets, from the hub or, for a
	// subnet configured with a device, from that device's agent, within its
	// capability ceiling. The hub scans on its schedule, and when an admin
	// asks from the web UI or CLI.
	NetworkScan Action = "network.scan"
	// NetworkHostMark marks a host network discovery found known or
	// ignored, or neither again, which silences or restores its new-device
	// alerts.
	NetworkHostMark Action = "network.host.mark"
	// NetworkHostAdopt adopts a host network discovery found as an
	// agentless device under a name, or unadopts it: it is listed with the
	// devices, its presence from the scans, and fires no new-device alerts.
	NetworkHostAdopt Action = "network.host.adopt"
	// NetworkImport is one import of the hosts a Pi-hole, a NetAlertX and
	// DHCP lease files know, by the hub.
	NetworkImport Action = "network.import"
	// BeszelRead is one read by the hub of the systems a Beszel hub
	// monitors.
	BeszelRead Action = "beszel.read"
	// TalosRead is one read by the hub of the Talos nodes of a talosconfig:
	// versions, services, memory, load and boot time, through the Talos API;
	// on its own, or for a runbook's talos_node check.
	TalosRead Action = "talos.read"
	// ProxmoxServerAdd adopts a Proxmox VE server: the hub stores its API
	// token, sealed, and starts reading it.
	ProxmoxServerAdd Action = "proxmox.server.add"
	// ProxmoxServerRemove forgets an adopted Proxmox VE server and its token.
	ProxmoxServerRemove Action = "proxmox.server.remove"
	// ProxmoxGuestStart starts a stopped VM or LXC container.
	ProxmoxGuestStart Action = "proxmox.guest.start"
	// ProxmoxGuestStop stops a VM or LXC container at once, without a clean
	// shutdown.
	ProxmoxGuestStop Action = "proxmox.guest.stop"
	// ProxmoxGuestReboot shuts a VM or LXC container down and starts it again.
	ProxmoxGuestReboot Action = "proxmox.guest.reboot"
	// RunbookStart starts a run of a runbook from a signed-in session. Every
	// action step of the run is decided on its own.
	RunbookStart Action = "runbook.start"
	// RunbookAnswer answers a prompt of a runbook run.
	RunbookAnswer Action = "runbook.answer"
	// RunbookRetry runs a stopped runbook step again.
	RunbookRetry Action = "runbook.retry"
	// RunbookRollback rolls a stopped runbook run back, or passes over the
	// rollback step it stopped at.
	RunbookRollback Action = "runbook.rollback"
	// RunbookPassOver gives up on the rollback step a run stopped at and goes
	// on with the others: what that step should have undone stays as it is.
	RunbookPassOver Action = "runbook.pass_over" //nolint:gosec // an action name, not a credential
	// RunbookCheck is a check step of a runbook run: the hub reads a service
	// over the network and changes nothing.
	RunbookCheck Action = "runbook.check"
	// HubBackup writes an encrypted backup of the hub, CA key included, to a
	// file on the hub host.
	HubBackup Action = "hub.backup"
	// HubRestore brings a hub back from a backup into an empty data dir.
	HubRestore Action = "hub.restore"
	// HubScheduledBackup is the hub's own scheduled backup: an encrypted
	// backup, without the CA key unless the operator opts in, uploaded to
	// S3-compatible storage, with the oldest backups there pruned.
	HubScheduledBackup Action = "hub.scheduled_backup"
	// TelemetrySet stores the admin's answer to "Share anonymous usage
	// stats?": opting in or out of the hub's weekly anonymous telemetry.
	TelemetrySet Action = "telemetry.set"
	// DeviceShell opens an interactive shell on a device, on a terminal in
	// the web UI, through its agent.
	DeviceShell Action = "device.shell"
	// PanelSave creates or changes a guest or kiosk panel: its widgets and
	// the actions they allow its guests.
	PanelSave Action = "panel.save"
	// PanelDelete deletes a panel and every share link of it.
	PanelDelete Action = "panel.delete"
	// PanelLinkCreate creates a share link that opens a panel without a
	// login.
	PanelLinkCreate Action = "panel.link.create"
	// PanelLinkRevoke revokes a panel's share link.
	PanelLinkRevoke Action = "panel.link.revoke"
	// DashboardRead is a read of the dashboard summary (device counts and
	// states) by a dashboard such as Homepage, with a dashboard token.
	DashboardRead Action = "dashboard.read"
	// DashboardTokenCreate creates a read-only token for a dashboard.
	DashboardTokenCreate Action = "dashboard.token.create"
	// DashboardTokenRevoke revokes a dashboard's token.
	DashboardTokenRevoke Action = "dashboard.token.revoke"
	// ConfigImport writes configuration documents (policy.yaml, notify.yaml,
	// automation and runbook files) into the store, or deletes an automation
	// or runbook document, with `hearth config import` or `hearth config
	// delete` on a hub host. Every hub applies them: a policy import changes
	// what every other action may do.
	ConfigImport Action = "config.import"
	// ConfigImportFirst is a hub's one-time import of its own configuration
	// files into an empty store, when it first starts at schema 28. The files
	// were the configuration in effect already.
	ConfigImportFirst Action = "config.import.first"
	// ConfigExport writes the configuration documents to files, with
	// `hearth config export` on a hub host, notify.yaml's credentials in
	// clear: only the hub host's CLI exports, no API does.
	ConfigExport Action = "config.export"
	// PluginStart starts a configured exec plugin's process on the hub, or
	// restarts it after it stopped (docs/plugins.md).
	PluginStart Action = "plugin.start"
	// PluginCommandRead, PluginCommandSafe and PluginCommandDangerous run a
	// command an exec plugin declares in its manifest, of that class. The
	// operator's manifest, not the plugin process, sets the class.
	PluginCommandRead      Action = "plugin.command.read"
	PluginCommandSafe      Action = "plugin.command.safe"
	PluginCommandDangerous Action = "plugin.command.dangerous"
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
	// ActorGuest is the holder of a panel's share link, identified as
	// panel/<panel id>. The link is the credential, for that one panel: a
	// guest may take only the actions the panel's widgets allow, which are
	// never dangerous.
	ActorGuest = "guest"
	// ActorDashboard is a dashboard such as Homepage, identified as
	// token/<token id> by its dashboard token. The token reads the dashboard
	// summary and nothing else.
	ActorDashboard = "dashboard"
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
	// fixedFor are the actors for whom the rule is fixed, when not every
	// actor's is.
	fixedFor []string
}

// rules is the action table. Anything not listed here is denied.
var rules = map[Action]rule{
	// The web UI's "Add device" creates tokens behind an admin session.
	TokenCreate:  {class: Safe, actors: []string{ActorAdmin, ActorWeb}},
	DeviceEnroll: {class: Safe, actors: []string{ActorToken}, fixed: true},
	// The web UI revokes behind an admin session and the password again.
	DeviceRevoke: {class: Dangerous, actors: []string{ActorAdmin, ActorWeb}},
	// Changing the credential that guards everything else is dangerous. On
	// the hub host it is also how a hub gets its first password, and the way
	// back in when it is lost, so it is never held for approval there. A
	// signed-in admin changing it in the web UI, with the current password,
	// follows the modes.
	AdminSetPassword: {class: Dangerous, actors: []string{ActorAdmin, ActorWeb}, fixedFor: []string{ActorAdmin}},
	// Anyone on the network may try to log in; the password decides.
	AdminLogin: {class: Safe, actors: []string{ActorWeb}, fixed: true},
	// Entering the password again only proves who is at the session; the
	// password decides, as at login.
	AdminReauth: {class: Safe, actors: []string{ActorWeb}, fixed: true},
	// Joining hands out the CA key: every step of it is dangerous. The web
	// UI's "Add hub" creates a token behind an admin session and the
	// password again.
	ClusterTokenCreate: {class: Dangerous, actors: []string{ActorAdmin, ActorWeb}},
	ClusterJoin:        {class: Dangerous, actors: []string{ActorJoinToken}, fixed: true},
	// A promotion moves the CA key or the rows: dangerous, and held or
	// denied as the policy says.
	ClusterPromote: {class: Dangerous, actors: []string{ActorAdmin, ActorWeb}},
	// A demotion takes a master's CA key and tokens away, or moves a
	// storage member's rows; the last master or storage member stays.
	ClusterDemote: {class: Dangerous, actors: []string{ActorAdmin, ActorWeb}},
	// Removal changes the quorum and locks a hub out for good. A master
	// removes a member down for --member-dead-after as the hub, following
	// the modes: a policy may hold it for approval or deny it.
	ClusterRemove: {class: Dangerous, actors: []string{ActorAdmin, ActorWeb, ActorHub}},
	// A rotation hands out a new CA key and, once finished, cuts off whatever
	// still holds an old-CA certificate. The web UI asks behind an admin
	// session and the password again.
	ClusterCARotate: {class: Dangerous, actors: []string{ActorAdmin, ActorWeb}},
	ClusterCAFinish: {class: Dangerous, actors: []string{ActorAdmin, ActorWeb}},
	ClusterCAAbort:  {class: Dangerous, actors: []string{ActorAdmin, ActorWeb}},
	// A member fetching the new CA key proves itself with its pinned node
	// certificate, in a protocol no operator could stop to approve.
	ClusterCAFetchKey: {class: Dangerous, actors: []string{ActorHub}, fixed: true},
	// A renewal grants nothing new: the same member, CA and epoch, for a
	// live, unrevoked member whose certificate is about to expire.
	ClusterNodeCertRenew: {class: Safe, actors: []string{ActorHub}, fixed: true},
	// Writing a log line changes nothing.
	AutomationLog: {class: Read, actors: []string{ActorAutomation}},
	// A webhook touches no device: it tells another system something.
	AutomationWebhook: {class: Safe, actors: []string{ActorAutomation}},
	// A restart is bounded and repeatable, the routine homelab fix, and
	// the device's agent restarts only the services its ceiling names.
	AutomationRestart: {class: Safe, actors: []string{ActorAutomation}},
	// An arbitrary command can do anything the agent can.
	AutomationExec: {class: Dangerous, actors: []string{ActorAutomation}},
	// A script by itself only computes, within its step and time limits:
	// every device read and action it calls is decided on its own, as the
	// automation, and a dangerous one is denied unless granted or approved.
	AutomationScript: {class: Safe, actors: []string{ActorAutomation}},
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
	// Deleting a Node object cannot be undone by Hearth: its pods are
	// deleted with it, and only the node's kubelet can register it again.
	// It is for runbooks and automations, the clean-up after a rollback.
	KubeNodeDelete: {class: Dangerous, actors: []string{ActorAutomation}},
	// Reading one Node's conditions changes nothing.
	KubeNodeReady: {class: Read, actors: []string{ActorAutomation}},
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
	// What an MCP client reads is what the web UI shows. An automation's
	// script reads the same.
	DeviceRead:    {class: Read, actors: []string{ActorMCP, ActorAutomation}},
	DeviceMetrics: {class: Read, actors: []string{ActorMCP}},
	KubeRead:      {class: Read, actors: []string{ActorMCP}},
	// As automation.restart and automation.exec, for an MCP client.
	// A panel's guest restarts only the service a widget names.
	DeviceRestart: {class: Safe, actors: []string{ActorMCP, ActorGuest}},
	DeviceExec:    {class: Dangerous, actors: []string{ActorMCP}},
	// Logs may carry secrets, so every stream opened is audited, and the
	// device's agent streams only the sources its ceiling names.
	DeviceLogs: {class: Read, actors: []string{ActorWeb}},
	// Connections say who talks to whom, so every read is audited, and only
	// an agent started with --allow-net-edges reports them.
	DeviceNetEdges: {class: Read, actors: []string{ActorWeb}},
	// As device.net_edges, for every device at once.
	NetworkTopology: {class: Read, actors: []string{ActorWeb}},
	// Listing containers changes nothing; a log may carry secrets, so every
	// read is audited. Starting, stopping and restarting a container is
	// bounded and undone by the next one, as a service restart is. The
	// device's agent does any of it only with --allow-docker, and nothing
	// else of the engine's API (no exec, create, remove or pull).
	DeviceDockerList:    {class: Read, actors: []string{ActorWeb}},
	DeviceDockerLogs:    {class: Read, actors: []string{ActorWeb}},
	DeviceDockerStart:   {class: Safe, actors: []string{ActorWeb}},
	DeviceDockerStop:    {class: Safe, actors: []string{ActorWeb}},
	DeviceDockerRestart: {class: Safe, actors: []string{ActorWeb}},
	// A plan only parses the file.
	AutomationPlan: {class: Read, actors: []string{ActorMCP}},
	// An applied automation runs on its own, again and again, long after the
	// request: as dangerous as anything it may do.
	AutomationApply: {class: Dangerous, actors: []string{ActorMCP, ActorWeb}},
	// A token may carry the dangerous scope; revoking one only takes access
	// away.
	MCPTokenCreate: {class: Dangerous, actors: []string{ActorAdmin, ActorWeb}},
	MCPTokenRevoke: {class: Safe, actors: []string{ActorAdmin, ActorWeb}},
	// A scan only asks who is there (one datagram per address, one mDNS
	// query) and changes nothing on any host, whether the hub or a device's
	// agent sends it, on the hub's schedule or an admin's request; an agent
	// scans only subnets its ceiling allows.
	NetworkScan: {class: Read, actors: []string{ActorHub, ActorWeb}},
	// Marking a host changes only which alerts the operator gets about it.
	NetworkHostMark: {class: Safe, actors: []string{ActorWeb}},
	// Adopting a host only names it and lists it with the devices: no
	// enrollment, no certificate, nothing runs on it.
	NetworkHostAdopt: {class: Safe, actors: []string{ActorWeb}},
	// An import reads Pi-hole's and NetAlertX's APIs and lease files; it
	// changes nothing.
	NetworkImport: {class: Read, actors: []string{ActorHub}},
	// A Beszel read lists the systems Beszel monitors; it changes nothing.
	BeszelRead: {class: Read, actors: []string{ActorHub}},
	// A Talos read calls only read methods of the Talos API; it changes
	// nothing on any node. The hub reads on its own, and for a runbook's
	// talos_node check.
	TalosRead: {class: Read, actors: []string{ActorHub, ActorAutomation}},
	// Adding a server hands the hub a credential to it; the hub only reads
	// with it, except for the proxmox.guest actions below, each decided and
	// audited on its own.
	ProxmoxServerAdd:    {class: Safe, actors: []string{ActorWeb}},
	ProxmoxServerRemove: {class: Safe, actors: []string{ActorWeb}},
	// Starting a guest brings a service up and loses nothing.
	ProxmoxGuestStart: {class: Safe, actors: []string{ActorWeb}},
	// A stop pulls the plug and may damage the guest's data; a reboot takes
	// down whatever the guest serves.
	ProxmoxGuestStop:   {class: Dangerous, actors: []string{ActorWeb}},
	ProxmoxGuestReboot: {class: Dangerous, actors: []string{ActorWeb}},
	// Starting a run does nothing by itself: each action step goes through
	// policy again, as the runbook.
	RunbookStart: {class: Safe, actors: []string{ActorWeb}},
	// An answer to a run that stopped to ask: holding it for approval in turn
	// would leave the run stuck, and the steps it leads to are decided anyway.
	RunbookAnswer: {class: Safe, actors: []string{ActorWeb}, fixed: true},
	// Deciding what a stopped run does next follows the hub's policy file;
	// each step that follows is decided on its own as well.
	RunbookRetry:    {class: Safe, actors: []string{ActorWeb}},
	RunbookRollback: {class: Safe, actors: []string{ActorWeb}},
	RunbookPassOver: {class: Safe, actors: []string{ActorWeb}},
	// A check reads a service and changes nothing.
	RunbookCheck: {class: Read, actors: []string{ActorAutomation}},
	// A backup carries the CA key out of the data dir, encrypted.
	// The web UI streams it to the browser behind the password again.
	HubBackup: {class: Dangerous, actors: []string{ActorAdmin, ActorWeb}},
	// A restore brings back a CA and every credential. It is the way back
	// after losing the hub, when no one is left to approve it.
	HubRestore: {class: Dangerous, actors: []string{ActorAdmin}, fixed: true},
	// The operator turns scheduled backups on with the hub's flags, the
	// passphrase file and the bucket's credentials: that is the grant. No one
	// is there to approve each run.
	HubScheduledBackup: {class: Dangerous, actors: []string{ActorHub}, fixed: true},
	// A config import replaces the policy itself, notification credentials
	// and what automations and runbooks do, on every hub: only the operator
	// on a hub host, or a signed-in admin in the web UI's editors (policy,
	// notification channels, runbooks, deleting an automation), and never
	// fixed, so a policy may hold it for approval.
	ConfigImport: {class: Dangerous, actors: []string{ActorAdmin, ActorWeb}},
	// The first import records the files a hub already runs with: nothing
	// changes, and the hub is starting, with no one to approve it.
	ConfigImportFirst: {class: Dangerous, actors: []string{ActorHub}, fixed: true},
	// An export reads the configuration, notify.yaml's credentials too, to
	// the hub host's disk, where the files were before.
	ConfigExport: {class: Read, actors: []string{ActorAdmin}},
	// The answer changes only whether the hub sends a few anonymous counts a
	// week (docs/telemetry.md); it touches no device. Only a signed-in admin
	// answers.
	TelemetrySet: {class: Safe, actors: []string{ActorWeb}},
	// A shell can do anything the agent's user can. Only a person at the
	// web UI, behind an admin session, may open one: never an automation
	// or an MCP client.
	DeviceShell: {class: Dangerous, actors: []string{ActorWeb}},
	// A panel shows a few entities and allows only read and safe actions on
	// them, each decided again when a guest takes it. Sharing it hands out
	// that much, and revoking or deleting only takes it away.
	PanelSave:       {class: Safe, actors: []string{ActorWeb}},
	PanelDelete:     {class: Safe, actors: []string{ActorWeb}},
	PanelLinkCreate: {class: Safe, actors: []string{ActorWeb}},
	PanelLinkRevoke: {class: Safe, actors: []string{ActorWeb}},
	// A dashboard reads device counts and states, no more than a panel's
	// guest sees. A token hands out only that, and revoking takes it away.
	DashboardRead:        {class: Read, actors: []string{ActorDashboard}},
	DashboardTokenCreate: {class: Safe, actors: []string{ActorWeb}},
	DashboardTokenRevoke: {class: Safe, actors: []string{ActorWeb}},
	// The operator turns a plugin on by naming its manifest in the hub's
	// flags: that is the grant. A plugin runs as a child process of the hub
	// with the hub's user, so it counts as the worst; no one is there to
	// approve a restart after a crash.
	PluginStart: {class: Dangerous, actors: []string{ActorHub}, fixed: true},
	// A plugin command is as risky as the class its manifest declares. A
	// command the manifest does not declare is decided as dangerous, and
	// denied. Automations, runbooks and MCP clients run them as the web UI
	// does, each under its own class modes and an MCP token's scope.
	PluginCommandRead:      {class: Read, actors: []string{ActorWeb, ActorAutomation, ActorMCP}},
	PluginCommandSafe:      {class: Safe, actors: []string{ActorWeb, ActorAutomation, ActorMCP}},
	PluginCommandDangerous: {class: Dangerous, actors: []string{ActorWeb, ActorAutomation, ActorMCP}},
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

// Admits reports whether the rule of action a admits actor kind at all,
// before any configuration: a panel offers its guests only the actions that
// admit ActorGuest.
func Admits(a Action, kind string) bool {
	r, ok := rules[a]
	return ok && slices.Contains(r.actors, kind)
}

// ErrDenied is returned when policy denies an action.
var ErrDenied = errors.New("denied by policy")

// ErrBeyondCeiling is returned when an action is beyond a device's
// capability ceiling, which the hub can never raise: the hub refuses it
// before sending it, and the device's agent refuses it again if it gets it.
// It matches ErrDenied.
var ErrBeyondCeiling = fmt.Errorf("beyond the device's capability ceiling: %w", ErrDenied)

// ErrReauth is returned when an approval is refused because the approver did
// not re-authenticate: approving a held action takes the approver's password
// again, so a session alone, such as a stolen one, cannot approve. It is
// returned together with ErrDenied.
var ErrReauth = errors.New("approver not re-authenticated")

// ErrLinkApprove is returned when an approval link is used to approve: a link
// can only deny. Approving needs a signed-in approver and their password. It
// is returned together with ErrDenied.
var ErrLinkApprove = errors.New("an approval link can only deny; sign in to Hearth to approve, with your password")
