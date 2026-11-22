// Typed client for the hub's JSON API (/api/v1). Every network call the UI
// makes lives in this directory.

export type DeviceStatus = 'unknown' | 'online' | 'offline';

export interface Disk {
  device: string;
  mountpoint: string;
  fstype: string;
  total_bytes: number;
  /** Space in use when the agent last sent its facts; absent from an agent that does not report it. */
  used_bytes?: number;
}

export interface NetInterface {
  name: string;
  mac: string;
  ips: string[];
}

// Facts are what the agent reported in its last Hello. A device that never
// connected has none, so every field is optional.
export interface Facts {
  hostname?: string;
  os?: string;
  arch?: string;
  kernel?: string;
  cpu_model?: string;
  cpu_cores?: number;
  mem_total_bytes?: number;
  disks?: Disk[];
  interfaces?: NetInterface[];
  agent_version?: string;
  capabilities?: string[];
  /** What the device's agent lets the hub do; absent for an agent too old to say. */
  ceiling?: Ceiling;
}

export interface Ceiling {
  exec: string[];
  restart: string[];
  probe: boolean;
  /** Log sources the hub may stream, as manager:pattern (systemd:*, docker:web). */
  logs?: string[];
  /** Whether an admin may open a terminal (the agent runs with --allow-shell). */
  shell?: boolean;
  /** IPv4 subnets network discovery may sweep from the device (--allow-scan). */
  scan?: string[];
  /** Whether the agent reports its neighbours and connections (--allow-net-edges). */
  net_edges?: boolean;
  /** Whether the hub may list and start, stop and restart its containers (--allow-docker). */
  docker?: boolean;
}

export interface Device {
  id: string;
  name: string;
  hostname: string;
  os: string;
  arch: string;
  status: DeviceStatus;
  labels: Record<string, string>;
  facts: Facts;
  first_seen: string;
  last_seen: string;
  /** When the host last booted (RFC 3339); null until a heartbeat reports uptime. */
  boot_time: string | null;
}

export interface Session {
  user: string;
  expires_at: string;
  /** Until when sensitive actions need no password again; absent when they do. */
  reauth_until?: string;
  /** The hub's build version. */
  version?: string;
}

export interface CreateTokenOptions {
  ttl?: string;
  labels?: Record<string, string>;
  name?: string;
  hub?: boolean;
}

export interface CreatedToken {
  token: string;
  expires_at: string;
  install_command: string;
  join_command: string;
}

/** One per-hub configuration item compared across the cluster's hubs: host_flags. */
export interface ConfigDriftItem {
  item: string;
  status: 'in_sync' | 'differs' | 'unknown';
  /** Hubs with the same content, one group per distinct content. */
  groups: string[][];
  /** Hubs that did not report this item. */
  unknown: string[];
}

/** See GET /api/v1/cluster/config-drift. Empty on a standalone hub. */
export interface ConfigDrift {
  hubs: { id: string; reported: boolean; reason?: string }[];
  items: ConfigDriftItem[];
}

/** How to reach the hub over HTTPS; see GET /api/v1/tls. */
export interface TlsInfo {
  /** The HTTPS port. */
  port: string;
  /** Names the hub certificate is valid for. */
  hosts: string[];
  /** SHA-256 of the hub CA certificate, as colon-separated hex pairs. */
  ca_fingerprint: string;
}

/** Why device metrics have no charts; `ok` means they do. */
export type MetricsStatus = 'ok' | 'not_configured' | 'unreachable' | 'no_target' | 'no_data';

export interface MetricChart {
  key: string;
  name: string;
  unit: string;
  /** [unix milliseconds, value] pairs. */
  points: [number, number][];
}

/** A device's chart series, from the hub's own metrics or Prometheus; see GET /api/v1/devices/{id}/metrics. */
export interface DeviceMetrics {
  source: 'builtin' | 'prometheus';
  status: MetricsStatus;
  message?: string;
  /** The Prometheus `instance` label the device mapped to. */
  instance?: string;
  /** The charted range in unix milliseconds; set when status is ok. */
  start?: number;
  end?: number;
  charts: MetricChart[];
}

/** A range the device charts offer, as the hub parses it. */
export type MetricsRange = '1h' | '24h' | '168h';

/** The last hour of every device's built-in metrics; see GET /api/v1/metrics/sparklines. */
export interface MetricsSparklines {
  /** The range in unix milliseconds. */
  start: number;
  end: number;
  /** Charts by device ID; devices without recent metrics are absent. */
  devices: Record<string, MetricChart[] | undefined>;
}

export type DeviceEventType = 'device.online' | 'device.offline' | 'device.updated';

export interface DeviceEvent {
  type: DeviceEventType;
  device: Device;
}

export type NetworkHostSource = 'scan' | 'pihole' | 'dhcp' | 'netalertx';

/** How a network scan asked for with POST /api/v1/network/scan ended (event network.scan.done). */
export interface NetworkScanDone {
  /** The scan's id, as POST /api/v1/network/scan answered it. */
  id: string;
  hosts: number;
  new: number;
  returned: number;
  duration_ms: number;
  /** Why the scan failed; absent when it did not. */
  error?: string;
}

/** A host network discovery found on the LAN; see /api/v1/network/hosts. */
export interface NetworkHost {
  /** Lower-case, colon-separated; the host's identity across IP changes. */
  mac: string;
  ip: string;
  /** From Pi-hole, a DHCP lease, NetAlertX, mDNS or LAN reverse DNS; empty when unknown. */
  hostname: string;
  /** Where the host was learned: the network scan, Pi-hole, DHCP lease files, NetAlertX. */
  sources: NetworkHostSource[];
  /** The source that gave `hostname`; empty when none did. */
  hostname_source: NetworkHostSource | '';
  /** From the MAC's OUI; empty when unknown or the MAC is randomized. */
  vendor: string;
  /** The enrolled device with this MAC; empty for an unmanaged host. */
  device_id: string;
  first_seen: string;
  last_seen: string;
  /** What the operator marked it: known, ignored and adopted hosts fire no new-device alerts. */
  state: NetworkHostState;
  /** The name it was adopted under; empty unless adopted. */
  name: string;
  /** Whether a scan or an import saw it within twice the discover interval. */
  online: boolean;
  /** The device whose agent last found the host in a scan; empty when the hub did. */
  scanned_by: string;
  /** The mDNS service types it answers for, as `_ipp._tcp`, sorted. */
  services: string[];
  /** What it looks like, from its services, vendor, hostname and being the gateway. */
  kind: NetworkHostKind;
  /** Whether it looks able to run a Hearth agent: a computer, or anything offering SSH. */
  agent_capable: boolean;
}

export type NetworkHostKind = 'router' | 'printer' | 'media' | 'phone' | 'computer' | 'nas' | 'iot' | 'unknown';

export type NetworkHostState = '' | 'known' | 'ignored' | 'adopted';

export type BeszelSystemStatus = 'up' | 'down' | 'paused' | 'pending';

/** A system a Beszel hub monitors, as the hub last read it; see /api/v1/beszel/systems. */
export interface BeszelSystem {
  id: string;
  name: string;
  /** The IP address or hostname Beszel reaches the system's agent at. */
  host: string;
  status: BeszelSystemStatus;
  /** Percent in use; disk is the root filesystem. */
  cpu: number;
  memory: number;
  disk: number;
  /** Seconds. */
  uptime: number;
  agent_version: string;
  /** The enrolled device this system is; empty if none. */
  device_id: string;
  device_name: string;
  /** The network host this system is, when it is no enrolled device; empty if none. */
  network_mac: string;
}

/** A Talos system service (apid, etcd, kubelet, ...). */
export interface TalosService {
  id: string;
  state: string;
  /** unknown: a service without a health check. */
  health: 'healthy' | 'unhealthy' | 'unknown';
  message?: string;
}

/** A Talos node, as the hub last read it through the Talos API; see /api/v1/talos/nodes. */
export interface TalosNode {
  /** The address or name the node is read at. */
  address: string;
  hostname: string;
  /** Why the node could not be read; the other fields are then empty. */
  error?: string;
  version: string;
  arch: string;
  platform: string;
  /** Every service running and none failing its health check. */
  healthy: boolean;
  services: TalosService[] | null;
  /** Bytes. */
  mem_total: number;
  mem_available: number;
  load1: number;
  load5: number;
  load15: number;
  boot_time: string;
  /** The enrolled device this node is (its DaemonSet agent); empty if none. */
  device_id: string;
  device_name: string;
}

export interface TalosNodes {
  status: 'not_configured' | 'connecting' | 'ok' | 'unavailable';
  error?: string;
  read_at: string | null;
  nodes: TalosNode[];
}

export interface BeszelSystems {
  status: 'not_configured' | 'connecting' | 'ok' | 'unavailable';
  /** Why the last read failed. */
  error?: string;
  /** When the last read that succeeded finished; null if none has. */
  read_at: string | null;
  systems: BeszelSystem[];
}

/** A Kubernetes cluster adopted through a kubeconfig; see /api/v1/kube. */
export type KubeState = 'connecting' | 'connected' | 'error';

export interface KubeCluster {
  id: string;
  name: string;
  server: string;
  context: string;
  state: KubeState;
  error: string;
  created_at: string;
  nodes: number;
  pods: number;
  /** Set on a kube.cluster event for a cluster that was removed. */
  removed?: boolean;
}

export interface KubeNode {
  name: string;
  ready: boolean;
  unschedulable: boolean;
  roles: string[];
  kubelet_version: string;
  os_image: string;
  arch: string;
  hostname: string;
  addresses: string[];
  cpu: string;
  memory: string;
  created: string;
  /** The Hearth device this node runs on, matched by IP or hostname; "" if none. */
  device_id: string;
}

export interface KubeNamespace {
  name: string;
  phase: string;
  created: string;
}

export interface KubeWorkload {
  kind: 'Deployment' | 'StatefulSet' | 'DaemonSet';
  namespace: string;
  name: string;
  desired: number;
  ready: number;
  created: string;
}

export interface KubePod {
  namespace: string;
  name: string;
  /** What `kubectl get pods` shows: Running, Pending, CrashLoopBackOff, ... */
  status: string;
  phase: string;
  ready: string;
  restarts: number;
  node: string;
  ip: string;
  owner: string;
  containers: string[];
  created: string;
}

export interface KubeEvent {
  uid: string;
  namespace: string;
  type: string;
  reason: string;
  message: string;
  object: string;
  count: number;
  last: string;
}

export interface KubeSnapshot {
  cluster: KubeCluster;
  nodes: KubeNode[];
  namespaces: KubeNamespace[];
  workloads: KubeWorkload[];
  pods: KubePod[];
  /** Newest first. */
  events: KubeEvent[];
}

export type KubeKind = 'node' | 'namespace' | 'workload' | 'pod' | 'event';

/** One entity added, changed or deleted in a cluster (a kube.object event). */
export interface KubeChange {
  cluster: string;
  kind: KubeKind;
  op: 'upsert' | 'delete';
  key: string;
  object?: KubeNode | KubeNamespace | KubeWorkload | KubePod | KubeEvent;
}

/** A Kubernetes action; see POST /api/v1/kube/clusters/{id}/actions. */
export type KubeActionName = 'restart' | 'scale' | 'delete_pod' | 'cordon' | 'uncordon' | 'drain';

export interface KubeActionRequest {
  action: KubeActionName;
  /** The workload's kind, for restart and scale. */
  kind?: string;
  namespace?: string;
  name: string;
  replicas?: number;
  timeout_seconds?: number;
  /** Only plan: read the objects involved and change nothing. */
  dry_run?: boolean;
}

/** The plan of an action and, unless it was a dry run, what came of it. */
export interface KubeActionResult {
  action: KubeActionName;
  class: 'read' | 'safe' | 'dangerous';
  target: string;
  dry_run: boolean;
  summary: string;
  steps: string[];
  warnings: string[];
  result?: string;
}

/** A notification channel configured on the hub; see /api/v1/notify. */
export interface NotifyChannel {
  name: string;
  type: 'ntfy' | 'telegram';
}

export type ActionClass = 'read' | 'safe' | 'dangerous';

/** A policy decision: allowed, held for approval, or denied. */
export type Decision = 'allow' | 'confirm' | 'deny';

/** One audit log entry; see GET /api/v1/audit. */
export interface AuditEntry {
  id: number;
  ts: string;
  actor_kind: string;
  actor_id: string;
  action: string;
  /** The action's policy class; empty for an action the hub no longer knows. */
  class: ActionClass | '';
  target: string;
  decision: Decision;
  result: string;
  detail: Record<string, unknown>;
}

export interface AuditPage {
  /** Newest first. */
  entries: AuditEntry[];
  /** The before= cursor of the next, older page; absent on the last page. */
  next_before?: number;
  /** The before= cursor of the next page on a hub of an AP cluster, where entry ids are not unique. */
  next_cursor?: string;
  /** Every action policy knows, for the filter. */
  actions: string[];
}

/** Audit log filters; empty fields match everything. */
export interface AuditFilter {
  actor_kind?: string;
  /** Part of the actor id. */
  actor?: string;
  action?: string;
  class?: ActionClass;
  decision?: Decision;
  /** A device id: entries targeting its id, name or hostname. */
  device?: string;
  /** RFC 3339. */
  since?: string;
  until?: string;
}

/** A runbook file the hub loaded; see /api/v1/runbooks. */
export interface Runbook {
  id: string;
  description?: string;
  steps: number;
}

export interface RunbookList {
  runbooks: Runbook[];
  /** What is wrong with the files that could not be loaded. */
  errors: string[];
}

/** One step of a plan, with what policy would decide on it now. */
export interface RunbookPlanStep {
  id: string;
  type: string;
  what: string;
  description?: string;
  target?: string;
  action?: string;
  class?: string;
  decision?: 'allow' | 'confirm' | 'deny';
  reason?: string;
  rollback?: RunbookPlanStep;
}

export interface RunbookPlan {
  id: string;
  description?: string;
  steps: RunbookPlanStep[];
}

export type RunbookRunStatus =
  | 'running'
  | 'waiting'
  | 'failed'
  | 'unknown'
  | 'rolling_back'
  | 'rollback_failed'
  | 'succeeded'
  | 'rolled_back';

export interface RunbookPrompt {
  kind: 'input' | 'confirm';
  message: string;
  secret: boolean;
  timeout_ms: number;
}

export interface RunbookRollback {
  what: string;
  status: string;
  attempts: number;
  error?: string;
}

export interface RunbookStep {
  id: string;
  type: string;
  what: string;
  description?: string;
  status: string;
  attempts: number;
  error?: string;
  prompt?: RunbookPrompt;
  rollback?: RunbookRollback;
}

export interface RunbookLogEntry {
  at: string;
  step?: string;
  actor?: string;
  message: string;
}

export interface RunbookRun {
  id: string;
  runbook_id: string;
  status: RunbookRunStatus;
  /** Named by an operator's decision, so it applies to the run as they saw it. */
  version: number;
  started_by: string;
  started_at: string;
  updated_at: string;
  finished_at?: string;
  can_retry: boolean;
  can_rollback: boolean;
  can_pass_over: boolean;
  /** The step whose rollback a pass-over has to name. */
  pass_over_step?: string;
  phase: 'forward' | 'rollback';
  /** The prompt step waiting for an answer. */
  awaiting?: string;
  deadline?: string;
  error?: string;
  steps: RunbookStep[];
  log: RunbookLogEntry[];
}

export type ApprovalStatus = 'pending' | 'approved' | 'denied' | 'expired';

/** An action policy holds until someone approves it; see /api/v1/approvals. */
export interface Approval {
  id: string;
  created_at: string;
  expires_at: string;
  actor_kind: string;
  actor_id: string;
  action: string;
  class: ActionClass;
  target: string;
  /** The request's audit detail. */
  detail: Record<string, unknown>;
  status: ApprovalStatus;
  /** Who decided, as kind/id ("web/192.168.1.5", "approval_link/...", "timeout"). */
  decided_by?: string;
  decided_at?: string;
}

/** The admin's answer to the telemetry prompt; see GET /api/v1/telemetry and docs/telemetry.md. */
export interface TelemetrySetting {
  /** False until the admin answers: the UI then asks. */
  answered: boolean;
  enabled: boolean;
  /** HEARTH_TELEMETRY=off on the hub: nothing is sent and the UI does not ask. */
  disabled_by_env: boolean;
}

/** An action a panel widget allows its guests; see docs/panels.md. */
export interface PanelAction {
  /** Set by the hub: the action's key within its widget. */
  id: string;
  action: string;
  /** For device.restart: the service, as manager:name. */
  service?: string;
  /** Set by the hub: read or safe, never dangerous. */
  class: ActionClass;
}

export interface PanelWidget {
  /** Set by the hub when empty; kept across edits. */
  id: string;
  kind: 'device';
  /** The device ID. */
  entity: string;
  actions: PanelAction[];
}

export interface PanelLink {
  id: string;
  created_at: string;
  expires_at: string | null;
  revoked_at: string | null;
  status: 'active' | 'expired' | 'revoked';
}

export interface Panel {
  id: string;
  name: string;
  widgets: PanelWidget[];
  links: PanelLink[];
  created_at: string;
  updated_at: string;
}

/** What a panel save sends: IDs and classes are filled in by the hub. */
export interface PanelInput {
  name: string;
  widgets: { id?: string; kind: 'device'; entity: string; actions: { action: string; service?: string }[] }[];
}

/** A new share link: the only time its token is shown. */
export interface CreatedPanelLink {
  link: PanelLink;
  token: string;
  /** /p/<token> */
  path: string;
}

/** A read-only token of a dashboard such as Homepage; see docs/homepage.md. */
export interface DashboardToken {
  id: string;
  name: string;
  created_at: string;
  expires_at: string | null;
  revoked_at: string | null;
  status: 'active' | 'expired' | 'revoked';
}

/** A new dashboard token: the only time its secret is shown. */
export interface CreatedDashboardToken {
  token: DashboardToken;
  secret: string;
}

/** A panel as its guests see it: names and states, nothing else. */
export interface GuestPanel {
  name: string;
  widgets: {
    id: string;
    kind: 'device';
    name: string;
    status: DeviceStatus;
    last_seen: string | null;
    actions: { id: string; label: string }[];
  }[];
}

/** ApiError carries the hub's `{"error","code"}` body and the HTTP status. */
export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  /** The answer's body, for errors that carry more than a message. */
  readonly body: unknown;

  constructor(status: number, code: string, message: string, body?: unknown) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
    this.body = body;
  }
}

const base = '/api/v1';

export async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = { Accept: 'application/json' };
  const init: RequestInit = { method, credentials: 'same-origin', headers };
  if (body !== undefined) {
    headers['Content-Type'] = 'application/json';
    init.body = JSON.stringify(body);
  }
  const res = await fetch(base + path, init);
  if (res.status === 204) {
    return undefined as T;
  }
  const data: unknown = await res.json().catch(() => null);
  if (!res.ok) {
    const err = (data ?? {}) as Partial<{ error: string; code: string }>;
    throw new ApiError(res.status, err.code ?? 'unknown', err.error ?? `request failed with status ${String(res.status)}`, data);
  }
  return data as T;
}

export const api = {
  login: (password: string) => request<Session>('POST', '/login', { password }),
  logout: () => request<undefined>('POST', '/logout'),
  /** The current session, or null when not logged in. */
  session: async (): Promise<Session | null> => {
    try {
      return await request<Session>('GET', '/session');
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        return null;
      }
      throw err;
    }
  },
  devices: async () => (await request<{ devices: Device[] }>('GET', '/devices')).devices,
  networkHosts: async () => (await request<{ hosts: NetworkHost[] }>('GET', '/network/hosts')).hosts,
  beszelSystems: () => request<BeszelSystems>('GET', '/beszel/systems'),
  talosNodes: () => request<TalosNodes>('GET', '/talos/nodes'),
  deviceMetrics: (id: string, range: MetricsRange = '1h') =>
    request<DeviceMetrics>('GET', `/devices/${encodeURIComponent(id)}/metrics?range=${encodeURIComponent(range)}`),
  metricsSparklines: () => request<MetricsSparklines>('GET', '/metrics/sparklines'),
  tlsInfo: () => request<TlsInfo>('GET', '/tls'),
  configDrift: () => request<ConfigDrift>('GET', '/cluster/config-drift'),
  /**
   * `name` names the device that enrolls with the token; without it, the device takes its hostname.
   * `hub` lets a capable Linux device installed with it become a hub (it may receive the CA key): the hub
   * asks for the admin password again.
   */
  createToken: (opts: CreateTokenOptions = {}) => request<CreatedToken>('POST', '/tokens', opts),
  audit: (filter: AuditFilter, before?: number | string) => {
    const q = new URLSearchParams();
    for (const [k, v] of Object.entries(filter)) {
      if (typeof v === 'string' && v !== '') {
        q.set(k, v);
      }
    }
    if (before !== undefined) {
      q.set('before', String(before));
    }
    return request<AuditPage>('GET', `/audit?${q.toString()}`);
  },
  kubeClusters: async () => (await request<{ clusters: KubeCluster[] }>('GET', '/kube/clusters')).clusters,
  kubeCluster: (id: string) => request<KubeSnapshot>('GET', `/kube/clusters/${encodeURIComponent(id)}`),
  addKubeCluster: (opts: { name: string; kubeconfig: string }) => request<KubeCluster>('POST', '/kube/clusters', opts),
  removeKubeCluster: (id: string) => request<undefined>('DELETE', `/kube/clusters/${encodeURIComponent(id)}`),
  kubePodLogs: async (opts: { cluster: string; namespace: string; pod: string; container: string; tail: number }) => {
    const e = encodeURIComponent;
    const q = new URLSearchParams({ container: opts.container, tail: String(opts.tail) });
    const path = `/kube/clusters/${e(opts.cluster)}/pods/${e(opts.namespace)}/${e(opts.pod)}/logs?${q.toString()}`;
    return (await request<{ logs: string }>('GET', path)).logs;
  },
  kubeAction: (cluster: string, req: KubeActionRequest) =>
    request<KubeActionResult>('POST', `/kube/clusters/${encodeURIComponent(cluster)}/actions`, req),
  /** Starts a scan of the hub's network; it ends with a network.scan.done event with its id. 409 while one runs. */
  scanNetwork: () => request<{ id: string }>('POST', '/network/scan'),
  /** Marks a host known or ignored, or neither again (''). */
  markNetworkHost: (mac: string, state: Exclude<NetworkHostState, 'adopted'>) =>
    request<undefined>(
      'POST',
      `/network/hosts/${encodeURIComponent(mac)}/${state === 'known' ? 'known' : state === 'ignored' ? 'ignore' : 'unmark'}`,
    ),
  /** Adopts a host as a device without an agent under a name, or renames it. */
  adoptNetworkHost: (mac: string, name: string) =>
    request<undefined>('POST', `/network/hosts/${encodeURIComponent(mac)}/adopt`, { name }),
  /** Stops listing an adopted host as a device. */
  unadoptNetworkHost: (mac: string) => request<undefined>('POST', `/network/hosts/${encodeURIComponent(mac)}/unadopt`),
  notifyChannels: async () => (await request<{ channels: NotifyChannel[] }>('GET', '/notify/channels')).channels,
  testNotifyChannel: (name: string) =>
    request<undefined>('POST', `/notify/channels/${encodeURIComponent(name)}/test`),
  /** The newest approvals: pending ones, or all of them. */
  approvals: (status: 'pending' | 'all') => request<Approval[]>('GET', `/approvals?status=${status}`),
  /** Approving takes the admin password again; a wrong or missing one is a 403 reauth_failed. */
  approveApproval: (id: string, password: string) =>
    request<undefined>('POST', `/approvals/${encodeURIComponent(id)}/approve`, { password }),
  denyApproval: (id: string) => request<undefined>('POST', `/approvals/${encodeURIComponent(id)}/deny`),
  /** The approval an approval link is for; needs no session, and does not use the link. */
  approvalLink: (token: string) => request<Approval>('POST', '/approval-link', { token }),
  /** Denies through an approval link, which this spends. A link cannot approve. */
  denyApprovalLink: (token: string) => request<undefined>('POST', '/approval-link/deny', { token }),
  runbooks: () => request<RunbookList>('GET', '/runbooks'),
  /** What a run would do. Nothing is executed. */
  runbookPlan: (id: string) => request<RunbookPlan>('GET', `/runbooks/${encodeURIComponent(id)}/plan`),
  startRunbook: (id: string) => request<RunbookRun>('POST', `/runbooks/${encodeURIComponent(id)}/runs`),
  runbookRuns: () => request<{ runs: RunbookRun[] }>('GET', '/runbook-runs').then((r) => r.runs),
  runbookRun: (id: string) => request<RunbookRun>('GET', `/runbook-runs/${encodeURIComponent(id)}`),
  answerRunbookPrompt: (id: string, step: string, value: string) =>
    request<RunbookRun>('POST', `/runbook-runs/${encodeURIComponent(id)}/answer`, { step, value }),
  retryRunbookRun: (id: string, version: number) =>
    request<RunbookRun>('POST', `/runbook-runs/${encodeURIComponent(id)}/retry`, { version }),
  rollbackRunbookRun: (id: string, version: number) =>
    request<RunbookRun>('POST', `/runbook-runs/${encodeURIComponent(id)}/rollback`, { version }),
  passOverRunbookStep: (id: string, step: string, version: number) =>
    request<RunbookRun>('POST', `/runbook-runs/${encodeURIComponent(id)}/pass-over`, { step, version }),
  telemetry: () => request<TelemetrySetting>('GET', '/telemetry'),
  /** Stores the admin's answer: yes sends anonymous usage stats weekly, no sends nothing. */
  setTelemetry: (enabled: boolean) => request<TelemetrySetting>('PUT', '/telemetry', { enabled }),
  panels: async () => (await request<{ panels: Panel[] }>('GET', '/panels')).panels,
  createPanel: (p: PanelInput) => request<Panel>('POST', '/panels', p),
  updatePanel: (id: string, p: PanelInput) => request<Panel>('PUT', `/panels/${encodeURIComponent(id)}`, p),
  deletePanel: (id: string) => request<undefined>('DELETE', `/panels/${encodeURIComponent(id)}`),
  /** expiresIn is a duration such as "24h"; empty for a link that never expires. */
  createPanelLink: (id: string, expiresIn: string) =>
    request<CreatedPanelLink>('POST', `/panels/${encodeURIComponent(id)}/links`, expiresIn ? { expires_in: expiresIn } : {}),
  revokePanelLink: (id: string, link: string) =>
    request<undefined>('DELETE', `/panels/${encodeURIComponent(id)}/links/${encodeURIComponent(link)}`),
  dashboardTokens: async () => (await request<{ tokens: DashboardToken[] }>('GET', '/dashboard/tokens')).tokens,
  /** expiresIn is a duration such as "720h"; empty for a token that never expires. */
  createDashboardToken: (name: string, expiresIn: string) =>
    request<CreatedDashboardToken>('POST', '/dashboard/tokens', expiresIn ? { name, expires_in: expiresIn } : { name }),
  revokeDashboardToken: (id: string) => request<undefined>('DELETE', `/dashboard/tokens/${encodeURIComponent(id)}`),
  /** A panel through its share link; needs no session. */
  guestPanel: (token: string) => request<GuestPanel>('GET', `/guest/${encodeURIComponent(token)}`),
  guestAction: (token: string, widget: string, action: string) =>
    request<{ ok: boolean }>('POST', `/guest/${encodeURIComponent(token)}/actions`, { widget, action }),
};

/**
 * Subscribes to a share link's change notices: onChange runs whenever an
 * entity on the panel changes. Returns a closer.
 */
export function subscribeGuestEvents(token: string, h: { onOpen: () => void; onChange: () => void; onError: () => void }): () => void {
  const es = new EventSource(`${base}/guest/${encodeURIComponent(token)}/events`);
  es.onopen = () => {
    h.onOpen();
  };
  es.onerror = () => {
    es.close();
    h.onError();
  };
  es.addEventListener('changed', () => {
    h.onChange();
  });
  return () => {
    es.close();
  };
}

export interface EventHandlers {
  onOpen: () => void;
  onEvent: (ev: DeviceEvent) => void;
  /** A Kubernetes cluster's state changed, or it was added or removed. */
  onKubeCluster: (c: KubeCluster) => void;
  onKubeChange: (c: KubeChange) => void;
  /** Network discovery found a new host, or one came back. */
  onNetworkHost: () => void;
  /** A network scan asked for from the UI or CLI ended. */
  onNetworkScanDone: (done: NetworkScanDone) => void;
  /** The stream broke; the caller decides when to reconnect. */
  onError: () => void;
}

const eventTypes: DeviceEventType[] = ['device.online', 'device.offline', 'device.updated'];

/** Subscribes to the hub's server-sent device events. Returns a closer. */
export function subscribeEvents(h: EventHandlers): () => void {
  const es = new EventSource(`${base}/events`);
  const onMessage = (msg: MessageEvent<string>) => {
    try {
      h.onEvent(JSON.parse(msg.data) as DeviceEvent);
    } catch {
      // A malformed event is skipped; the next refetch repairs the cache.
    }
  };
  es.onopen = () => {
    h.onOpen();
  };
  es.onerror = () => {
    es.close();
    h.onError();
  };
  for (const t of eventTypes) {
    es.addEventListener(t, onMessage);
  }
  es.addEventListener('kube.cluster', (msg: MessageEvent<string>) => {
    try {
      h.onKubeCluster(JSON.parse(msg.data) as KubeCluster);
    } catch {
      // As above.
    }
  });
  for (const t of ['network.device.new', 'network.device.returned']) {
    es.addEventListener(t, () => {
      h.onNetworkHost();
    });
  }
  es.addEventListener('network.scan.done', (msg: MessageEvent<string>) => {
    try {
      h.onNetworkScanDone(JSON.parse(msg.data) as NetworkScanDone);
    } catch {
      // As above.
    }
  });
  es.addEventListener('kube.object', (msg: MessageEvent<string>) => {
    try {
      h.onKubeChange(JSON.parse(msg.data) as KubeChange);
    } catch {
      // As above.
    }
  });
  return () => {
    es.close();
  };
}

/** One line of a log stream. */
export interface LogLine {
  /** When it was written (RFC 3339), or null if the source does not say. */
  ts: string | null;
  text: string;
}

export interface LogStreamHandlers {
  /** New lines; skipped counts lines dropped before them because the reader was slow. */
  onLines: (lines: LogLine[], skipped: number) => void;
  /** The stream ended: refused, failed, or the source ended (no error). */
  onEnd: (error?: string) => void;
}

/**
 * Streams a device's log source (manager:name, such as systemd:nginx.service):
 * its last tail lines, then new ones. Returns a closer; closing ends the
 * stream on the device too. It does not reconnect: every stream opened is a
 * policy decision and an audit entry.
 */
export function streamDeviceLogs(device: string, source: string, tail: number, h: LogStreamHandlers): () => void {
  const ctl = new AbortController();
  const q = new URLSearchParams({ source, tail: String(tail) });
  const run = async () => {
    const res = await fetch(`${base}/devices/${encodeURIComponent(device)}/logs?${q.toString()}`, {
      credentials: 'same-origin',
      headers: { Accept: 'text/event-stream' },
      signal: ctl.signal,
    });
    if (!res.ok || !res.body) {
      const err = ((await res.json().catch(() => null)) ?? {}) as Partial<{ error: string }>;
      h.onEnd(err.error ?? `request failed with status ${String(res.status)}`);
      return;
    }
    const reader = res.body.pipeThrough(new TextDecoderStream()).getReader();
    let buf = '';
    for (;;) {
      const { done, value } = await reader.read();
      if (done) {
        h.onEnd('the hub closed the stream');
        return;
      }
      buf += value;
      let i;
      while ((i = buf.indexOf('\n\n')) >= 0) {
        const block = buf.slice(0, i);
        buf = buf.slice(i + 2);
        let event = '';
        let data = '';
        for (const line of block.split('\n')) {
          if (line.startsWith('event: ')) {
            event = line.slice(7);
          } else if (line.startsWith('data: ')) {
            data += line.slice(6);
          }
        }
        if (event === 'lines') {
          const m = JSON.parse(data) as { lines: LogLine[]; skipped?: number };
          h.onLines(m.lines, m.skipped ?? 0);
        } else if (event === 'end') {
          const m = JSON.parse(data) as { error?: string };
          ctl.abort();
          h.onEnd(m.error);
          return;
        }
      }
    }
  };
  run().catch((err: unknown) => {
    if (!ctl.signal.aborted) {
      h.onEnd(err instanceof Error ? err.message : String(err));
    }
  });
  return () => {
    ctl.abort();
  };
}
