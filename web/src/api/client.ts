// Typed client for the hub's JSON API (/api/v1). Every network call the UI
// makes lives in this directory.

export type DeviceStatus = 'unknown' | 'online' | 'offline';

export interface Disk {
  device: string;
  mountpoint: string;
  fstype: string;
  total_bytes: number;
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
}

export interface CreatedToken {
  token: string;
  expires_at: string;
  install_command: string;
  join_command: string;
}

/** One per-hub configuration item compared across the cluster's hubs. */
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
  /** What the operator marked it: known and ignored hosts fire no new-device alerts. */
  state: NetworkHostState;
}

export type NetworkHostState = '' | 'known' | 'ignored';

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

export interface BeszelSystems {
  /** standby: a hub of a cluster that does not lead it; only the leader reads Beszel. */
  status: 'not_configured' | 'connecting' | 'ok' | 'unavailable' | 'standby';
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

/** ApiError carries the hub's `{"error","code"}` body and the HTTP status. */
export class ApiError extends Error {
  readonly status: number;
  readonly code: string;

  constructor(status: number, code: string, message: string) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
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
    throw new ApiError(res.status, err.code ?? 'unknown', err.error ?? `request failed with status ${String(res.status)}`);
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
  deviceMetrics: (id: string, range: MetricsRange = '1h') =>
    request<DeviceMetrics>('GET', `/devices/${encodeURIComponent(id)}/metrics?range=${encodeURIComponent(range)}`),
  metricsSparklines: () => request<MetricsSparklines>('GET', '/metrics/sparklines'),
  tlsInfo: () => request<TlsInfo>('GET', '/tls'),
  configDrift: () => request<ConfigDrift>('GET', '/cluster/config-drift'),
  createToken: (opts: { ttl?: string; labels?: Record<string, string> } = {}) =>
    request<CreatedToken>('POST', '/tokens', opts),
  audit: (filter: AuditFilter, before?: number) => {
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
  /** Marks a host known or ignored, or neither again (''). */
  markNetworkHost: (mac: string, state: NetworkHostState) =>
    request<undefined>(
      'POST',
      `/network/hosts/${encodeURIComponent(mac)}/${state === 'known' ? 'known' : state === 'ignored' ? 'ignore' : 'unmark'}`,
    ),
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
};

export interface EventHandlers {
  onOpen: () => void;
  onEvent: (ev: DeviceEvent) => void;
  /** A Kubernetes cluster's state changed, or it was added or removed. */
  onKubeCluster: (c: KubeCluster) => void;
  onKubeChange: (c: KubeChange) => void;
  /** Network discovery found a new host, or one came back. */
  onNetworkHost: () => void;
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
