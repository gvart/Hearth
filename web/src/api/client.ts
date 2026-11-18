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
export type MetricsStatus = 'ok' | 'not_configured' | 'unreachable' | 'no_target';

export interface MetricChart {
  key: string;
  name: string;
  unit: string;
  /** [unix milliseconds, value] pairs. */
  points: [number, number][];
}

/** A device's chart series, read from Prometheus; see GET /api/v1/devices/{id}/metrics. */
export interface DeviceMetrics {
  source: string;
  status: MetricsStatus;
  message?: string;
  /** The Prometheus `instance` label the device mapped to. */
  instance?: string;
  /** The charted range in unix milliseconds; set when status is ok. */
  start?: number;
  end?: number;
  charts: MetricChart[];
}

export type DeviceEventType = 'device.online' | 'device.offline' | 'device.updated';

export interface DeviceEvent {
  type: DeviceEventType;
  device: Device;
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

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
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
  deviceMetrics: (id: string, range = '1h') =>
    request<DeviceMetrics>('GET', `/devices/${encodeURIComponent(id)}/metrics?range=${encodeURIComponent(range)}`),
  tlsInfo: () => request<TlsInfo>('GET', '/tls'),
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
  notifyChannels: async () => (await request<{ channels: NotifyChannel[] }>('GET', '/notify/channels')).channels,
  testNotifyChannel: (name: string) =>
    request<undefined>('POST', `/notify/channels/${encodeURIComponent(name)}/test`),
};

export interface EventHandlers {
  onOpen: () => void;
  onEvent: (ev: DeviceEvent) => void;
  /** A Kubernetes cluster's state changed, or it was added or removed. */
  onKubeCluster: (c: KubeCluster) => void;
  onKubeChange: (c: KubeChange) => void;
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
