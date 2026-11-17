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

export type DeviceEventType = 'device.online' | 'device.offline' | 'device.updated';

export interface DeviceEvent {
  type: DeviceEventType;
  device: Device;
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
  tlsInfo: () => request<TlsInfo>('GET', '/tls'),
  createToken: (opts: { ttl?: string; labels?: Record<string, string> } = {}) =>
    request<CreatedToken>('POST', '/tokens', opts),
};

export interface EventHandlers {
  onOpen: () => void;
  onEvent: (ev: DeviceEvent) => void;
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
  return () => {
    es.close();
  };
}
