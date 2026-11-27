// Typed client and hooks for adopted UniFi Network controllers (/api/v1/unifi).

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { request } from './client.ts';
import { useWithReauth } from './reauth.ts';

export type UniFiState = 'connecting' | 'connected' | 'unavailable';
export type UniFiKind = 'unifi_os' | 'classic';

export interface UniFiController {
  id: string;
  name: string;
  /** https://host:port */
  url: string;
  kind: UniFiKind;
  /** The site's short name, such as default. */
  site: string;
  auth: 'api_key' | 'password';
  /** The local login's, when auth is password. */
  username: string;
  /** system or fingerprint (a pinned, often self-signed, certificate). */
  tls: 'system' | 'fingerprint';
  state: UniFiState;
  error: string;
  created_at: string;
  devices: number;
  clients: number;
}

export interface UniFiDevice {
  mac: string;
  ip: string;
  name: string;
  model: string;
  kind: 'gateway' | 'switch' | 'access_point' | 'other';
  type: string;
  version: string;
  state: string;
  /** Seconds. */
  uptime: number;
  clients: number;
}

export interface UniFiClient {
  mac: string;
  ip: string;
  hostname: string;
  vendor?: string;
  wired: boolean;
  /** The access point or switch it is connected to. */
  uplink: string;
  uplink_mac: string;
  /** A wired client's switch port. */
  port?: number;
  ssid?: string;
  /** dBm. */
  signal?: number;
  /** Unix seconds. */
  last_seen: number;
}

export interface UniFiHealth {
  subsystem: string;
  status: string;
  wan_ip?: string;
  isp?: string;
  latency_ms?: number;
  /** Bytes per second. */
  rx_rate?: number;
  tx_rate?: number;
  users?: number;
}

export interface UniFiSnapshot {
  controller: UniFiController;
  devices: UniFiDevice[];
  clients: UniFiClient[];
  health: UniFiHealth[];
  /** What the last read could not get, and why. */
  missing: string[];
  /** The policy class of restarting an access point. */
  restart_class: string;
}

export interface AddUniFiController {
  name: string;
  url: string;
  kind: UniFiKind;
  site: string;
  api_key: string;
  username: string;
  password: string;
  fingerprint: string;
}

export interface UniFiActionResult {
  action: string;
  class: string;
  target: string;
  result: string;
}

const path = (id: string) => `/unifi/controllers/${encodeURIComponent(id)}`;

const unifiApi = {
  controllers: async () =>
    (await request<{ controllers: UniFiController[] }>('GET', '/unifi/controllers')).controllers,
  controller: (id: string) => request<UniFiSnapshot>('GET', path(id)),
  add: (opts: AddUniFiController) => request<UniFiController>('POST', '/unifi/controllers', opts),
  remove: (id: string) => request<undefined>('DELETE', path(id)),
  restartAP: (id: string, mac: string) =>
    request<UniFiActionResult>('POST', `${path(id)}/devices/${encodeURIComponent(mac)}/restart`),
};

const keys = {
  all: ['unifi'] as const,
  controllers: ['unifi', 'controllers'] as const,
  controller: (id: string) => ['unifi', 'controller', id] as const,
};

const refreshMs = 5000;

export function useUniFiControllers(enabled = true) {
  return useQuery({ queryKey: keys.controllers, queryFn: unifiApi.controllers, refetchInterval: refreshMs, enabled });
}

export function useUniFiController(id: string) {
  return useQuery({ queryKey: keys.controller(id), queryFn: () => unifiApi.controller(id), refetchInterval: refreshMs });
}

export function useAddUniFiController() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: unifiApi.add,
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: keys.all });
    },
  });
}

export function useRemoveUniFiController() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: unifiApi.remove,
    onSuccess: (_, id) => {
      qc.removeQueries({ queryKey: keys.controller(id) });
      void qc.invalidateQueries({ queryKey: keys.controllers });
    },
  });
}

/** Restarts an access point: dangerous, so it asks for the admin password first (reauth.ts). */
export function useRestartUniFiAP(id: string) {
  const qc = useQueryClient();
  const withReauth = useWithReauth();
  return useMutation({
    mutationFn: (mac: string) => withReauth(() => unifiApi.restartAP(id, mac)),
    onSettled: () => {
      void qc.invalidateQueries({ queryKey: keys.controller(id) });
    },
  });
}
