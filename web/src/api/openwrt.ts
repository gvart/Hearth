// Typed client and hooks for adopted OpenWrt routers (/api/v1/openwrt).

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { request } from './client.ts';
import { useWithReauth } from './reauth.ts';

export type OpenWrtState = 'connecting' | 'connected' | 'unavailable';

export interface OpenWrtRouter {
  id: string;
  name: string;
  /** The router's web server: the hub calls /ubus on it. */
  url: string;
  username: string;
  /** none (plain http), system or fingerprint. */
  tls: 'none' | 'system' | 'fingerprint';
  state: OpenWrtState;
  error: string;
  created_at: string;
  hostname: string;
  model: string;
  release: string;
  clients: number;
}

export interface OpenWrtSystem {
  hostname: string;
  model: string;
  board_name: string;
  kernel: string;
  release: string;
  target: string;
  uptime: number;
  load: [number, number, number];
  mem_total: number;
  mem_available: number;
}

export interface OpenWrtInterface {
  name: string;
  type: string;
  up: boolean;
  carrier: boolean;
  mac: string;
  rx_bytes: number;
  tx_bytes: number;
  rx_packets: number;
  tx_packets: number;
  rx_errors: number;
  tx_errors: number;
}

export interface OpenWrtClient {
  mac: string;
  ip: string;
  hostname: string;
  lease: boolean;
  /** Seconds the lease has left; 0 for a static lease. */
  lease_expires: number;
  wireless: boolean;
  radio?: string;
  /** dBm. */
  signal?: number;
  /** Milliseconds since the radio last heard it. */
  inactive?: number;
}

export interface OpenWrtSnapshot {
  router: OpenWrtRouter;
  system: OpenWrtSystem;
  interfaces: OpenWrtInterface[];
  clients: OpenWrtClient[];
  /** What the last read could not get, and why. */
  missing: string[];
  /** The policy class of restarting dnsmasq. */
  restart_class: string;
}

export interface AddOpenWrtRouter {
  name: string;
  url: string;
  username: string;
  password: string;
  fingerprint: string;
}

export interface OpenWrtActionResult {
  action: string;
  class: string;
  target: string;
  result: string;
}

const openwrtApi = {
  routers: async () => (await request<{ routers: OpenWrtRouter[] }>('GET', '/openwrt/routers')).routers,
  router: (id: string) => request<OpenWrtSnapshot>('GET', `/openwrt/routers/${encodeURIComponent(id)}`),
  add: (opts: AddOpenWrtRouter) => request<OpenWrtRouter>('POST', '/openwrt/routers', opts),
  remove: (id: string) => request<undefined>('DELETE', `/openwrt/routers/${encodeURIComponent(id)}`),
  restartDNS: (id: string) =>
    request<OpenWrtActionResult>('POST', `/openwrt/routers/${encodeURIComponent(id)}/restart-dnsmasq`),
};

const keys = {
  all: ['openwrt'] as const,
  routers: ['openwrt', 'routers'] as const,
  router: (id: string) => ['openwrt', 'router', id] as const,
};

const refreshMs = 5000;

export function useOpenWrtRouters(enabled = true) {
  return useQuery({ queryKey: keys.routers, queryFn: openwrtApi.routers, refetchInterval: refreshMs, enabled });
}

export function useOpenWrtRouter(id: string) {
  return useQuery({ queryKey: keys.router(id), queryFn: () => openwrtApi.router(id), refetchInterval: refreshMs });
}

export function useAddOpenWrtRouter() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: openwrtApi.add,
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: keys.all });
    },
  });
}

export function useRemoveOpenWrtRouter() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: openwrtApi.remove,
    onSuccess: (_, id) => {
      qc.removeQueries({ queryKey: keys.router(id) });
      void qc.invalidateQueries({ queryKey: keys.routers });
    },
  });
}

/** Restarts dnsmasq: dangerous, so it asks for the admin password first (reauth.ts). */
export function useRestartOpenWrtDNS(id: string) {
  const qc = useQueryClient();
  const withReauth = useWithReauth();
  return useMutation({
    mutationFn: () => withReauth(() => openwrtApi.restartDNS(id)),
    onSettled: () => {
      void qc.invalidateQueries({ queryKey: keys.router(id) });
    },
  });
}
