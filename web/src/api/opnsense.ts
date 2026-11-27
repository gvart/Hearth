// Typed client and hooks for adopted OPNsense firewalls (/api/v1/opnsense).

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { request } from './client.ts';
import { useWithReauth } from './reauth.ts';

export type OPNsenseState = 'connecting' | 'connected' | 'unavailable';

export interface OPNsenseFirewall {
  id: string;
  name: string;
  /** The firewall's web GUI: the hub calls /api on it. */
  url: string;
  /** How its certificate is verified: system roots or a pinned fingerprint. */
  tls: 'system' | 'fingerprint';
  state: OPNsenseState;
  error: string;
  created_at: string;
  hostname: string;
  /** Such as "OPNsense 25.7.4-amd64". */
  version: string;
  clients: number;
}

export interface OPNsenseSystem {
  hostname: string;
  versions: string[] | null;
  /** As the firewall formats it: "12 days, 03:04:05". */
  uptime: string;
  /** "0.24, 0.31, 0.29". */
  load: string;
  mem_total: number;
  mem_used: number;
}

export interface OPNsenseFirmware {
  product: string;
  version: string;
  latest: string;
  /** none, update, upgrade or error; empty when not read. */
  status: string;
  message: string;
}

export interface OPNsenseInterface {
  name: string;
  description: string;
  device: string;
  rx_bytes: number;
  tx_bytes: number;
  rx_packets: number;
  tx_packets: number;
  rx_errors: number;
  tx_errors: number;
}

export interface OPNsenseClient {
  mac: string;
  ip: string;
  ipv6: string[];
  hostname: string;
  vendor: string;
  interface: string;
  lease: boolean;
  /** isc, kea or dnsmasq. */
  lease_source: string;
  static: boolean;
  /** When the lease ends, Unix seconds; 0 when the server does not say. */
  lease_ends: number;
  /** In the ARP table right now. */
  arp: boolean;
}

export interface OPNsenseSnapshot {
  firewall: OPNsenseFirewall;
  system: OPNsenseSystem;
  firmware: OPNsenseFirmware;
  interfaces: OPNsenseInterface[];
  clients: OPNsenseClient[];
  /** What the last read could not get, and why. */
  missing: string[];
  /** The policy class of restarting Unbound. */
  restart_class: string;
}

export interface AddOPNsenseFirewall {
  name: string;
  url: string;
  key: string;
  secret: string;
  fingerprint: string;
}

export interface OPNsenseActionResult {
  action: string;
  class: string;
  target: string;
  result: string;
}

const opnsenseApi = {
  firewalls: async () => (await request<{ firewalls: OPNsenseFirewall[] }>('GET', '/opnsense/firewalls')).firewalls,
  firewall: (id: string) => request<OPNsenseSnapshot>('GET', `/opnsense/firewalls/${encodeURIComponent(id)}`),
  add: (opts: AddOPNsenseFirewall) => request<OPNsenseFirewall>('POST', '/opnsense/firewalls', opts),
  remove: (id: string) => request<undefined>('DELETE', `/opnsense/firewalls/${encodeURIComponent(id)}`),
  restartUnbound: (id: string) =>
    request<OPNsenseActionResult>('POST', `/opnsense/firewalls/${encodeURIComponent(id)}/restart-unbound`),
};

const keys = {
  all: ['opnsense'] as const,
  firewalls: ['opnsense', 'firewalls'] as const,
  firewall: (id: string) => ['opnsense', 'firewall', id] as const,
};

const refreshMs = 5000;

export function useOPNsenseFirewalls(enabled = true) {
  return useQuery({ queryKey: keys.firewalls, queryFn: opnsenseApi.firewalls, refetchInterval: refreshMs, enabled });
}

export function useOPNsenseFirewall(id: string) {
  return useQuery({ queryKey: keys.firewall(id), queryFn: () => opnsenseApi.firewall(id), refetchInterval: refreshMs });
}

export function useAddOPNsenseFirewall() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: opnsenseApi.add,
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: keys.all });
    },
  });
}

export function useRemoveOPNsenseFirewall() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: opnsenseApi.remove,
    onSuccess: (_, id) => {
      qc.removeQueries({ queryKey: keys.firewall(id) });
      void qc.invalidateQueries({ queryKey: keys.firewalls });
    },
  });
}

/** Restarts Unbound: dangerous, so it asks for the admin password first (reauth.ts). */
export function useRestartOPNsenseUnbound(id: string) {
  const qc = useQueryClient();
  const withReauth = useWithReauth();
  return useMutation({
    mutationFn: () => withReauth(() => opnsenseApi.restartUnbound(id)),
    onSettled: () => {
      void qc.invalidateQueries({ queryKey: keys.firewall(id) });
    },
  });
}
