// Typed client and hooks for adopted Proxmox VE servers (/api/v1/proxmox).

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { request } from './client.ts';

export type ProxmoxState = 'connecting' | 'connected' | 'unavailable';

export interface ProxmoxServer {
  id: string;
  name: string;
  url: string;
  /** How the server's certificate is verified. */
  tls: 'system' | 'ca' | 'fingerprint';
  state: ProxmoxState;
  error: string;
  created_at: string;
  nodes: number;
  guests: number;
}

export interface ProxmoxNode {
  name: string;
  /** online, offline or unknown. */
  status: string;
  cpu: number;
  max_cpu: number;
  mem: number;
  max_mem: number;
  disk: number;
  max_disk: number;
  uptime: number;
}

export interface ProxmoxGuest {
  vmid: number;
  kind: 'qemu' | 'lxc';
  name: string;
  node: string;
  /** running, stopped, paused or unknown. */
  status: string;
  cpu: number;
  max_cpu: number;
  mem: number;
  max_mem: number;
  uptime: number;
}

export interface ProxmoxStorage {
  name: string;
  node: string;
  /** The storage plugin: dir, lvmthin, nfs, zfspool, ... */
  type: string;
  status: string;
  content: string;
  shared: boolean;
  used: number;
  total: number;
}

export type ProxmoxActionName = 'start' | 'stop' | 'reboot';

export interface ProxmoxSnapshot {
  server: ProxmoxServer;
  nodes: ProxmoxNode[];
  guests: ProxmoxGuest[];
  storage: ProxmoxStorage[];
  /** The policy class of each guest action. */
  action_classes: Record<ProxmoxActionName, string>;
}

export interface AddProxmoxServer {
  name: string;
  url: string;
  token: string;
  ca_pem: string;
  fingerprint: string;
}

export interface ProxmoxActionResult {
  action: ProxmoxActionName;
  class: string;
  target: string;
  result: string;
  task: string;
}

const proxmoxApi = {
  servers: async () => (await request<{ servers: ProxmoxServer[] }>('GET', '/proxmox/servers')).servers,
  server: (id: string) => request<ProxmoxSnapshot>('GET', `/proxmox/servers/${encodeURIComponent(id)}`),
  add: (opts: AddProxmoxServer) => request<ProxmoxServer>('POST', '/proxmox/servers', opts),
  remove: (id: string) => request<undefined>('DELETE', `/proxmox/servers/${encodeURIComponent(id)}`),
  act: (server: string, action: ProxmoxActionName, vmid: number) =>
    request<ProxmoxActionResult>('POST', `/proxmox/servers/${encodeURIComponent(server)}/actions`, { action, vmid }),
};

const keys = {
  all: ['proxmox'] as const,
  servers: ['proxmox', 'servers'] as const,
  server: (id: string) => ['proxmox', 'server', id] as const,
};

/** The hub reads each server every 15 s; this keeps the page close behind it. */
const refreshMs = 5000;

export function useProxmoxServers(enabled = true) {
  return useQuery({ queryKey: keys.servers, queryFn: proxmoxApi.servers, refetchInterval: refreshMs, enabled });
}

export function useProxmoxServer(id: string) {
  return useQuery({ queryKey: keys.server(id), queryFn: () => proxmoxApi.server(id), refetchInterval: refreshMs });
}

export function useAddProxmoxServer() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: proxmoxApi.add,
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: keys.all });
    },
  });
}

export function useRemoveProxmoxServer() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: proxmoxApi.remove,
    onSuccess: (_, id) => {
      qc.removeQueries({ queryKey: keys.server(id) });
      void qc.invalidateQueries({ queryKey: keys.servers });
    },
  });
}

/** Asks for a guest action. It answers once policy decided and Proxmox accepted it. */
export function useProxmoxAction(server: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (req: { action: ProxmoxActionName; vmid: number }) => proxmoxApi.act(server, req.action, req.vmid),
    onSettled: () => {
      void qc.invalidateQueries({ queryKey: keys.server(server) });
    },
  });
}
