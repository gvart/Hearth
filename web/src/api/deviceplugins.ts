// Typed client and hooks for device plugins: the registry of uploaded plugins
// (/api/v1/device-plugins) and a device's own (/api/v1/devices/{id}/plugins).
// Uploading a plugin binary is dangerous: it asks for the password again (reauth.ts).

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { ApiError, request } from './client.ts';
import type { PluginCommand, PluginCommandSpec, PolicyClass, PolicyDecision } from './plugins.ts';
import { useWithReauth } from './reauth.ts';

export interface DevicePlugin {
  id: string;
  name: string;
  os: string;
  arch: string;
  version: string;
  sha256: string;
  size: number;
  capabilities: string[];
  commands: PluginCommandSpec[];
  uploaded_at: string;
  uploaded_by: string;
}

export interface DevicePluginList {
  plugins: DevicePlugin[];
  /** The largest program the hub takes, in bytes. */
  max_size: number;
}

export const uploadOSes = ['linux', 'darwin', 'windows', 'freebsd'] as const;
export const uploadArches = ['amd64', 'arm64', 'arm', '386', 'riscv64'] as const;

export interface PluginUpload {
  manifest: File;
  program: File;
  os: string;
  arch: string;
}

/** What a device holds of one plugin: whether it is installed, and the commands it may run. */
export interface DevicePluginState {
  name: string;
  max_class: PolicyClass;
  version?: string;
  sha256?: string;
  installed: boolean;
  error?: string;
  commands: (PluginCommandSpec & { allowed: boolean })[];
}

export interface DevicePlugins {
  /** False for an agent too old to run plugins. */
  supported: boolean;
  connected: boolean;
  os?: string;
  arch?: string;
  plugins: DevicePluginState[];
  decisions: Record<PolicyClass, PolicyDecision>;
}

const registryKey = ['device-plugins'] as const;
const deviceKey = (id: string) => ['devices', id, 'plugins'] as const;

/** The program sent as multipart: the manifest first, then the program, as the hub reads them in order. */
async function upload(u: PluginUpload): Promise<DevicePlugin> {
  const form = new FormData();
  form.append('manifest', u.manifest);
  form.append('program', u.program);
  const res = await fetch(`/api/v1/device-plugins?os=${encodeURIComponent(u.os)}&arch=${encodeURIComponent(u.arch)}`, {
    method: 'POST',
    credentials: 'same-origin',
    headers: { Accept: 'application/json' },
    body: form,
  });
  const data: unknown = await res.json().catch(() => null);
  if (!res.ok) {
    const err = (data ?? {}) as Partial<{ error: string; code: string }>;
    throw new ApiError(res.status, err.code ?? 'unknown', err.error ?? `request failed with status ${String(res.status)}`, data);
  }
  return data as DevicePlugin;
}

/** The uploaded device plugins. */
export function useDevicePluginRegistry() {
  return useQuery({ queryKey: registryKey, queryFn: () => request<DevicePluginList>('GET', '/device-plugins') });
}

export function useUploadDevicePlugin() {
  const qc = useQueryClient();
  const withReauth = useWithReauth();
  return useMutation({
    mutationFn: (u: PluginUpload) => withReauth(() => upload(u)),
    onSettled: () => {
      void qc.invalidateQueries({ queryKey: registryKey });
    },
  });
}

export function useDeleteDevicePlugin() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => request<undefined>('DELETE', `/device-plugins/${encodeURIComponent(id)}`),
    onSettled: () => {
      void qc.invalidateQueries({ queryKey: registryKey });
    },
  });
}

/** The plugins a device holds and may run; polled while its agent installs one. */
export function useDevicePlugins(id: string) {
  return useQuery({
    queryKey: deviceKey(id),
    queryFn: () => request<DevicePlugins>('GET', `/devices/${encodeURIComponent(id)}/plugins`),
    refetchInterval: (q) => (q.state.data?.plugins.some((p) => !p.installed && !p.error) ? 3000 : 15000),
  });
}

/** Runs a command of a plugin on the device, through policy. */
export function useDevicePluginCommand(id: string, plugin: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (cmd: PluginCommand) =>
      request<{ output: string }>(
        'POST',
        `/devices/${encodeURIComponent(id)}/plugins/${encodeURIComponent(plugin)}/commands`,
        cmd,
      ),
    onSettled: () => {
      void qc.invalidateQueries({ queryKey: deviceKey(id) });
    },
  });
}
