// Typed client and hooks for the plugin registry (/api/v1/plugin-registry):
// the WASM plugins a signed index offers and those installed on this hub.
// Installing and updating are dangerous: they ask for the password again (reauth.ts).

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { request } from './client.ts';
import type { PluginCommandSpec, PolicyDecision } from './plugins.ts';
import { useWithReauth } from './reauth.ts';

/** A plugin as the index offers it, or as installed. */
export interface RegistryEntry {
  name: string;
  version: string;
  description?: string;
  author?: string;
  homepage?: string;
  license?: string;
  runtime: string;
  sha256: string;
  /** Names the whole entry, grants included: an install or update confirms it. */
  digest: string;
  /** Its memory cap, in MiB. */
  memory: number;
  capabilities: string[];
  commands: PluginCommandSpec[];
  /** The hosts it may reach over HTTP: its only access outside its sandbox. */
  http_allow: string[];
}

export interface InstalledPlugin extends RegistryEntry {
  source: string;
  installed_at: string;
  installed_by: string;
  /** A newer version the index offers; never an older one. */
  update?: RegistryEntry;
  /** Why the hub does not run it. */
  error?: string;
}

export interface PluginRegistry {
  /** False without a configured index; installed plugins are still listed. */
  enabled: boolean;
  source?: string;
  /** The ids of the trusted index keys. */
  keys: string[];
  installed: InstalledPlugin[];
  /** The newest version of each plugin the index offers. */
  available: RegistryEntry[];
  /** Why the index could not be read or trusted. */
  index_error?: string;
  decisions: Record<'install' | 'update' | 'remove', PolicyDecision>;
}

/** What the caller reviewed: the hub refuses if the signed index now says otherwise. */
export interface RegistryChange {
  name: string;
  version: string;
  sha256: string;
  digest: string;
  allow_downgrade?: boolean;
}

const key = ['plugin-registry'] as const;

export function usePluginRegistry() {
  return useQuery({ queryKey: key, queryFn: () => request<PluginRegistry>('GET', '/plugin-registry'), retry: false });
}

function useChange(path: 'install' | 'update') {
  const qc = useQueryClient();
  const withReauth = useWithReauth();
  return useMutation({
    mutationFn: (c: RegistryChange) => withReauth(() => request<RegistryEntry>('POST', `/plugin-registry/${path}`, c)),
    onSettled: () => {
      void qc.invalidateQueries({ queryKey: key });
      void qc.invalidateQueries({ queryKey: ['plugins'] });
    },
  });
}

export const useInstallRegistryPlugin = () => useChange('install');
export const useUpdateRegistryPlugin = () => useChange('update');

export function useRemoveRegistryPlugin() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (name: string) => request<undefined>('DELETE', `/plugin-registry/${encodeURIComponent(name)}`),
    onSettled: () => {
      void qc.invalidateQueries({ queryKey: key });
      void qc.invalidateQueries({ queryKey: ['plugins'] });
    },
  });
}
