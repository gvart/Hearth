// Typed client and hooks for the hub's exec plugins (/api/v1/plugins).

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { ApiError, request } from './client.ts';

export type PolicyClass = 'read' | 'safe' | 'dangerous';

/** What policy decides now for a command of a class: it runs, is held for approval, or is refused. */
export type PolicyDecision = 'allow' | 'confirm' | 'deny';

export interface PluginCommandSpec {
  name: string;
  /** The class the plugin's manifest declares: the hub decides on it, never the caller. */
  class: PolicyClass;
  description?: string;
}

export interface PluginEntity {
  id: string;
  name: string;
  kind?: string;
  unit?: string;
  /** The entity's last state: any JSON value, null if none yet. */
  state: unknown;
}

export interface PluginDevice {
  id: string;
  name: string;
  kind?: string;
  entities: PluginEntity[];
}

export type PluginState = 'starting' | 'running' | 'restarting' | 'stopped';

export interface Plugin {
  name: string;
  version: string;
  state: PluginState;
  error?: string;
  restarts: number;
  started_at: string | null;
  capabilities: string[];
  commands: PluginCommandSpec[];
  devices: PluginDevice[];
  stderr: string[];
}

export interface Plugins {
  plugins: Plugin[];
  /** What policy decides now for this session's commands, by class. */
  decisions: Record<PolicyClass, PolicyDecision>;
}

export interface PluginCommand {
  command: string;
  device?: string;
  args?: Record<string, unknown>;
}

const pluginsApi = {
  /** The hub's plugins, or null when it runs none (the API is not served then). */
  list: async (): Promise<Plugins | null> => {
    try {
      return await request<Plugins>('GET', '/plugins');
    } catch (err) {
      if (err instanceof ApiError && err.status === 404) {
        return null;
      }
      throw err;
    }
  },
  command: (plugin: string, cmd: PluginCommand) =>
    request<{ output: string }>('POST', `/plugins/${encodeURIComponent(plugin)}/commands`, cmd),
};

const key = ['plugins'] as const;

/** Plugins push state as it changes; this keeps the page close behind it. */
const refreshMs = 5000;

export function usePlugins() {
  return useQuery({ queryKey: key, queryFn: pluginsApi.list, refetchInterval: refreshMs });
}

/** Runs a plugin command. It answers once policy decided (and, if held, an operator approved) and the plugin answered. */
export function usePluginCommand(plugin: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (cmd: PluginCommand) => pluginsApi.command(plugin, cmd),
    onSettled: () => {
      void qc.invalidateQueries({ queryKey: key });
    },
  });
}
