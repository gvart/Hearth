// Typed client and hooks for what the CLI does on a hub host and the web UI
// does behind the admin session: revoking devices, MCP tokens, the admin
// password, the policy and notification channel editors, runbook files,
// automation run history and deletion, and backup downloads. The sensitive
// ones ask for the password again (reauth.ts).

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import type { AutomationProblem } from './automations.ts';
import { ApiError, request, type RunbookPlan } from './client.ts';
import { keys as appKeys } from './hooks.ts';
import { useWithReauth } from './reauth.ts';

export type McpScope = 'read' | 'safe' | 'dangerous';

export interface McpToken {
  name: string;
  scope: McpScope;
  created_at: string;
  revoked_at: string | null;
}

export interface CreatedMcpToken {
  name: string;
  scope: McpScope;
  /** Shown this once: the hub keeps only its hash. */
  secret: string;
  /** The hub's MCP endpoint path. */
  path: string;
}

/** A configuration document as written, with the revision an edit names. */
export interface ConfigDoc {
  file: string;
  yaml: string;
  revision: string;
}

export interface Validation {
  valid: boolean;
  problems: AutomationProblem[];
  plan?: RunbookPlan;
}

export type NotifyType = 'ntfy' | 'telegram';

/** A channel as the editor sees it: which fields are set, never their values. */
export interface NotifyChannelConfig {
  name: string;
  type: NotifyType;
  set: Record<string, boolean | undefined>;
}

export interface NotifyChannelEdit {
  type: NotifyType;
  url?: string;
  topic?: string;
  token?: string;
  bot_token?: string;
  chat_id?: string;
  /** Fields to empty; an empty field otherwise keeps the stored value. */
  clear?: string[];
}

export interface RunbookFile {
  file: string;
  id: string;
}

export interface AutomationStep {
  id: string;
  type: string;
  status: string;
  error?: string;
}

export interface AutomationRun {
  id: string;
  trigger_id: string;
  started_at: string;
  finished_at: string;
  status: string;
  error?: string;
  steps: AutomationStep[];
}

/** The problems of a write refused as invalid (422), or none. */
export function problemsOf(err: unknown): AutomationProblem[] {
  if (err instanceof ApiError && err.code === 'invalid') {
    return (err.body as { problems?: AutomationProblem[] } | null)?.problems ?? [];
  }
  return [];
}


const e = encodeURIComponent;

export const adminApi = {
  revokeDevice: (id: string) => request<{ revoked: number }>('POST', `/devices/${e(id)}/revoke`),
  mcpTokens: async () => (await request<{ tokens: McpToken[] }>('GET', '/mcp/tokens')).tokens,
  createMcpToken: (name: string, scope: McpScope) => request<CreatedMcpToken>('POST', '/mcp/tokens', { name, scope }),
  revokeMcpToken: (name: string) => request<undefined>('DELETE', `/mcp/tokens/${e(name)}`),
  changePassword: (current: string, next: string) =>
    request<undefined>('PUT', '/admin/password', { current_password: current, new_password: next }),
  policy: () => request<ConfigDoc>('GET', '/policy'),
  validatePolicy: (yaml: string) => request<Validation>('POST', '/policy/validate', { yaml }),
  savePolicy: (yaml: string, revision: string) => request<ConfigDoc>('PUT', '/policy', { yaml, revision }),
  notifyConfig: async () => (await request<{ channels: NotifyChannelConfig[] }>('GET', '/notify/config')).channels,
  saveNotifyChannel: (name: string, edit: NotifyChannelEdit) =>
    request<undefined>('PUT', `/notify/channels/${e(name)}`, edit),
  deleteNotifyChannel: (name: string) => request<undefined>('DELETE', `/notify/channels/${e(name)}`),
  runbookFiles: async () => (await request<{ files: RunbookFile[] }>('GET', '/runbook-files')).files,
  runbookFile: (file: string) => request<ConfigDoc>('GET', `/runbook-files/${e(file)}`),
  validateRunbook: (yaml: string, file: string) => request<Validation>('POST', '/runbook-files/validate', { yaml, file }),
  saveRunbook: (file: string, yaml: string, revision: string) =>
    request<ConfigDoc>('PUT', `/runbook-files/${e(file)}`, { yaml, revision }),
  deleteRunbook: (file: string) => request<undefined>('DELETE', `/runbook-files/${e(file)}`),
  automationRuns: async (id: string) =>
    (await request<{ runs: AutomationRun[] }>('GET', `/automations/${e(id)}/runs`)).runs,
  deleteAutomation: (id: string) => request<undefined>('DELETE', `/automations/${e(id)}`),
  /** The encrypted backup archive, as a file to save. */
  backup: async (passphrase: string): Promise<{ blob: Blob; name: string }> => {
    const res = await fetch('/api/v1/backup', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ passphrase }),
    });
    if (!res.ok) {
      const err = ((await res.json().catch(() => null)) ?? {}) as Partial<{ error: string; code: string }>;
      throw new ApiError(res.status, err.code ?? 'unknown', err.error ?? `backup failed with status ${String(res.status)}`);
    }
    const name = /filename="([^"]+)"/.exec(res.headers.get('Content-Disposition') ?? '')?.[1] ?? 'hearth.hbk';
    return { blob: await res.blob(), name };
  },
};

const keys = {
  mcpTokens: ['mcp-tokens'] as const,
  policy: ['policy'] as const,
  notifyConfig: ['notify', 'config'] as const,
  runbookFiles: ['runbooks', 'files'] as const,
  runbookFile: (file: string) => ['runbooks', 'file', file] as const,
  automationRuns: (id: string) => ['automations', 'runs', id] as const,
};

/** Revokes every certificate of a device: dangerous, with the password again. */
export function useRevokeDevice() {
  const withReauth = useWithReauth();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => withReauth(() => adminApi.revokeDevice(id)),
    onSettled: () => qc.invalidateQueries({ queryKey: appKeys.devices }),
  });
}

export function useMcpTokens() {
  return useQuery({ queryKey: keys.mcpTokens, queryFn: adminApi.mcpTokens });
}

export function useCreateMcpToken() {
  const withReauth = useWithReauth();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ name, scope }: { name: string; scope: McpScope }) =>
      withReauth(() => adminApi.createMcpToken(name, scope)),
    onSettled: () => qc.invalidateQueries({ queryKey: keys.mcpTokens }),
  });
}

export function useRevokeMcpToken() {
  const withReauth = useWithReauth();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (name: string) => withReauth(() => adminApi.revokeMcpToken(name)),
    onSettled: () => qc.invalidateQueries({ queryKey: keys.mcpTokens }),
  });
}

/** Changes the admin password; every session ends, this one too. */
export function useChangePassword() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ current, next }: { current: string; next: string }) => adminApi.changePassword(current, next),
    // Every session ended, this one too: back to the login form, with
    // nothing of the old session left in the cache. The session query
    // stays, so the app sees it turn null.
    onSuccess: () => {
      qc.setQueryData(appKeys.session, null);
      qc.removeQueries({ predicate: (q) => q.queryKey[0] !== appKeys.session[0] });
    },
  });
}

/** The policy as stored; anyone signed in reads it. */
export function usePolicy() {
  return useQuery({ queryKey: keys.policy, queryFn: adminApi.policy, refetchOnWindowFocus: false });
}

export function useValidatePolicy() {
  return useMutation({ mutationFn: adminApi.validatePolicy });
}

export function useSavePolicy() {
  const withReauth = useWithReauth();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ yaml, revision }: { yaml: string; revision: string }) =>
      withReauth(() => adminApi.savePolicy(yaml, revision)),
    onSuccess: (doc) => {
      qc.setQueryData(keys.policy, doc);
    },
  });
}

export function useNotifyConfig() {
  return useQuery({ queryKey: keys.notifyConfig, queryFn: adminApi.notifyConfig });
}

/** Every hub applies a channel change within seconds: refetch the lists then. */
function refetchChannelsSoon(qc: ReturnType<typeof useQueryClient>) {
  void qc.invalidateQueries({ queryKey: ['notify'] });
  setTimeout(() => void qc.invalidateQueries({ queryKey: ['notify'] }), 3000);
}

export function useSaveNotifyChannel() {
  const withReauth = useWithReauth();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ name, edit }: { name: string; edit: NotifyChannelEdit }) =>
      withReauth(() => adminApi.saveNotifyChannel(name, edit)),
    onSuccess: () => {
      refetchChannelsSoon(qc);
    },
  });
}

export function useDeleteNotifyChannel() {
  const withReauth = useWithReauth();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (name: string) => withReauth(() => adminApi.deleteNotifyChannel(name)),
    onSuccess: () => {
      refetchChannelsSoon(qc);
    },
  });
}

export function useRunbookFiles() {
  return useQuery({ queryKey: keys.runbookFiles, queryFn: adminApi.runbookFiles });
}

/** A runbook file as stored. An open editor keeps its own copy. */
export function useRunbookFile(file: string | undefined) {
  return useQuery({
    queryKey: keys.runbookFile(file ?? ''),
    queryFn: () => adminApi.runbookFile(file ?? ''),
    enabled: file !== undefined,
    refetchOnWindowFocus: false,
    staleTime: Infinity,
    gcTime: 0,
  });
}

export function useValidateRunbook() {
  return useMutation({ mutationFn: ({ yaml, file }: { yaml: string; file: string }) => adminApi.validateRunbook(yaml, file) });
}

export function useSaveRunbook() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ file, yaml, revision }: { file: string; yaml: string; revision: string }) =>
      adminApi.saveRunbook(file, yaml, revision),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['runbooks'] }),
  });
}

export function useDeleteRunbook() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: adminApi.deleteRunbook,
    // Not the deleted file's own query: the editor showing it would fetch it
    // again, and it goes once the editor closes (gcTime 0).
    onSuccess: () => qc.invalidateQueries({ predicate: (q) => q.queryKey[0] === 'runbooks' && q.queryKey[1] !== 'file' }),
  });
}

export function useAutomationRuns(id: string) {
  return useQuery({ queryKey: keys.automationRuns(id), queryFn: () => adminApi.automationRuns(id), refetchInterval: 15_000 });
}

export function useDeleteAutomation() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: adminApi.deleteAutomation,
    // Not the deleted automation's own query: the editor showing it would
    // fetch it again, and it goes once the editor closes (gcTime 0).
    onSuccess: () => qc.invalidateQueries({ queryKey: ['automations', 'list'] }),
  });
}

/** Makes an encrypted backup and hands it to the browser to save. */
export function useDownloadBackup() {
  const withReauth = useWithReauth();
  return useMutation({
    mutationFn: async (passphrase: string) => {
      const { blob, name } = await withReauth(() => adminApi.backup(passphrase));
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = name;
      document.body.append(a);
      a.click();
      a.remove();
      setTimeout(() => {
        URL.revokeObjectURL(url);
      }, 60_000);
      return name;
    },
  });
}
