// Typed client and hooks for the AI settings and explanations
// (GET /api/v1/ai, PUT /api/v1/ai/config, POST /api/v1/devices/{id}/explain, #59)
// automation drafts (POST /api/v1/automations/draft, #60), and runbook drafts
// from recorded terminal sessions (/api/v1/devices/{id}/recordings, #81).

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import type { AutomationProblem } from './automations.ts';
import { ApiError, request, type RunbookPlan } from './client.ts';
import { useWithReauth } from './reauth.ts';

/** ai.yaml as the hub shows it: never the API key, only whether one is set. */
export interface AIConfig {
  enabled: boolean;
  provider: '' | 'openai' | 'anthropic';
  base_url: string;
  model: string;
  api_key_set: boolean;
  max_tokens: number;
  timeout_seconds: number;
  max_context_bytes: number;
  revision: string;
}

export interface AIMessage {
  role: string;
  content: string;
}

/** An explanation, with exactly what was sent for it. */
export interface Explanation {
  provider: string;
  model: string;
  base_url: string;
  /** Plain text: shown as such, never as HTML. */
  answer: string;
  sent: { system: string; messages: AIMessage[] };
  sent_bytes: number;
  redactions: number;
  truncated: string[];
  notes: string[];
  preview: boolean;
  input_tokens?: number;
  output_tokens?: number;
}

export interface ExplainRequest {
  question: string;
  logs: string[];
  preview: boolean;
}

/** A draft automation: never saved by the hub, only shown in the editor. */
export interface AutomationDraft {
  provider: string;
  model: string;
  base_url: string;
  /** The file; empty for a preview. */
  yaml: string;
  /** Whether the hub's validator accepts it. */
  valid: boolean;
  problems: AutomationProblem[];
  plan?: string;
  /** Answers asked for: two when the first did not validate. */
  attempts: number;
  sent: { system: string; messages: AIMessage[] };
  sent_bytes: number;
  redactions: number;
  truncated: string[];
  preview: boolean;
  input_tokens?: number;
  output_tokens?: number;
}

/** A terminal session recorded for a runbook: never what it holds. */
export interface Recording {
  id: string;
  device: string;
  started: string;
  /** Absent while the session is being recorded. */
  ended?: string;
  /** When the hub deletes it if no runbook is made from it. */
  expires?: string;
  bytes: number;
  full: boolean;
}

/** A draft runbook: never saved by the hub, only shown in the editor. */
export interface RunbookDraft {
  provider: string;
  model: string;
  base_url: string;
  /** The file, and the name it would be saved as; empty for a preview. */
  yaml: string;
  file: string;
  valid: boolean;
  problems: AutomationProblem[];
  plan?: RunbookPlan;
  attempts: number;
  sent: { system: string; messages: AIMessage[] };
  sent_bytes: number;
  redactions: number;
  truncated: string[];
  preview: boolean;
  /** The recording was deleted: it is, once the model answered. */
  discarded: boolean;
}

const aiKey = ['ai', 'config'] as const;
const recordingsKey = (device: string) => ['recordings', device] as const;
const recordingPath = (device: string, id: string) =>
  `/devices/${encodeURIComponent(device)}/recordings/${encodeURIComponent(id)}`;

export const aiApi = {
  /** null on a hub that keeps its configuration in files: AI is not served there. */
  config: async (): Promise<AIConfig | null> => {
    try {
      return await request<AIConfig>('GET', '/ai');
    } catch (err) {
      if (err instanceof ApiError && err.status === 404) {
        return null;
      }
      throw err;
    }
  },
  save: (body: Record<string, unknown>) => request<AIConfig>('PUT', '/ai/config', body),
  explain: (device: string, body: ExplainRequest) =>
    request<Explanation>('POST', `/devices/${encodeURIComponent(device)}/explain`, body),
  draftAutomation: (body: { text: string; preview: boolean }) =>
    request<AutomationDraft>('POST', '/automations/draft', body),
  recordings: (device: string) =>
    request<{ recordings: Recording[] }>('GET', `/devices/${encodeURIComponent(device)}/recordings`),
  discardRecording: (device: string, id: string) => request<undefined>('DELETE', recordingPath(device, id)),
  draftRunbook: (device: string, id: string, body: { notes: string; preview: boolean }) =>
    request<RunbookDraft>('POST', `${recordingPath(device, id)}/runbook`, body),
};

/** The AI settings; null where AI is not served. */
export function useAIConfig() {
  return useQuery({ queryKey: aiKey, queryFn: aiApi.config });
}

/** Saves ai.yaml: it decides where the hub's evidence goes, so it asks for the password again. */
export function useSaveAIConfig() {
  const qc = useQueryClient();
  const withReauth = useWithReauth();
  return useMutation({
    mutationFn: (body: Record<string, unknown>) => withReauth(() => aiApi.save(body)),
    onSuccess: (cfg) => {
      qc.setQueryData(aiKey, cfg);
    },
  });
}

/** Asks the model about a device, or with preview only gathers what would be sent. */
export function useExplain(device: string) {
  return useMutation({ mutationFn: (body: ExplainRequest) => aiApi.explain(device, body) });
}

/** Asks the model for an automation file; the hub validates it and saves nothing. */
export function useDraftAutomation() {
  return useMutation({ mutationFn: aiApi.draftAutomation });
}

/** The recordings of a device, on the hub that holds its terminal. */
export function useRecordings(device: string, enabled = true) {
  return useQuery({
    queryKey: recordingsKey(device),
    queryFn: async () => (await aiApi.recordings(device)).recordings,
    enabled,
    refetchInterval: 15_000,
  });
}

/** Deletes a recording at once. */
export function useDiscardRecording(device: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => aiApi.discardRecording(device, id),
    onSettled: () => qc.invalidateQueries({ queryKey: recordingsKey(device) }),
  });
}

/** Asks the model for a runbook from a recording; the hub validates it and saves nothing. */
export function useDraftRunbook(device: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, notes, preview }: { id: string; notes: string; preview: boolean }) =>
      aiApi.draftRunbook(device, id, { notes, preview }),
    onSettled: () => qc.invalidateQueries({ queryKey: recordingsKey(device) }),
  });
}
