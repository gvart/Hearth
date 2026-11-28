// Typed client and hooks for the AI settings and explanations
// (GET /api/v1/ai, PUT /api/v1/ai/config, POST /api/v1/devices/{id}/explain, #59).

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { ApiError, request } from './client.ts';
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

const aiKey = ['ai', 'config'] as const;

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
