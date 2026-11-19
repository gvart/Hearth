// Typed client and hooks for the automation editor (/api/v1/automations).

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { request } from './client.ts';

export interface AutomationProblem {
  /** 0 when the problem has no line. */
  line: number;
  message: string;
}

export interface AutomationSummary {
  /** Empty for a file that declares no id. */
  id: string;
  file: string;
  description: string;
  mode: string;
  triggers: number;
  actions: number;
  /** Why the hub cannot load the file; empty when it can. */
  problems: AutomationProblem[];
}

export interface AutomationSource {
  id: string;
  file: string;
  yaml: string;
  revision: string;
  problems: AutomationProblem[];
}

export type PolicyDecision = 'allow' | 'confirm' | 'deny';

export interface AutomationActionDecision {
  step: string;
  type: string;
  action: string;
  class: string;
  target: string;
  decision: PolicyDecision;
  reason?: string;
}

export interface AutomationDryRun {
  valid: boolean;
  problems: AutomationProblem[];
  /** Why a valid file could not be saved now. */
  blocked?: string;
  plan?: string;
  save?: { action: string; class: string; decision: PolicyDecision; reason?: string };
  actions: AutomationActionDecision[];
}

export interface SavedAutomation {
  id: string;
  file: string;
  revision: string;
}

export interface SaveAutomation {
  /** The automation being replaced; undefined creates a new one. */
  id?: string;
  yaml: string;
  revision: string;
}

const automationsApi = {
  list: async () => (await request<{ automations: AutomationSummary[] }>('GET', '/automations')).automations,
  get: (id: string) => request<AutomationSource>('GET', `/automations/${encodeURIComponent(id)}`),
  save: ({ id, yaml, revision }: SaveAutomation) =>
    id === undefined
      ? request<SavedAutomation>('POST', '/automations', { yaml, revision })
      : request<SavedAutomation>('PUT', `/automations/${encodeURIComponent(id)}`, { yaml, revision }),
  dryRun: (body: SaveAutomation) => request<AutomationDryRun>('POST', '/automations/dry-run', body),
};

const keys = {
  all: ['automations'] as const,
  list: ['automations', 'list'] as const,
  one: (id: string) => ['automations', 'one', id] as const,
};

export function useAutomations() {
  return useQuery({ queryKey: keys.list, queryFn: automationsApi.list });
}

/** The file as it is on the hub. An open editor keeps its own copy. */
export function useAutomation(id: string) {
  return useQuery({
    queryKey: keys.one(id),
    queryFn: () => automationsApi.get(id),
    refetchOnWindowFocus: false,
    refetchOnReconnect: false,
    staleTime: Infinity,
    gcTime: 0,
  });
}

/** Saves a file. A save policy holds for approval answers once it is decided. */
export function useSaveAutomation() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: automationsApi.save,
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: keys.list });
    },
  });
}

/** Validates a file and asks policy about it. Nothing is written or run. */
export function useDryRunAutomation() {
  return useMutation({ mutationFn: automationsApi.dryRun });
}
