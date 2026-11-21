// Typed client and hooks for the members of an AP cluster
// (/api/v1/cluster/members).

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import type { CAStep, ClusterAction, ClusterCA, ClusterRole, ClusterStatus } from '../cluster.ts';
import { ApiError, request } from './client.ts';
import { useWithReauth } from './reauth.ts';

/** What a promotion or demotion did: done, syncing or draining. */
export interface RoleChange {
  member: string;
  role: string;
  state: 'done' | 'syncing' | 'draining';
}

/** What a removal did. */
export interface Removal {
  member: string;
  revoked: number;
}

/** A created cluster join token: shown once, never retrievable again. */
export interface JoinToken {
  token: string;
  expires_at: string;
  /** This master's URL: the new hub joins through it. */
  hub_url: string;
  join_command: string;
}

const clusterApi = {
  members: () => request<ClusterStatus>('GET', '/cluster/members'),
  ca: () => request<ClusterCA>('GET', '/cluster/ca'),
  caStep: (step: CAStep) => request<ClusterCA>('POST', `/cluster/ca/${step}`),
  createJoinToken: (ttl: string, roles: ClusterRole[]) => request<JoinToken>('POST', '/cluster/tokens', { ttl, roles }),
  change: (member: string, a: ClusterAction): Promise<RoleChange | Removal> => {
    const path = `/cluster/members/${encodeURIComponent(member)}`;
    return a.op === 'remove'
      ? request<Removal>('DELETE', path)
      : request<RoleChange>('POST', `${path}/${a.op}`, { role: a.role });
  },
};

const keys = { members: ['cluster', 'members'] as const, ca: ['cluster', 'ca'] as const };

/** A hub outside an AP cluster answers 404: the cluster page is not offered. */
export function isNotAPCluster(err: unknown): boolean {
  return err instanceof ApiError && err.status === 404;
}

/** The members, refreshed often enough to follow a drain or a catch-up. */
export function useClusterMembers() {
  return useQuery({
    queryKey: keys.members,
    queryFn: clusterApi.members,
    refetchInterval: (q) => (isNotAPCluster(q.state.error) ? false : 3000),
    retry: (n, err) => !isNotAPCluster(err) && n < 3,
  });
}

/** Promotes, demotes or removes a member once policy allows it. */
export function useClusterChange() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (req: { member: string; action: ClusterAction }) => clusterApi.change(req.member, req.action),
    onSettled: () => {
      void qc.invalidateQueries({ queryKey: keys.members });
    },
  });
}

/** The hub CA rotation and every member's side of it, refreshed often enough to follow one. */
export function useClusterCA() {
  return useQuery({
    queryKey: keys.ca,
    queryFn: clusterApi.ca,
    refetchInterval: (q) => (isNotAPCluster(q.state.error) ? false : 3000),
    retry: (n, err) => !isNotAPCluster(err) && n < 3,
  });
}

/** Starts, finishes or aborts the hub CA rotation: dangerous, with the password again. */
export function useClusterCAStep() {
  const withReauth = useWithReauth();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (step: CAStep) => withReauth(() => clusterApi.caStep(step)),
    onSuccess: (st) => {
      qc.setQueryData(keys.ca, st);
    },
    onSettled: () => {
      void qc.invalidateQueries({ queryKey: keys.ca });
      void qc.invalidateQueries({ queryKey: keys.members });
    },
  });
}

/**
 * Creates a cluster join token: dangerous, with the password again. The
 * token lives in this mutation only, dropped as soon as its dialog closes.
 */
export function useCreateJoinToken() {
  const withReauth = useWithReauth();
  return useMutation({
    mutationFn: ({ ttl, roles }: { ttl: string; roles: ClusterRole[] }) =>
      withReauth(() => clusterApi.createJoinToken(ttl, roles)),
    gcTime: 0,
  });
}
