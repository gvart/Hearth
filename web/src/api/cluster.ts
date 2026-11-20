// Typed client and hooks for the members of an AP cluster
// (/api/v1/cluster/members).

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import type { ClusterAction, ClusterStatus } from '../cluster.ts';
import { ApiError, request } from './client.ts';

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

const clusterApi = {
  members: () => request<ClusterStatus>('GET', '/cluster/members'),
  change: (member: string, a: ClusterAction): Promise<RoleChange | Removal> => {
    const path = `/cluster/members/${encodeURIComponent(member)}`;
    return a.op === 'remove'
      ? request<Removal>('DELETE', path)
      : request<RoleChange>('POST', `${path}/${a.op}`, { role: a.role });
  },
};

const keys = { members: ['cluster', 'members'] as const };

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
