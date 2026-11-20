// Typed client and hook for a device's network edges (/api/v1/devices/{id}/net-edges).

import { useQuery } from '@tanstack/react-query';
import { request } from './client.ts';

/** What the hub knows the other end of an edge to be. */
export interface Peer {
  kind: 'device' | 'hub' | 'host';
  /** The device's id, or the host's MAC; absent for the hub. */
  id?: string;
  name: string;
}

export interface Neighbor {
  ip: string;
  mac: string;
  peer: Peer | null;
}

/** A group of established TCP connections with one peer. */
export interface Connection {
  ip: string;
  /** The peer's port of an outbound connection, the device's own of an inbound one. */
  port: number;
  inbound: boolean;
  count: number;
  peer: Peer | null;
}

export interface NetEdges {
  /** Whether the device's agent reports edges (runs with --allow-net-edges). */
  enabled: boolean;
  updated_at: string | null;
  neighbors: Neighbor[];
  connections: Connection[];
}

const netEdgesApi = {
  get: (device: string) => request<NetEdges>('GET', `/devices/${encodeURIComponent(device)}/net-edges`),
};

/**
 * The device's edges. Every read is audited on the hub, so this never polls
 * or refetches on focus: it reads once per drawer opening, and on refetch().
 */
export function useNetEdges(device: string) {
  return useQuery({
    queryKey: ['net-edges', device] as const,
    queryFn: () => netEdgesApi.get(device),
    staleTime: Infinity,
    gcTime: 0,
    refetchOnWindowFocus: false,
    retry: false,
  });
}
