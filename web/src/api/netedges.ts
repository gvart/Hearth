// Typed client and hooks for network edges: a device's (/api/v1/devices/{id}/net-edges)
// and every device's at once, as a graph (/api/v1/net-edges).

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

/** A node of the topology graph. */
export interface TopologyNode {
  /** "device:<id>", "hub", "host:<mac>" or "ip:<address>". */
  id: string;
  kind: 'device' | 'hub' | 'host' | 'unknown';
  name: string;
  /** A device's id. */
  device_id?: string;
  /** The address a host or unknown node was seen at. */
  ip?: string;
  /** Set on a device whose agent reports edges. */
  reports?: boolean;
}

/** An edge of the topology graph: a connection goes from the client to the server. */
export interface TopologyEdge {
  kind: 'neighbor' | 'connection';
  from: string;
  to: string;
  /** A connection's server port. */
  port?: number;
  count?: number;
}

/** Every device's network edges, as a graph. */
export interface Topology {
  /** How many devices' agents report edges (run with --allow-net-edges). */
  reporting: number;
  updated_at: string | null;
  nodes: TopologyNode[];
  edges: TopologyEdge[];
}

const netEdgesApi = {
  get: (device: string) => request<NetEdges>('GET', `/devices/${encodeURIComponent(device)}/net-edges`),
  topology: () => request<Topology>('GET', '/net-edges'),
};

/**
 * Every device's edges, as a graph. One read is one audit entry on the hub,
 * so this never polls or refetches on focus: it reads once per page opening,
 * and on refetch().
 */
export function useTopology() {
  return useQuery({
    queryKey: ['net-topology'] as const,
    queryFn: netEdgesApi.topology,
    staleTime: Infinity,
    gcTime: 0,
    refetchOnWindowFocus: false,
    retry: false,
  });
}

/**
 * The device's edges. Every read is audited on the hub, so this never polls
 * or refetches on focus: it reads once per opening of the device page, and on refetch().
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
