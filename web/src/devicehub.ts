// Whether a device is a hub of the cluster too, and what its page offers to
// change that (#332): kept apart from the components so node --test can check
// it (web/test/devicehub.test.mjs). See docs/cluster.md.

import type { ClusterMember } from './cluster.ts';

/** GET /api/v1/devices/{id}/hub. */
export interface DeviceHub {
  /** The member the device became; absent for an agent only. */
  node_id?: string;
  roles: string[];
  allowed_roles: string[];
  /** alive, suspect, dead, left, or unknown while this hub does not see it. */
  state?: string;
  masters: number;
  storage: number;
  max_masters: number;
  max_storage: number;
  /** Run on the device, it stops and removes its hub service. */
  agent_only_command: string;
}

/** POST /api/v1/devices/{id}/hub: the command that makes the device a hub. Shown once. */
export interface MakeHub {
  roles: string[];
  expires_at: string;
  command: string;
}

/** The device's hub as a member card would show it. */
export function hubMember(h: DeviceHub): ClusterMember | undefined {
  if (!h.node_id) {
    return undefined;
  }
  return { id: h.node_id, address: '', roles: h.roles, allowed_roles: h.allowed_roles, state: h.state ?? 'unknown' };
}

/** One line on the device's hub roles: master and storage, storage only, or none. */
export function hubRoleLine(h: DeviceHub): string {
  if (!h.node_id) {
    return 'Agent only: the hub service is not installed on this device.';
  }
  const master = h.roles.includes('master');
  const storage = h.roles.includes('storage');
  if (master && storage) {
    return 'Master and storage: serves the UI, the API and agents, and keeps a share of the store.';
  }
  if (master) {
    return 'Master: serves the UI, the API and agents.';
  }
  if (storage) {
    return 'Storage: keeps a share of the store.';
  }
  return 'No role yet.';
}

/**
 * Whether a device of os and arch may run a hub. os is the agent's platform
 * ("darwin 26.1", "debian 12", "Microsoft Windows 11 Pro"): only Windows and
 * Android are ruled out here; the device checks the rest (Linux or macOS,
 * memory and disk) itself.
 */
export function hubPlatform(os: string, arch: string): boolean {
  const o = os.toLowerCase();
  return (arch === '' || arch === 'amd64' || arch === 'arm64') && !o.includes('windows') && !o.startsWith('android');
}

/**
 * Why "Make this device a hub" is not offered, or undefined when it is. The
 * hub checks again, and counts the join tokens not yet used too.
 */
export function makeHubBlocked(h: DeviceHub, os: string, arch: string): string | undefined {
  if (!hubPlatform(os, arch)) {
    return 'Only a 64-bit Linux or macOS device (amd64 or arm64) can run a hub.';
  }
  if (h.storage >= h.max_storage) {
    return `The cluster has ${String(h.storage)} storage members, the most devices become (${String(h.max_storage)}). Make another device agent-only first.`;
  }
  return undefined;
}

/** What making the device a hub would give it, from the counts now. */
export function makeHubEffect(h: DeviceHub): string {
  if (h.masters < h.max_masters) {
    return `It becomes a master and a storage member: ${String(h.masters)} of at most ${String(h.max_masters)} masters now. As a master it receives the hub CA key.`;
  }
  return `It becomes a storage member only: the cluster has ${String(h.masters)} masters, the most devices become. Promote it to master later if one goes.`;
}

/** The caps line: how many masters and storage members of the most devices become. */
export function capsLine(h: DeviceHub): string {
  return `${String(h.masters)} of ${String(h.max_masters)} masters · ${String(h.storage)} of ${String(h.max_storage)} storage members`;
}
