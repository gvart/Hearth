// Adopting a host without an agent as a device (docs/discovery.md, "Adopting a
// host"). Kept apart from the components so node --test can check it
// (web/test/adopt.test.mjs).

import type { NetworkHost } from './api/client.ts';

/** The longest name a host may be adopted under, in characters, as the hub checks it. */
export const maxAdoptName = 63;

/** What a discovered host is called before it is adopted: its hostname, else its vendor, else its IP. */
export function hostName(h: Pick<NetworkHost, 'hostname' | 'vendor' | 'ip'>): string {
  return h.hostname.replace(/\.local$/, '') || h.vendor || h.ip;
}

/** The name the adopt prompt starts with: the host's name, cut to what the hub accepts. */
export function adoptPrefill(h: Pick<NetworkHost, 'hostname' | 'vendor' | 'ip'>): string {
  // Code points, as the hub counts them.
  return Array.from(hostName(h)).slice(0, maxAdoptName).join('');
}

/** Whether the hub takes name: 1 to 63 characters once trimmed, none of them a control character. */
export function validAdoptName(name: string): boolean {
  const n = Array.from(name.trim());
  return n.length > 0 && n.length <= maxAdoptName && !n.some((c) => /\p{Cc}/u.test(c));
}

/** The adopted hosts, by name. */
export function adoptedHosts(hosts: NetworkHost[]): NetworkHost[] {
  return hosts.filter((h) => h.state === 'adopted' && h.device_id === '').sort((a, b) => a.name.localeCompare(b.name));
}
