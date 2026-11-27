// The OPNsense model: how a firewall's clients and its firmware read. Kept
// apart from the components so node --test can check it (web/test/opnsense.test.mjs).

import type { OPNsenseClient, OPNsenseFirmware } from './api/opnsense.ts';

const leaseServer: Record<string, string> = { isc: 'ISC DHCP', kea: 'Kea', dnsmasq: 'Dnsmasq' };

/** How Hearth knows a client: from a DHCP lease, the ARP table, the NDP table, or several. */
export function clientVia(c: Pick<OPNsenseClient, 'lease' | 'lease_source' | 'arp' | 'ipv6'>): string {
  const via: string[] = [];
  if (c.lease) {
    via.push(`${leaseServer[c.lease_source] ?? 'DHCP'} lease`);
  }
  if (c.arp) {
    via.push('ARP');
  }
  if (c.ipv6.length > 0) {
    via.push('NDP');
  }
  return via.join(' · ') || '—';
}

/** What a lease has left at nowSec (Unix seconds). */
export function leaseLeft(c: Pick<OPNsenseClient, 'lease' | 'static' | 'lease_ends'>, nowSec: number): string {
  if (!c.lease) {
    return '—';
  }
  if (c.static) {
    return 'Static';
  }
  if (c.lease_ends <= 0) {
    return 'Active';
  }
  const s = c.lease_ends - nowSec;
  if (s <= 0) {
    return 'Ended';
  }
  if (s < 3600) {
    return `${String(Math.max(1, Math.round(s / 60)))} min`;
  }
  if (s < 2 * 86400) {
    return `${String(Math.round(s / 3600))} h`;
  }
  return `${String(Math.round(s / 86400))} d`;
}

/** The firmware line: the version, and what the firewall's last update check found. */
export function firmwareLine(f: OPNsenseFirmware): string {
  if (f.version === '') {
    return '';
  }
  const version = `${f.product || 'OPNsense'} ${f.version}`;
  switch (f.status) {
    case 'update':
    case 'upgrade':
      return f.latest && f.latest !== f.version ? `${version} · ${f.latest} available` : `${version} · updates available`;
    case 'error':
      return `${version} · update check failed`;
    default:
      return version;
  }
}

/** Whether a firewall URL is plain http, which Hearth refuses: the API key would cross the network in the clear. */
export function isPlainHTTP(url: string): boolean {
  return url.trim().toLowerCase().startsWith('http://');
}
