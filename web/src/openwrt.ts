// The OpenWrt model: how a router's clients and its connection read. Kept
// apart from the components so node --test can check it (web/test/openwrt.test.mjs).

import type { OpenWrtClient } from './api/openwrt.ts';

/** How Hearth knows a client: from a DHCP lease, a wireless association or both. */
export function clientVia(c: Pick<OpenWrtClient, 'lease' | 'wireless' | 'radio'>): string {
  const wifi = c.wireless ? `Wi-Fi${c.radio ? ` (${c.radio})` : ''}` : '';
  if (c.lease && wifi) {
    return `Lease · ${wifi}`;
  }
  return c.lease ? 'Lease' : wifi || '—';
}

/** What a lease has left: 0 is a static lease. */
export function leaseLeft(c: Pick<OpenWrtClient, 'lease' | 'lease_expires'>): string {
  if (!c.lease) {
    return '—';
  }
  const s = c.lease_expires;
  if (s <= 0) {
    return 'Static';
  }
  if (s < 3600) {
    return `${String(Math.max(1, Math.round(s / 60)))} min`;
  }
  return `${String(Math.round(s / 3600))} h`;
}

/** A SHA-256 fingerprint, as AA:BB:... or plain hex; empty is none. */
export function validFingerprint(fp: string): boolean {
  const hex = fp.trim().replaceAll(':', '');
  return hex === '' || /^[0-9a-fA-F]{64}$/.test(hex);
}

/** Whether a router URL sends the password in the clear. */
export function isPlainHTTP(url: string): boolean {
  return url.trim().toLowerCase().startsWith('http://');
}
