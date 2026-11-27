// The UniFi model: how a controller's clients and health read. Kept apart
// from the components so node --test can check it (web/test/unifi.test.mjs).

import type { UniFiClient, UniFiHealth } from './api/unifi.ts';

/** Where a client is connected: the AP and SSID, or the switch and port. */
export function clientLink(c: Pick<UniFiClient, 'wired' | 'uplink' | 'port' | 'ssid'>): string {
  if (c.wired) {
    const at = [c.uplink, c.port ? `port ${String(c.port)}` : ''].filter((s) => s !== '').join(' · ');
    return at ? `Wired · ${at}` : 'Wired';
  }
  const at = [c.uplink, c.ssid ?? ''].filter((s) => s !== '').join(' · ');
  return at ? `Wi-Fi · ${at}` : 'Wi-Fi';
}

/** A bytes-per-second rate as bits per second, the way links are sold. */
export function bitRate(bytesPerSecond: number): string {
  const bits = bytesPerSecond * 8;
  if (bits >= 1e9) {
    return `${(bits / 1e9).toFixed(1)} Gbit/s`;
  }
  if (bits >= 1e6) {
    return `${(bits / 1e6).toFixed(1)} Mbit/s`;
  }
  if (bits >= 1e3) {
    return `${String(Math.round(bits / 1e3))} kbit/s`;
  }
  return `${String(Math.round(bits))} bit/s`;
}

/** One line on a subsystem's health, past its status. */
export function healthDetail(h: UniFiHealth): string {
  const parts: string[] = [];
  if (h.wan_ip) {
    parts.push(h.wan_ip);
  }
  if (h.isp) {
    parts.push(h.isp);
  }
  if (h.rx_rate || h.tx_rate) {
    parts.push(`↓ ${bitRate(h.rx_rate ?? 0)} ↑ ${bitRate(h.tx_rate ?? 0)}`);
  }
  if (h.latency_ms) {
    parts.push(`${String(h.latency_ms)} ms`);
  }
  if (h.users) {
    parts.push(`${String(h.users)} ${h.users === 1 ? 'client' : 'clients'}`);
  }
  return parts.join(' · ');
}

/** A SHA-256 fingerprint, as AA:BB:... or plain hex; empty is none. */
export function validFingerprint(fp: string): boolean {
  const hex = fp.trim().replaceAll(':', '');
  return hex === '' || /^[0-9a-fA-F]{64}$/.test(hex);
}
