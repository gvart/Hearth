import type { Device, DeviceStatus } from './api/client.ts';

const statusLabels: Record<DeviceStatus, string> = {
  online: 'Online',
  offline: 'Offline',
  unknown: 'Never connected',
};

export function statusLabel(s: DeviceStatus): string {
  return statusLabels[s];
}

/** The address a person would type to reach the device: the first routable IPv4, else IPv6. */
export function primaryIP(d: Device): string | undefined {
  const ips = (d.facts.interfaces ?? []).flatMap((i) => i.ips).map((ip) => ip.replace(/\/\d+$/, ''));
  const usable = ips.filter((ip) => !isLoopback(ip) && !ip.startsWith('169.254.') && !ip.toLowerCase().startsWith('fe80:'));
  return usable.find((ip) => !ip.includes(':')) ?? usable[0];
}

function isLoopback(ip: string) {
  return ip.startsWith('127.') || ip === '::1';
}

export function osArch(d: Device): string {
  const os = d.os || d.facts.os;
  const arch = d.arch || d.facts.arch;
  return [os, arch].filter(Boolean).join(' / ') || '—';
}

export function displayName(d: Device): string {
  return d.name || d.hostname || d.id;
}

const units: [Intl.RelativeTimeFormatUnit, number][] = [
  ['day', 86_400],
  ['hour', 3_600],
  ['minute', 60],
  ['second', 1],
];

const rtf = new Intl.RelativeTimeFormat(undefined, { numeric: 'auto', style: 'narrow' });

/** "5 min ago"-style time relative to now. */
export function relativeTime(iso: string, now: number): string {
  const t = Date.parse(iso);
  if (Number.isNaN(t) || t <= 0) {
    return '—';
  }
  const secs = Math.round((t - now) / 1000);
  if (Math.abs(secs) < 10) {
    return 'just now';
  }
  for (const [unit, size] of units) {
    if (Math.abs(secs) >= size) {
      return rtf.format(Math.trunc(secs / size), unit);
    }
  }
  return rtf.format(secs, 'second');
}

export function formatBytes(n: number | undefined): string {
  if (!n) {
    return '—';
  }
  const steps = ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB'];
  let i = 0;
  let v = n;
  while (v >= 1024 && i < steps.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(v >= 10 || i === 0 ? 0 : 1)} ${steps[i] ?? ''}`;
}

export function formatDateTime(iso: string): string {
  const t = Date.parse(iso);
  return Number.isNaN(t) || t <= 0 ? '—' : new Date(t).toLocaleString();
}
