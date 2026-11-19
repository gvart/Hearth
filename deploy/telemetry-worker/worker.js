// SPDX-License-Identifier: AGPL-3.0-only
//
// Hearth's telemetry collector: a Cloudflare Worker that takes the weekly
// anonymous usage stats opted-in hubs send (docs/telemetry.md) and keeps one
// row per install ID per week in D1. It checks the payload's shape strictly,
// and stores no IP address: it never reads the request's headers beyond the
// content type.

const KEYS = ['arch', 'devices', 'install_id', 'integrations', 'os', 'version'];
const DEVICES = ['0', '1-5', '6-20', '21-50', '51+'];
const INTEGRATIONS = ['beszel', 'dhcp', 'discovery', 'kubernetes', 'netalertx', 'pihole', 'prometheus', 'proxmox'];
const MAX_BODY = 2048;

/** Returns the payload if it is exactly what a hub sends, or null. */
export function validate(p) {
  if (p === null || typeof p !== 'object' || Array.isArray(p)) {
    return null;
  }
  const keys = Object.keys(p).sort();
  if (keys.length !== KEYS.length || keys.some((k, i) => k !== KEYS[i])) {
    return null;
  }
  const ok =
    typeof p.install_id === 'string' &&
    /^[A-Z2-7]{26}$/.test(p.install_id) &&
    typeof p.version === 'string' &&
    /^[0-9A-Za-z.+_-]{1,64}$/.test(p.version) &&
    typeof p.os === 'string' &&
    /^[a-z0-9]{1,16}$/.test(p.os) &&
    typeof p.arch === 'string' &&
    /^[a-z0-9]{1,16}$/.test(p.arch) &&
    DEVICES.includes(p.devices) &&
    Array.isArray(p.integrations) &&
    p.integrations.length <= INTEGRATIONS.length &&
    p.integrations.every((n) => INTEGRATIONS.includes(n)) &&
    new Set(p.integrations).size === p.integrations.length;
  return ok ? p : null;
}

/** The ISO week of d, such as 2026-W47: the week the collector counts in. */
export function isoWeek(d) {
  const t = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate()));
  const day = t.getUTCDay() || 7;
  t.setUTCDate(t.getUTCDate() + 4 - day);
  const year = t.getUTCFullYear();
  const week = Math.ceil(((t - Date.UTC(year, 0, 1)) / 86400000 + 1) / 7);
  return `${year}-W${String(week).padStart(2, '0')}`;
}

export default {
  async fetch(request, env) {
    if (request.method !== 'POST') {
      return new Response('POST only\n', { status: 405, headers: { Allow: 'POST' } });
    }
    if (!(request.headers.get('Content-Type') ?? '').startsWith('application/json')) {
      return new Response('JSON only\n', { status: 415 });
    }
    const text = await request.text();
    if (text.length > MAX_BODY) {
      return new Response('too large\n', { status: 413 });
    }
    let p;
    try {
      p = validate(JSON.parse(text));
    } catch {
      p = null;
    }
    if (!p) {
      return new Response('bad payload\n', { status: 400 });
    }
    // One row per install ID per week: a hub that sends twice in a week
    // (a restart, a failover) counts once.
    await env.DB.prepare(
      `INSERT INTO pings (week, install_id, version, os, arch, devices, integrations)
       VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
       ON CONFLICT (week, install_id) DO UPDATE SET
         version = excluded.version, os = excluded.os, arch = excluded.arch,
         devices = excluded.devices, integrations = excluded.integrations`,
    )
      .bind(isoWeek(new Date()), p.install_id, p.version, p.os, p.arch, p.devices, [...p.integrations].sort().join(','))
      .run();
    return new Response(null, { status: 204 });
  },
};
