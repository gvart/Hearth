// What Settings → Plugins shows of a plugin index: which plugins match a search,
// what each may do once installed, and whether one is installed or has an update.
// Kept apart from the components so node --test can check it (web/test/pluginregistry.test.mjs).

import type { InstalledPlugin, RegistryEntry } from './api/pluginregistry.ts';

/** Whether an entry's name, description or author holds the search text. */
export function matches(e: RegistryEntry, query: string): boolean {
  const q = query.trim().toLowerCase();
  if (q === '') {
    return true;
  }
  return [e.name, e.description ?? '', e.author ?? ''].some((s) => s.toLowerCase().includes(q));
}

/** What installing an entry grants, line by line, as the install dialog lists it. */
export function accessLines(e: RegistryEntry): string[] {
  const lines =
    e.http_allow.length > 0
      ? e.http_allow.map((h) => `Make HTTP requests to ${h}`)
      : ['Reach nothing outside its sandbox: no network, no files'];
  lines.push(`Use up to ${String(e.memory)} MiB of memory`);
  if (e.capabilities.includes('discover')) {
    lines.push('Report devices and their entities to the hub');
  }
  return lines;
}

/** A short summary of an entry's host access, for a table cell. */
export function accessSummary(e: RegistryEntry): string {
  return e.http_allow.length > 0 ? `HTTP: ${e.http_allow.join(', ')}` : 'No network';
}

/** Compares two semantic versions, as the hub does: -1, 0 or 1. */
export function compareVersions(a: string, b: string): number {
  const split = (v: string) => {
    const [core = '', pre = ''] = v.replace(/^v/, '').split(/-(.*)/s);
    return { core: core.split('.'), pre: pre === '' ? [] : pre.split('.') };
  };
  const idents = (x: string[], y: string[]): number => {
    for (let i = 0; i < Math.min(x.length, y.length); i++) {
      const xs = x[i] ?? '';
      const ys = y[i] ?? '';
      const xn = /^\d+$/.test(xs);
      const yn = /^\d+$/.test(ys);
      if (xn && yn) {
        const d = Number(xs) - Number(ys);
        if (d !== 0) {
          return Math.sign(d);
        }
      } else if (xn !== yn) {
        return xn ? -1 : 1;
      } else if (xs !== ys) {
        return xs < ys ? -1 : 1;
      }
    }
    return Math.sign(x.length - y.length);
  };
  const x = split(a);
  const y = split(b);
  const c = idents(x.core, y.core);
  if (c !== 0) {
    return c;
  }
  if (x.pre.length === 0 || y.pre.length === 0) {
    return Math.sign(y.pre.length - x.pre.length);
  }
  return idents(x.pre, y.pre);
}

export type BrowseState = 'install' | 'installed' | 'update';

/** What Browse offers for an entry: install it, or it is installed, or an update of it. */
export function browseState(e: RegistryEntry, installed: InstalledPlugin[]): BrowseState {
  const i = installed.find((p) => p.name === e.name);
  if (!i) {
    return 'install';
  }
  return compareVersions(e.version, i.version) > 0 ? 'update' : 'installed';
}
