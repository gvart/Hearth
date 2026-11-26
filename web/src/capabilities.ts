// What a device's Capabilities card shows and changes (#346): each thing the
// hub may do there, on or off, set here or by a flag on the device. Kept apart
// from the components so node --test can check it (web/test/capabilities.test.mjs).

import type { Ceiling } from './api/client.ts';

/** A device's capabilities, as GET /api/v1/devices/{id}/capabilities answers. */
export interface Capabilities {
  /** What the hub sets for the device. */
  hub: Ceiling;
  /** What the agent's --allow-* flags grant, which the hub cannot take away; null until it reports. */
  local: Ceiling | null;
  /** What the agent reports in effect; null until it reports. */
  effective: Ceiling | null;
  /** The agent runs with --local-ceiling: it ignores what the hub sets. */
  locked: boolean;
  /** The agent takes capabilities from the hub; an older one must be upgraded first. */
  manageable: boolean;
  agent_version: string;
  updated_at?: string;
  updated_by?: string;
}

/** "On" for a capability with a list: all of it. The hub's AllLogs, AllRestart and AllScan. */
export const allLogs = ['systemd:*', 'systemd-user:*', 'docker:*'];
export const allRestart = ['systemd:*', 'systemd-user:*', 'docker:*'];
export const allScan = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'];

export type CapKey = 'logs' | 'docker' | 'net_edges' | 'probe' | 'scan' | 'restart' | 'exec' | 'shell';

/** How a capability is switched: on/off, on/off with "restrict to", Docker's three levels, or a list only. */
export type CapKind = 'switch' | 'list' | 'docker' | 'exec';

export interface CapInfo {
  key: CapKey;
  label: string;
  /** What it lets the hub do, in a few words. */
  what: string;
  kind: CapKind;
  /** Raising it lets the hub change the device: dangerous, and the password again. */
  risky: boolean;
  /** For a list: what an entry looks like. */
  placeholder?: string;
}

export const capInfo: CapInfo[] = [
  { key: 'logs', label: 'Logs', what: 'Stream systemd and container logs here.', kind: 'list', risky: false, placeholder: 'systemd:nginx.service, docker:web' },
  { key: 'docker', label: 'Containers', what: 'List Docker or Podman containers and read their logs; with control, start, stop and restart them.', kind: 'docker', risky: true },
  { key: 'net_edges', label: 'Neighbors', what: 'Report its neighbours and TCP connections for the network map (Linux).', kind: 'switch', risky: false },
  { key: 'probe', label: 'Checks', what: 'Run HTTP, TCP and DNS checks from this device.', kind: 'switch', risky: false },
  { key: 'scan', label: 'Network scan', what: 'Sweep a subnet for discovery from here.', kind: 'list', risky: false, placeholder: '192.168.20.0/24' },
  { key: 'restart', label: 'Restart services', what: 'Restart systemd units and containers, from automations and runbooks.', kind: 'list', risky: true, placeholder: 'systemd:pihole-FTL.service, docker:jellyfin' },
  { key: 'exec', label: 'Run programs', what: 'Run the programs named here, with any arguments.', kind: 'exec', risky: true, placeholder: '/usr/bin/df' },
  { key: 'shell', label: 'Terminal', what: "Open a shell in the browser, as the agent's user.", kind: 'switch', risky: true },
];

/** The list "on" stands for, of a list capability. */
export function allOf(key: CapKey): string[] | undefined {
  return key === 'logs' ? allLogs : key === 'restart' ? allRestart : key === 'scan' ? allScan : undefined;
}

export const emptyCeiling = (): Ceiling => ({
  exec: [],
  restart: [],
  probe: false,
  logs: [],
  shell: false,
  scan: [],
  net_edges: false,
  docker: false,
  docker_read: false,
});

function listOf(c: Ceiling | null | undefined, key: CapKey): string[] {
  if (!c) {
    return [];
  }
  switch (key) {
    case 'logs':
      return c.logs ?? [];
    case 'restart':
      return c.restart;
    case 'scan':
      return c.scan ?? [];
    case 'exec':
      return c.exec;
    default:
      return [];
  }
}

function flagOf(c: Ceiling | null | undefined, key: CapKey): boolean {
  if (!c) {
    return false;
  }
  switch (key) {
    case 'shell':
      return c.shell ?? false;
    case 'probe':
      return c.probe;
    case 'net_edges':
      return c.net_edges ?? false;
    case 'docker':
      return (c.docker ?? false) || (c.docker_read ?? false);
    default:
      return listOf(c, key).length > 0;
  }
}

/** Docker's level in c: off, read (list and logs), or control (start, stop, restart too). */
export type DockerLevel = 'off' | 'read' | 'control';

export function dockerLevel(c: Ceiling | null | undefined): DockerLevel {
  return c?.docker ? 'control' : c?.docker_read ? 'read' : 'off';
}

/** Whether a list is everything ("on") rather than some entries. */
export function isAll(key: CapKey, list: string[]): boolean {
  const all = allOf(key);
  return all !== undefined && all.every((e) => list.includes(e));
}

/** One capability's state on the card. */
export interface CapState {
  info: CapInfo;
  /** On as the hub sets it. */
  hubOn: boolean;
  /** On by a flag on the device: the hub cannot turn it off. */
  local: boolean;
  /** The hub's list, for a list capability. */
  hubList: string[];
  /** The flags' list. */
  localList: string[];
  /** In effect, as the agent reports. */
  effectiveOn: boolean;
  /** "all" for a list that is everything, else the entries. */
  summary: string;
  docker: { hub: DockerLevel; local: DockerLevel };
  /** Why it cannot be on this device's platform, if it cannot. */
  unsupported?: string;
}

/** Whether the device's platform lacks key: a terminal on Windows, neighbours off Linux. */
export function unsupportedOn(os: string | undefined, key: CapKey): string | undefined {
  const o = (os ?? '').toLowerCase();
  if (key === 'shell' && o.includes('windows')) {
    return 'Not on Windows';
  }
  if (key === 'net_edges' && (o.includes('windows') || o.includes('darwin') || o.includes('macos'))) {
    return 'Linux only';
  }
  return undefined;
}

function summarize(key: CapKey, list: string[]): string {
  if (list.length === 0) {
    return 'off';
  }
  return isAll(key, list) ? 'all' : list.join(', ');
}

/** The card's rows. */
export function capStates(caps: Capabilities, os?: string): CapState[] {
  return capInfo.map((info) => {
    const hubList = listOf(caps.hub, info.key);
    const localList = listOf(caps.local, info.key);
    const both = [...localList, ...hubList.filter((e) => !localList.includes(e))];
    return {
      info,
      hubOn: flagOf(caps.hub, info.key),
      local: flagOf(caps.local, info.key),
      hubList,
      localList,
      effectiveOn: flagOf(caps.effective, info.key),
      summary: summarize(info.key, both),
      docker: { hub: dockerLevel(caps.hub), local: dockerLevel(caps.local) },
      unsupported: unsupportedOn(os, info.key),
    };
  });
}

/** c with key switched on or off: "on" is all of a list capability, and read for Docker. */
export function withSwitch(c: Ceiling, key: CapKey, on: boolean): Ceiling {
  const next = { ...emptyCeiling(), ...c };
  switch (key) {
    case 'shell':
      next.shell = on;
      break;
    case 'probe':
      next.probe = on;
      break;
    case 'net_edges':
      next.net_edges = on;
      break;
    case 'docker':
      next.docker = false;
      next.docker_read = on;
      break;
    case 'logs':
    case 'restart':
    case 'scan':
      return withList(next, key, on ? (allOf(key) ?? []) : []);
    case 'exec':
      if (!on) {
        next.exec = [];
      }
      break;
  }
  return next;
}

/** c with Docker at level. */
export function withDocker(c: Ceiling, level: DockerLevel): Ceiling {
  return { ...emptyCeiling(), ...c, docker: level === 'control', docker_read: level !== 'off' };
}

/** c with the list of key set to list. */
export function withList(c: Ceiling, key: CapKey, list: string[]): Ceiling {
  const next = { ...emptyCeiling(), ...c };
  const clean = [...new Set(list.map((e) => e.trim()).filter((e) => e !== ''))];
  switch (key) {
    case 'logs':
      next.logs = clean;
      break;
    case 'restart':
      next.restart = clean;
      break;
    case 'scan':
      next.scan = clean;
      break;
    case 'exec':
      next.exec = clean;
      break;
    default:
      break;
  }
  return next;
}

/** Splits what was typed into a list: commas, spaces or new lines. */
export function parseList(text: string): string[] {
  return text
    .split(/[\s,]+/)
    .map((e) => e.trim())
    .filter((e) => e !== '');
}

/**
 * Whether going from old to next raises a shell, exec, restart or Docker
 * control: the hub then asks for the password again, as it decides it
 * (hub.ChangeOf).
 */
export function raisesRisky(old: Ceiling, next: Ceiling): boolean {
  const added = (o: string[], n: string[]) => n.some((e) => !o.includes(e));
  return (
    ((next.shell ?? false) && !(old.shell ?? false)) ||
    added(old.exec, next.exec) ||
    added(old.restart, next.restart) ||
    ((next.docker ?? false) && !(old.docker ?? false))
  );
}

/** Whether the agent reports what the hub and its flags add up to: false while it has not applied a change yet. */
export function applied(caps: Capabilities): boolean {
  if (!caps.effective || caps.locked) {
    return true;
  }
  return capInfo.every((i) => {
    const want = flagOf(caps.hub, i.key) || flagOf(caps.local, i.key);
    return i.key === 'shell' || i.key === 'net_edges' ? true : want === flagOf(caps.effective, i.key);
  });
}

/** What the card says about the agent: who manages its capabilities. */
export type CardMode = 'managed' | 'locked' | 'upgrade' | 'unreported';

export function cardMode(caps: Capabilities): CardMode {
  if (caps.locked) {
    return 'locked';
  }
  if (!caps.effective) {
    return 'unreported';
  }
  return caps.manageable ? 'managed' : 'upgrade';
}

/** Whether a ceiling entry is a glob (docker:*) rather than one name. */
export function isPattern(entry: string): boolean {
  const name = entry.slice(entry.indexOf(':') + 1);
  return /[*?[\\]/.test(name);
}

/** The glob of a ceiling entry's name as a RegExp: * and ? never cross a slash, as Go's path.Match. */
function globRegExp(glob: string): RegExp {
  let re = '';
  for (const ch of glob) {
    re += ch === '*' ? '[^/]*' : ch === '?' ? '[^/]' : ch.replace(/[.+^${}()|[\]\\]/g, '\\$&');
  }
  return new RegExp(`^${re}$`);
}

/** Whether one of entries (manager:name or manager:glob) allows service, a manager:name. */
export function allowsService(entries: string[], service: string): boolean {
  const i = service.indexOf(':');
  if (i < 0) {
    return false;
  }
  const manager = service.slice(0, i);
  const name = service.slice(i + 1);
  return entries.some((e) => {
    const j = e.indexOf(':');
    return j >= 0 && e.slice(0, j) === manager && globRegExp(e.slice(j + 1)).test(name);
  });
}
