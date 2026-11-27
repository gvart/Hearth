// What the Devices page shows of a device's metrics and disks. Kept apart from
// the components so node --test can check it (web/test/devices.test.mjs).

import type { Ceiling, Disk, MetricChart, NetworkHost } from './api/client.ts';

export type MeterTone = 'ok' | 'warn' | 'bad';

/** The share of a disk in use, in whole percent; undefined when the agent does not report it. */
export function diskUse(d: Pick<Disk, 'total_bytes' | 'used_bytes'>): number | undefined {
  if (!d.used_bytes || !d.total_bytes) {
    return undefined;
  }
  return Math.min(100, Math.round((d.used_bytes / d.total_bytes) * 100));
}

/** How full is too full: a warning from 85%, a problem from 95%. */
export function meterTone(percent: number): MeterTone {
  return percent >= 95 ? 'bad' : percent >= 85 ? 'warn' : 'ok';
}

/** The newest value of one chart of a device, such as its cpu; undefined without data. */
export function latest(charts: MetricChart[] | undefined, key: string): number | undefined {
  const points = charts?.find((c) => c.key === key)?.points;
  return points?.[points.length - 1]?.[1];
}

/** The cards of the device page its agent keeps off: they are turned on in its Capabilities card. */
export interface NotAllowed {
  logs: boolean;
  docker: boolean;
  netEdges: boolean;
}

/**
 * The parts of the device page its agent keeps off. An agent too old to report
 * its ceiling allows none of them.
 */
export function notAllowed(device: { facts: { ceiling?: Ceiling } }): NotAllowed {
  const c = device.facts.ceiling;
  return {
    logs: (c?.logs ?? []).length === 0,
    docker: !c?.docker && !c?.docker_read,
    netEdges: !c?.net_edges,
  };
}

export type DevicesView = 'blocks' | 'table';

const viewKey = 'hearth.devices.view';

/** The view of the device list this browser chose, or blocks. */
export function storedView(): DevicesView {
  try {
    return localStorage.getItem(viewKey) === 'table' ? 'table' : 'blocks';
  } catch {
    return 'blocks';
  }
}

export function rememberView(view: DevicesView): void {
  try {
    localStorage.setItem(viewKey, view);
  } catch {
    // Private mode: the choice lasts for this page only.
  }
}

/**
 * The device name suggested for a discovered host: its hostname without
 * .local, reduced to what the hub accepts (1 to 63 letters, digits, ., - or _,
 * starting with a letter or digit). Empty when it has no hostname: the device
 * then takes its own.
 */
export function suggestedName(h: Pick<NetworkHost, 'hostname'>): string {
  return h.hostname
    .replace(/\.local\.?$/i, '')
    .replace(/[^A-Za-z0-9._-]+/g, '-')
    .replace(/^[^A-Za-z0-9]+/, '')
    .slice(0, 63);
}

/**
 * The Devices page's subtitle: how many devices are online, agents and
 * adopted network hosts together, and how many of them run no agent.
 */
export function devicesSummary(agents: { status: string }[], adopted: { online: boolean }[]): string {
  const total = agents.length + adopted.length;
  if (total === 0) {
    return 'No devices yet';
  }
  const online = agents.filter((d) => d.status === 'online').length + adopted.filter((h) => h.online).length;
  const summary = `${String(online)} of ${String(total)} online`;
  return adopted.length === 0 ? summary : `${summary} · ${String(adopted.length)} without an agent`;
}
