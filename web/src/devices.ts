// What the Devices page shows of a device's metrics and disks. Kept apart from
// the components so node --test can check it (web/test/devices.test.mjs).

import type { Ceiling, Disk, MetricChart } from './api/client.ts';

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

/** What a device's agent does not allow, and the agent flag that turns each on. */
export interface NotAllowed {
  logs: boolean;
  docker: boolean;
  netEdges: boolean;
  flags: { what: string; flag: string }[];
}

/**
 * The parts of the device page its agent keeps off. An agent too old to report
 * its ceiling allows none of them.
 */
export function notAllowed(device: { facts: { ceiling?: Ceiling } }): NotAllowed {
  const c = device.facts.ceiling;
  const logs = (c?.logs ?? []).length === 0;
  const docker = !c?.docker;
  const netEdges = !c?.net_edges;
  const flags: NotAllowed['flags'] = [];
  if (logs) {
    flags.push({ what: 'Logs', flag: '--allow-logs systemd:UNIT' });
  }
  if (docker) {
    flags.push({ what: 'Containers', flag: '--allow-docker' });
  }
  if (netEdges) {
    flags.push({ what: 'Neighbors', flag: '--allow-net-edges' });
  }
  if (!c?.shell) {
    flags.push({ what: 'Terminal', flag: '--allow-shell' });
  }
  return { logs, docker, netEdges, flags };
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
