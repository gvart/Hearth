// What the Devices page shows of a device's metrics and disks. Kept apart from
// the components so node --test can check it (web/test/devices.test.mjs).

import type { Disk, MetricChart } from './api/client.ts';

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
