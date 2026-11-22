// The Devices page's network scan: the line it shows when one ends, and its
// state as done events and reconnects change it. Kept apart from
// the components so node --test can check it (web/test/networkscan.test.mjs).

import type { NetworkScanDone } from './api/client.ts';

/** "Found 14 hosts, 3 new", or why the scan failed. */
export function scanSummary(done: NetworkScanDone): string {
  if (done.error) {
    return `The scan failed: ${done.error}`;
  }
  const parts = [`Found ${done.hosts === 1 ? '1 host' : `${String(done.hosts)} hosts`}`];
  if (done.new > 0) {
    parts.push(`${String(done.new)} new`);
  }
  if (done.returned > 0) {
    parts.push(`${String(done.returned)} back`);
  }
  return parts.join(', ');
}

/** A network scan asked for from this UI: running, its id, and how it ended. */
export interface NetworkScanState {
  running: boolean;
  /** The id POST /api/v1/network/scan answered; absent for a scan another admin started (409). */
  id?: string;
  done?: NetworkScanDone;
}

/** How long the UI waits for a scan's done event before it stops showing it as running. */
export const scanTimeoutMs = 60_000;

/**
 * The state once a network.scan.done event arrives: it ends this UI's scan
 * when it carries its id, or, for a scan another admin started (no id), the
 * first one to end. Other admins' scans leave it as it is.
 */
export function applyScanDone(state: NetworkScanState, done: NetworkScanDone): NetworkScanState {
  const mine = state.id === undefined ? state.running : done.id === state.id;
  return mine ? { running: false, id: state.id, done } : state;
}

/**
 * The state once the done event may have been missed (the event stream
 * reopened, or it did not come in time): not running any more. A done event
 * with its id that comes later still applies.
 */
export function scanInterrupted(state: NetworkScanState): NetworkScanState {
  return state.running ? { ...state, running: false } : state;
}
