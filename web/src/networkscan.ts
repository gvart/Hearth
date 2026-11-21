// The line the Devices page shows when a network scan ends. Kept apart from
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
