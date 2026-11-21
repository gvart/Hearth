// The Devices page's line about a finished network scan. Run with `npm test` in web/.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { scanSummary } from '../src/networkscan.ts';

test('scanSummary counts the hosts, and names only the new and returned ones there are', () => {
  const cases = [
    [{ hosts: 14, new: 3, returned: 0, duration_ms: 2100 }, 'Found 14 hosts, 3 new'],
    [{ hosts: 14, new: 3, returned: 2, duration_ms: 2100 }, 'Found 14 hosts, 3 new, 2 back'],
    [{ hosts: 1, new: 0, returned: 0, duration_ms: 900 }, 'Found 1 host'],
    [{ hosts: 0, new: 0, returned: 0, duration_ms: 900 }, 'Found 0 hosts'],
    [{ hosts: 0, new: 0, returned: 0, duration_ms: 0, error: 'sweep: boom' }, 'The scan failed: sweep: boom'],
  ];
  for (const [done, want] of cases) {
    assert.equal(scanSummary(done), want, JSON.stringify(done));
  }
});
