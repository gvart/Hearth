// The Devices page's network scan: its line once one ends, and its state. Run with `npm test` in web/.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { applyScanDone, scanInterrupted, scanStarted, scanSummary } from '../src/networkscan.ts';

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

test('applyScanDone ends only the scan this UI started, by its id', () => {
  const done = (id) => ({ id, hosts: 2, new: 1, returned: 0, duration_ms: 100 });
  const cases = [
    ['ours ends', { running: true, id: 'a' }, done('a'), { running: false, id: 'a', done: done('a') }],
    ["another admin's is ignored", { running: true, id: 'a' }, done('b'), { running: true, id: 'a' }],
    ['ours still shows after an interruption', { running: false, id: 'a' }, done('a'), { running: false, id: 'a', done: done('a') }],
    ['one another admin started (409) ends with the first done', { running: true }, done('b'), { running: false, id: undefined, done: done('b') }],
    ['none of ours: ignored', { running: false }, done('b'), { running: false }],
  ];
  for (const [name, state, ev, want] of cases) {
    assert.deepEqual(applyScanDone(state, ev), want, name);
  }
});

test('scanStarted runs the scan, unless its done event beat the answer', () => {
  const done = { id: 'a', hosts: 0, new: 0, returned: 0, duration_ms: 0, error: 'boom' };
  // Before the answer the state is { running: true }; an early done ends it.
  const early = applyScanDone({ running: true }, done);
  assert.deepEqual(scanStarted(early, 'a'), { running: false, id: 'a', done });
  assert.deepEqual(scanStarted({ running: true }, 'a'), { running: true, id: 'a' });
  const previous = { running: false, id: 'z', done: { ...done, id: 'z' } };
  assert.deepEqual(scanStarted(previous, 'a'), { running: true, id: 'a' });
});

test('scanInterrupted stops a running scan and keeps its id', () => {
  assert.deepEqual(scanInterrupted({ running: true, id: 'a' }), { running: false, id: 'a' });
  const idle = { running: false, id: 'a', done: { id: 'a', hosts: 1, new: 0, returned: 0, duration_ms: 1 } };
  assert.equal(scanInterrupted(idle), idle);
});
