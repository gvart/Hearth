// The Devices page's levels: disk use, meter tones and the newest metric. Run with `npm test` in web/.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { diskUse, latest, meterTone, notAllowed, suggestedName } from '../src/devices.ts';

test('suggestedName is the hostname without .local, in the characters a device name allows', () => {
  const cases = [
    ['garage-pi.local', 'garage-pi'],
    ['NAS.local.', 'NAS'],
    ['pi.lan', 'pi.lan'],
    ['Galaxy S21', 'Galaxy-S21'],
    ['_printer', 'printer'],
    ['', ''],
    ['a'.repeat(80), 'a'.repeat(63)],
  ];
  for (const [hostname, want] of cases) {
    assert.equal(suggestedName({ hostname }), want, hostname);
  }
});

test('diskUse is the share in use, and unknown when the agent does not report it', () => {
  const cases = [
    [{ total_bytes: 100, used_bytes: 63 }, 63],
    [{ total_bytes: 8e12, used_bytes: 7.12e12 }, 89],
    [{ total_bytes: 3, used_bytes: 2 }, 67],
    [{ total_bytes: 100, used_bytes: 250 }, 100],
    [{ total_bytes: 100 }, undefined],
    [{ total_bytes: 100, used_bytes: 0 }, undefined],
    [{ total_bytes: 0, used_bytes: 5 }, undefined],
  ];
  for (const [disk, want] of cases) {
    assert.equal(diskUse(disk), want, JSON.stringify(disk));
  }
});

test('meterTone warns from 85% and alarms from 95%', () => {
  const cases = [
    [0, 'ok'],
    [84, 'ok'],
    [85, 'warn'],
    [94, 'warn'],
    [95, 'bad'],
    [100, 'bad'],
  ];
  for (const [percent, want] of cases) {
    assert.equal(meterTone(percent), want, String(percent));
  }
});

test('latest reads the newest point of one chart', () => {
  const charts = [
    { key: 'cpu', name: 'CPU', unit: '%', points: [[1, 10], [2, 42]] },
    { key: 'memory', name: 'Memory', unit: '%', points: [] },
  ];
  assert.equal(latest(charts, 'cpu'), 42);
  assert.equal(latest(charts, 'memory'), undefined);
  assert.equal(latest(charts, 'disk'), undefined);
  assert.equal(latest(undefined, 'cpu'), undefined);
});

test('notAllowed names what the agent keeps off and the flag for each', () => {
  const open = notAllowed({ facts: { ceiling: { exec: [], restart: [], probe: true, logs: ['systemd:*'], docker: true, net_edges: true, shell: true } } });
  assert.deepEqual(open, { logs: false, docker: false, netEdges: false, flags: [] });

  const shut = notAllowed({ facts: { ceiling: { exec: [], restart: [], probe: false } } });
  assert.equal(shut.logs && shut.docker && shut.netEdges, true);
  assert.deepEqual(
    shut.flags.map((f) => f.flag),
    ['--allow-logs systemd:UNIT', '--allow-docker', '--allow-net-edges', '--allow-shell'],
  );

  // An agent too old to report a ceiling allows none of them.
  assert.equal(notAllowed({ facts: {} }).flags.length, 4);
});
