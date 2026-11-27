// The editor's "Run on the device" option: `local: true` (#70).

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readAutomation, setLocal, writeBack } from '../src/automations/model.ts';

const watchdog = `id: dns-watchdog
# Pi-hole on the Pi itself
triggers:
  - type: dns
    name: example.com
    server: 127.0.0.1
    from: pi4
actions:
  - type: restart
    device: pi4
    service: systemd:pihole-FTL.service
`;

test('turning local on and off changes only that line', () => {
  const on = setLocal(watchdog, true);
  assert.equal(on, watchdog.replace('# Pi-hole', 'local: true\n# Pi-hole'));
  const read = readAutomation(on);
  assert.ok(read.ok);
  assert.equal(read.model.local, true);
  assert.equal(read.model.extras.length, 0);
  assert.equal(writeBack(on), on);
  assert.equal(setLocal(on, false), watchdog);
});

test('a file without local reads as not local', () => {
  const read = readAutomation(watchdog);
  assert.ok(read.ok);
  assert.equal(read.model.local, false);
});

test('a local value the form cannot show stays read-only', () => {
  const odd = watchdog.replace('triggers:', 'local: "yes"\ntriggers:');
  const read = readAutomation(odd);
  assert.ok(read.ok);
  assert.equal(read.model.local, false);
  assert.equal(read.model.extras.length, 1);
  assert.equal(writeBack(odd), odd);
});
